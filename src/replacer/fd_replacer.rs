use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use procfs::process::FDTarget;
use tracing::{debug, error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Copy)]
#[repr(packed)]
#[repr(C)]
struct ReplaceCase {
    fd: u64,
    new_path_offset: u64,
}

impl ReplaceCase {
    pub fn new(fd: u64, new_path_offset: u64) -> ReplaceCase {
        ReplaceCase {
            fd,
            new_path_offset,
        }
    }
}

struct ProcessAccessorBuilder {
    cases: Vec<ReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl ProcessAccessorBuilder {
    pub fn new() -> ProcessAccessorBuilder {
        ProcessAccessorBuilder {
            cases: Vec::new(),
            new_paths: Cursor::new(Vec::new()),
        }
    }

    pub fn build(self, process: ptrace::TracedProcess) -> Result<ProcessAccessor> {
        Ok(ProcessAccessor {
            process,

            cases: self.cases,
            new_paths: self.new_paths,
        })
    }

    pub fn push_case(&mut self, fd: u64, new_path: PathBuf) -> anyhow::Result<()> {
        trace!("push case fd: {}, new_path: {}", fd, new_path.display());

        let mut new_path = new_path
            .to_str()
            .ok_or(anyhow!("fd contains non-UTF-8 character"))?
            .as_bytes()
            .to_vec();

        new_path.push(0);

        let offset = self.new_paths.position();
        self.new_paths.write_all(new_path.as_slice())?;

        self.cases.push(ReplaceCase::new(fd, offset));

        Ok(())
    }
}

impl FromIterator<(u64, PathBuf)> for ProcessAccessorBuilder {
    fn from_iter<T: IntoIterator<Item = (u64, PathBuf)>>(iter: T) -> Self {
        let mut builder = Self::new();
        for (fd, path) in iter {
            if let Err(err) = builder.push_case(fd, path) {
                error!("fail to write to AccessorBuilder. Error: {:?}", err)
            }
        }

        builder
    }
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,

    cases: Vec<ReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl Debug for ProcessAccessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.process.fmt(f)
    }
}

impl ProcessAccessor {
    pub fn run(&mut self) -> anyhow::Result<()> {
        self.new_paths.set_position(0);

        let mut new_paths = Vec::new();
        self.new_paths.read_to_end(&mut new_paths)?;

        let cases = &mut *self.cases.clone();
        let cases_ptr = &mut cases[0] as *mut ReplaceCase as *mut u8;
        let size = std::mem::size_of_val(cases);
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr, size) };

        info!("Aarch64Relocation start");
        self.process.run_codes(|addr| {
            let mut vec_rt =
                dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(addr as usize);
            dynasm!(vec_rt
                ; .arch aarch64
                ; ->cases:
                ; .bytes cases
                ; ->cases_length:
                ; .qword cases.len() as i64
                ; ->new_paths:
                ; .bytes new_paths.as_slice()
                ; nop
                ; nop
            );

            trace!("static bytes placed");
            let replace = vec_rt.offset();
            dynasm!(vec_rt
                ; .arch aarch64
                // set x15 to 0
                ; mov x15, 0
                ; adr x14, -> cases

                ; b ->end
                ; ->start:
                // fcntl
                ; mov x8, 0x48
                ; ldr x0, [x14, x15] // fd
                ; mov x1, 0x3
                ; mov x2, 0x0
                ; svc 0
                ; mov x1, x0
                // open
                ; mov x8, 0x2
                ; adr x0, -> new_paths
                ; add x0, x0, x15, lsl 3 // path
                ; mov x2, 0x0
                ; svc 0
                ; mov x12, x0 // store newly opened fd in x12
                // lseek
                ; mov x8, 0x8
                ; ldr x0, [x14, x15] // fd
                ; mov x1, 0
                ; mov x2, 1
                ; svc 0
                ; mov x0, x12
                ; mov x1, x0
                // lseek
                ; mov x8, 0x8
                ; mov x2, 0
                ; svc 0
                // dup2
                ; mov x8, 0x21
                ; mov x0, x12
                ; ldr x1, [x14, x15] // fd
                ; svc 0
                // close
                ; mov x8, 0x3
                ; mov x0, x12
                ; svc 0

                ; add x15, x15, #16
                ; ->end:
                ; ldr x13, ->cases_length
                ; cmp x15, x13
                ; b.lt ->start

                ; brk 0
            );

            let instructions = vec_rt.finalize()?;

            Ok((replace.0 as u64, instructions))
        })?;

        info!("reopen successfully");
        Ok(())
    }
}

pub struct FdReplacer {
    processes: HashMap<i32, ProcessAccessor>,
}

impl FdReplacer {
    pub fn prepare<P1: AsRef<Path>, P2: AsRef<Path>>(
        detect_path: P1,
        new_path: P2,
    ) -> Result<FdReplacer> {
        info!("preparing fd replacer");

        let detect_path = detect_path.as_ref();
        let new_path = new_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = match ptrace::trace(pid) {
                    Ok(p) => p,
                    Err(err) => {
                        error!("fail to trace process: {} {}", pid, err);
                        return None;
                    }
                };
                let fd = process.fd().ok()?.filter_map(|fd| fd.ok());

                Some((traced_process, fd))
            })
            .flat_map(|(process, fd)| {
                fd.into_iter()
                    .filter_map(|entry| match entry.target {
                        FDTarget::Path(path) => Some((entry.fd as u64, path)),
                        _ => None,
                    })
                    .filter(|(_, path)| path.starts_with(detect_path))
                    .filter_map(move |(fd, path)| {
                        trace!("replace fd({}): {}", fd, path.display());
                        let stripped_path = path.strip_prefix(detect_path).ok()?;
                        Some((process.clone(), (fd, new_path.join(stripped_path))))
                    })
            })
            .group_by(|(process, _)| process.pid)
            .into_iter()
            .filter_map(|(pid, group)| Some((ptrace::trace(pid).ok()?, group)))
            .map(|(process, group)| (process, group.map(|(_, group)| group)))
            .filter_map(|(process, group)| {
                let pid = process.pid;
                match group.collect::<ProcessAccessorBuilder>().build(process) {
                    Ok(accessor) => Some((pid, accessor)),
                    Err(err) => {
                        error!("fail to build accessor: {:?}", err);
                        None
                    }
                }
            })
            .collect();
        info!("preparing fd replacer end");
        Ok(FdReplacer { processes })
    }
}

impl Replacer for FdReplacer {
    fn run(&mut self) -> Result<()> {
        info!("running fd replacer");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.run()?;
        }
        info!("running fd replacer end");
        Ok(())
    }
}