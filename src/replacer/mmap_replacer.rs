use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use nix::sys::mman::{MapFlags, ProtFlags};
use procfs::process::{MMapPath,MMPermissions};
use tracing::{debug, error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Debug)]
struct ReplaceCase {
    pub memory_addr: u64,
    pub length: u64,
    pub prot: u64,
    pub flags: u64,
    pub path: PathBuf,
    pub offset: u64,
}

#[derive(Clone, Copy)]
#[repr(packed)]
#[repr(C)]
struct RawReplaceCase {
    memory_addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    new_path_offset: u64,
    offset: u64,
}

impl RawReplaceCase {
    pub fn new(
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path_offset: u64,
        offset: u64,
    ) -> RawReplaceCase {
        RawReplaceCase {
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
        }
    }
}

// TODO: encapsulate this struct for fd replacer and mmap replacer
struct ProcessAccessorBuilder {
    cases: Vec<RawReplaceCase>,
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

    pub fn push_case(
        &mut self,
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path: PathBuf,
        offset: u64,
    ) -> anyhow::Result<()> {
        let mut new_path = new_path
            .to_str()
            .ok_or(anyhow!("fd contains non-UTF-8 character"))?
            .as_bytes()
            .to_vec();

        new_path.push(0);

        let new_path_offset = self.new_paths.position();
        self.new_paths.write_all(new_path.as_slice())?;

        self.cases.push(RawReplaceCase::new(
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
        ));

        Ok(())
    }
}

impl FromIterator<ReplaceCase> for ProcessAccessorBuilder {
    fn from_iter<T: IntoIterator<Item = ReplaceCase>>(iter: T) -> Self {
        let mut builder = Self::new();
        for case in iter {
            if let Err(err) = builder.push_case(
                case.memory_addr,
                case.length,
                case.prot,
                case.flags,
                case.path,
                case.offset,
            ) {
                error!("fail to write to AccessorBuilder. Error: {:?}", err)
            }
        }

        builder
    }
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,

    cases: Vec<RawReplaceCase>,
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

        let (cases_ptr, length, _) = self.cases.clone().into_raw_parts();
        let size = length * std::mem::size_of::<RawReplaceCase>();
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr as *mut u8, size) };

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
                ; mov x15, #0
                ; adr x14, -> cases

                ; b ->end
                ; ->start:
                // munmap
                ; mov x8, #215 // munmap syscall number
                ; ldr x0, [x14, x15] // addr
                ; add x16, x14, x15
                ; ldr x2, [x16, #8]
                ; mov x2, #0
                ; svc #0
                // open
                ; mov x8, #56 // openat syscall number
                ; add x0, x0, #101 // AT_FDCWD
                ; adr x1, -> new_paths
                ; add x15, x15, #32 // set x15 to point to path
                ; ldr x2, [x14,x15]
                ; add x1, x1, x2 // path
                ; sub x15, x15, #32
                ; mov x2, #2 // O_RDWR
                ; mov x3, #0
                ; svc 0
                ; mov x8, x0 // Save fd to x8
                // mmap
                ; mov x8, #222 // mmap syscall number
                ; mov x0, #0
                ; add x15, x15, #8
                ; ldr x2, [x14, x15] // length
                ; add x15, x15, #8
                ; ldr x2, [x14, x15] // prot
                ; add x15, x15, #8
                ; ldr x3, [x14, x15] // flags
                ; add x15, x15, #16
                ; ldr x5, [x14, x15] // offset
                ; mov x4, x8 // fd
                ; svc #0
                ; sub x15, x15, #40
                // close
                ; mov x8, #57 // close syscall number
                ; mov x0, x8 // fd
                ; svc #0

                ; add x15, x15, #48 // size of RawReplaceCase
                ; ->end:
                ; ldr x13, ->cases_length
                ; cmp x15, x13
                ; b.lo ->start

                ; brk #0
            );

            let instructions = vec_rt.finalize()?;

            Ok((replace.0 as u64, instructions))
        })?;

        trace!("reopen successfully");
        Ok(())
    }
}

fn get_prot_and_flags_from_perms(perms: MMPermissions) -> (u64, u64) {
    let mut prot = ProtFlags::empty();
    if perms.contains(MMPermissions::READ) {
        prot |= ProtFlags::PROT_READ
    }
    if perms.contains(MMPermissions::WRITE) {
        prot |= ProtFlags::PROT_WRITE
    }
    if perms.contains(MMPermissions::EXECUTE) {
        prot |= ProtFlags::PROT_EXEC
    }

    let flags = if perms.contains(MMPermissions::SHARED) {
        MapFlags::MAP_SHARED
    } else {
        MapFlags::MAP_PRIVATE
    };

    trace!(
        "perms: {:?}, prot: {:?}, flags: {:?}",
        perms,
        prot,
        flags
    );
    (prot.bits() as u64, flags.bits() as u64)
}

pub struct MmapReplacer {
    processes: HashMap<i32, ProcessAccessor>,
}

impl MmapReplacer {
    pub fn prepare<P1: AsRef<Path>, P2: AsRef<Path>>(
        detect_path: P1,
        new_path: P2,
    ) -> Result<MmapReplacer> {
        info!("preparing mmap replacer");

        let detect_path = detect_path.as_ref();
        let new_path = new_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = ptrace::trace(pid).ok()?;
                let maps = process.maps().ok()?;

                Some((traced_process, maps))
            })
            .flat_map(|(process, maps)| {
                maps.into_iter()
                    .filter_map(move |entry| {
                        match entry.pathname {
                            MMapPath::Path(path) => {
                                let (start_address, end_address) = entry.address;
                                let length = end_address - start_address;
                                let (prot, flags) = get_prot_and_flags_from_perms(entry.perms);
                                // TODO: extract permission from perms

                                let case = ReplaceCase {
                                    memory_addr: start_address,
                                    length,
                                    prot,
                                    flags,
                                    path,
                                    offset: entry.offset,
                                };
                                Some((process.clone(), case))
                            }
                            _ => None,
                        }
                    })
                    .filter(|(_, case)| case.path.starts_with(detect_path))
                    .filter_map(|(process, mut case)| {
                        let stripped_path = case.path.strip_prefix(detect_path).ok()?;
                        case.path = new_path.join(stripped_path);
                        Some((process, case))
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

        info!("preparing mmap replacer end");
        Ok(MmapReplacer { processes })
    }
}

impl Replacer for MmapReplacer {
    fn run(&mut self) -> Result<()> {
        info!("running mmap replacer");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.run()?;
        }

        Ok(())
    }
}