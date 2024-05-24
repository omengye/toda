// gcc -std=c99 -o example-w example-w.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define WRITE_TIMES 100000000 // 循环写入次数

int main() {
  // 要写入的字符串
  const char *message = "Hello, world! This is a test string.\n";
  size_t message_len = strlen(message);

  // 打开文件
  FILE *fp = fopen("/var/run/test/aaaaaa.docx", "w");
  if (fp == NULL) {
    perror("无法打开文件");
    return 1;
  }

  // 分配缓冲区
  char buffer[BUFFER_SIZE];

  // 循环写入指定次数
  for (int i = 0; i < WRITE_TIMES; i++) {
    // 将字符串复制到缓冲区，直到写完整个字符串
    size_t bytes_written = 0;
    while (bytes_written < message_len) {
      // 计算要复制到缓冲区的字节数
      size_t bytes_to_copy = BUFFER_SIZE < message_len - bytes_written ?
                            BUFFER_SIZE : message_len - bytes_written;

      // 将字符串的一部分复制到缓冲区
      memcpy(buffer, message + bytes_written, bytes_to_copy);

      // 将缓冲区内容写入文件
      size_t bytes_written_this_time = fwrite(buffer, 1, bytes_to_copy, fp);
      if (bytes_written_this_time != bytes_to_copy) {
        perror("写入文件时出错");
        fclose(fp);
        return 1;
      }

      bytes_written += bytes_written_this_time;
    }
    printf("%d\n",i);
  }

  // 检查写入错误
  if (ferror(fp)) {
    perror("写入文件时出错");
    fclose(fp);
    return 1;
  }

  // 关闭文件
  fclose(fp);

  return 0;
}