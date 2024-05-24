// gcc -o example-r example-r.c

#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024 // 定义缓冲区大小

int main() {
  FILE *fp;
  char buffer[BUFFER_SIZE];
  size_t bytes_read;

  // 打开文件
  fp = fopen("/var/run/test/aaaaaa.docx", "r");
  if (fp == NULL) {
    perror("打开文件失败");
    return 1;
  }

  // 循环读取文件内容
  while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
    // 处理读取到的数据，例如打印到屏幕
    fwrite(buffer, 1, bytes_read, stdout);
  }

  // 检查读取错误
  if (ferror(fp)) {
    perror("读取文件失败");
    fclose(fp);
    return 1;
  }

  // 关闭文件
  fclose(fp);
  return 0;
}