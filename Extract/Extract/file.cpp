#include "file.h"
#include <stdint.h>

ssize_t pread64(HANDLE __fd, void* __buf, size_t __count, off64_t __offset) {
  DWORD rc = 0;
  off64_t file_offset = __offset;
  rc = SetFilePointer(__fd, *(PLONG)&__offset, ((PLONG)&__offset) + 1, FILE_BEGIN);
  *(DWORD *)&__offset = rc;
  if (file_offset != __offset) {
    return -1;
  }
  return ReadFile(__fd, __buf, __count, &rc, NULL) != 0 ? rc : -1;
}

ssize_t pwrite64(HANDLE __fd, const void* __buf, size_t __count, off64_t __offset) {
  DWORD rc = 0;
  off64_t file_offset = __offset;
  rc = SetFilePointer(__fd, *(PLONG)&__offset, ((PLONG)&__offset) + 1, FILE_BEGIN);
  *(DWORD *)&__offset = rc;
  if (file_offset != __offset) {
    return -1;
  }
  return WriteFile(__fd, __buf, __count, &rc, NULL) != 0 ? rc : -1;
}

void* mmap(void* __addr, size_t __size, int __prot, int __flags, HANDLE __fd, off_t __offset) {
  return mmap64(__addr, __size, __prot, __flags, __fd, __offset);
}

void* mmap64(void* __addr, size_t __size, int __prot, int __flags, HANDLE mapping, off64_t __offset) {
  return MapViewOfFile(mapping, FILE_MAP_READ|FILE_MAP_WRITE, ((uint32_t *)&__offset)[1], ((uint32_t *)&__offset)[0], __size);
}

LPTSTR g_buf = NULL;
DWORD g_buf_len = 0;

LPTSTR my_strerror(DWORD errno_) {
  LPTSTR buf;
  if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
    | FORMAT_MESSAGE_IGNORE_INSERTS
    | FORMAT_MESSAGE_FROM_SYSTEM
    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
    NULL,
    errno_,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPTSTR)&buf,
    0,
    NULL)) {
    DWORD len = strlen(buf);
    if (g_buf == NULL) {
      g_buf = (LPTSTR)malloc(len * 2);
      g_buf_len = len * 2;
    }
    if (g_buf_len <= len) {
      g_buf = (LPTSTR)realloc(g_buf, len * 2);
      g_buf_len = len * 2;
    }
    strcpy(g_buf, buf);
    LocalFree(buf);
    return g_buf;
  }
  return NULL;
}