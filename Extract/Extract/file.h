
#include <Windows.h>
#include <sys/cdefs.h>
#include <asm-generic/posix_types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


#define DL_ERR(fmt, ...) fprintf(stderr, "DL_ERR: " ## fmt ## "\r\n", __VA_ARGS__)

#define DL_WARN(fmt, ...) fprintf(stdout, "DL_WARN: " ## fmt ## "\r\n", __VA_ARGS__)

#define INFO(fmt, ...) fprintf(stdout, "INFO: " ## fmt ## "\r\n", __VA_ARGS__)

#define DEBUG(fmt, ...) fprintf(stdout, "DEBUG: " ## fmt ## "\r\n", __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

ssize_t pread64(HANDLE __fd, void* __buf, size_t __count, off64_t __offset);

void* mmap(void* __addr, size_t __size, int __prot, int __flags, HANDLE __fd, off_t __offset);

void* mmap64(void* __addr, size_t __size, int __prot, int __flags, HANDLE __fd, off64_t __offset);

LPTSTR my_strerror(DWORD errno_);

#ifdef __cplusplus
}
#endif