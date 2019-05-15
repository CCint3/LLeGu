#ifndef FINALLY_PUBLIC_H
#define FINALLY_PUBLIC_H


#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <android/log.h>

#define LOG_TAG "ZWP_SHELL"

#define MY_TEMP_FAILURE_RETRY(exp) ({      \
    __typeof__(exp) _rc;                   \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1);                   \
    _rc; })

#define ELF_HASH_fmodf                    0x006D45A6
#define ELF_HASH_strlen                   0x07AB92BE
#define ELF_HASH_fopen                    0x006D66BE
#define ELF_HASH_fgets                    0x006CDCB3
#define ELF_HASH_close                    0x006A3695
#define ELF_HASH___system_property_get    0x04CEF454
#define ELF_HASH_memset                   0x073C49C4
#define ELF_HASH_malloc                   0x07383353
#define ELF_HASH_access                   0x06799CA3
#define ELF_HASH_feof                     0x0006CC56
#define ELF_HASH_mmap                     0x00074380
#define ELF_HASH_open                     0x000766BE
#define ELF_HASH_pread                    0x00778B74
#define ELF_HASH_sscanf                   0x07A99846
#define ELF_HASH_memcpy                   0x073C3A79
#define ELF_HASH_free                     0x0006D8B5
#define ELF_HASH_fclose                   0x06CA3695
#define ELF_HASH_atoi                     0x00068B59
#define ELF_HASH_inflateInit2_            0x09CA2FAF
#define ELF_HASH_inflate                  0x004D28D5
#define ELF_HASH_inflateEnd               0x028DA094
#define ELF_HASH___android_log_print      0x0DC5A6F4
#define ELF_HASH_dlsym                    0x006B3AFD
#define ELF_HASH_dlopen                   0x06B366BE
#define ELF_HASH_pread64                  0x078B77E4
#define ELF_HASH_fstat                    0x006DAA84
#define ELF_HASH_munmap                   0x074C5380
#define ELF_HASH_mprotect                 0x0796ACE4
#define ELF_HASH_cacheflush               0x0EBBAB08

#define CHECKSUM_munmap                   0x028E0006
#define CHECKSUM_mprotect                 0x036E0008
#define CHECKSUM_cacheflush               0x0416000A
#define CHECKSUM_fmodf                    0x020C0005
#define CHECKSUM_strlen                   0x02980006
#define CHECKSUM_fopen                    0x02180005
#define CHECKSUM_fgets                    0x02190005
#define CHECKSUM_close                    0x02160005
#define CHECKSUM___system_property_get    0x08E60015
#define CHECKSUM_memset                   0x028B0006
#define CHECKSUM_malloc                   0x02780006
#define CHECKSUM_access                   0x02720006
#define CHECKSUM_feof                     0x01A00004
#define CHECKSUM_mmap                     0x01AB0004
#define CHECKSUM_open                     0x01B20004
#define CHECKSUM_pread                    0x020C0005
#define CHECKSUM_sscanf                   0x027E0006
#define CHECKSUM_memcpy                   0x028B0006
#define CHECKSUM_free                     0x01A20004
#define CHECKSUM_fclose                   0x027C0006
#define CHECKSUM_atoi                     0x01AD0004
#define CHECKSUM_inflateInit2_            0x0508000D
#define CHECKSUM_inflate                  0x02E30007
#define CHECKSUM_inflateEnd               0x03FA000A
#define CHECKSUM___android_log_print      0x07CC0013
#define CHECKSUM_dlsym                    0x02290005
#define CHECKSUM_dlopen                   0x02820006
#define CHECKSUM_pread64                  0x02760007
#define CHECKSUM_fstat                    0x02220005

typedef int (* p_munmap)(void* __addr, size_t __size);
typedef int (* p_mprotect)(void* __addr, size_t __size, int __prot);
typedef int (* p_cacheflush)(long start, long end, long /*flags*/);
typedef float (* p_fmodf)(float x, float y);
typedef size_t (* p_strlen)(const char *s);
typedef int (* p_sscanf)(const char *str, const char *format, ...);
typedef ssize_t (* p_pread)(int fd, void *buf, size_t count, off_t offset);
typedef int (* p_open)(const char* __path, int __flags, ...);
typedef void *(* p_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef void *(* p_memset)(void *s, int c, size_t n);
typedef void *(* p_memcpy)(void *dest, const void *src, size_t n);
typedef void *(* p_malloc)(size_t size);
typedef int (* p_inflateInit2_)(z_streamp strm, int windowBits, const char *version, int stream_size);
typedef int (* p_inflateEnd)(z_streamp stream);
typedef int (*p_inflate)(z_streamp strm, int flush);
typedef void (*p_free)(void *ptr);
typedef FILE* (* p_fopen)(const char* __path, const char* __mode);
typedef char *(* p_fgets)(char *s, int n, FILE *stream);
typedef int (* p_feof)(FILE *stream);
typedef void *(* p_dlsym)(void *handle, const char *symbol);
typedef void *(* p_dlopen)(const char *filename, int flags);
typedef int (* p_close)(int fd);
typedef int (* p_atoi)(const char *nptr);
typedef int (* p___system_property_get)(const char *name, char *value);
typedef int (* p___android_log_print)(int prio, const char* tag, const char* fmt, ...);
typedef ssize_t (* p_pread64)(int __fd, void* __buf, size_t __count, off64_t __offset);
typedef int (* p_fstat)(int __fd, struct stat* __buf);


#ifdef DYNAMIC_CALL
#define CALL(func_name, ...) (((p_##func_name)elf_lookup(ELF_HASH_##func_name, CHECKSUM_##func_name))(__VA_ARGS__))
#else
#define CALL(func_name, ...) (func_name(__VA_ARGS__))
#endif

#ifdef MYLOG
#define ALOGE(tag, ...) CALL(__android_log_print, 6, tag, __VA_ARGS__)
#else
#define ALOGE(tag, ...)
#endif

#define DLL_PUBLIC __attribute__ ((visibility ("default")))

#define DLL_LOCAL __attribute__ ((visibility ("hidden")))
//#define DLL_LOCAL

#define SECTION(name) __attribute__((section(name)))

//#define INLINE_FUNC
#define INLINE_FUNC __inline

#define CONSTRUCTOR(n) __attribute__ ((constructor(100+n)))

#define ICACHE (1 << 0)
#define DCACHE (1 << 1)
#define BCACHE (ICACHE | DCACHE)
#define CACHEABLE 0
#define UNCACHEABLE 1

#endif //FINALLY_PUBLIC_H
