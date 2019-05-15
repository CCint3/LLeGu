#ifndef TXLEGU_FINALLY_H
#define TXLEGU_FINALLY_H

#include <stdint.h>

#include "public.h"
#include "include/linker.h"

#define SwapBytes( Value1, Value2 ) \
{                                   \
  uint8_t temp = Value1;            \
  Value1 = Value2;                  \
  Value2 = temp;                    \
}

struct Rc4Context {
  uint32_t     i;
  uint32_t     j;
  uint8_t      S[256];
};

struct Key {
  uint32_t k1;
  uint32_t k2;
};

struct Exchange {
  uint32_t m0 : 4;
  uint32_t m1 : 4;
  uint32_t m2 : 4;
  uint32_t m3 : 4;

  uint32_t m4 : 4;
  uint32_t m5 : 4;
  uint32_t m6 : 4;
  uint32_t m7 : 4;
};

#pragma pack(push)
#pragma pack(1)

// sizeof = 0x58
struct Header {
  ElfW(Addr)    min_vaddr;            // +00: 最小虚拟地址 希望内存被分布的地址
  size_t        self_size_;
  size_t        load_size_;           // +04: 所有可加载段
  size_t        load_seg_num_;        // +0A: 可加载段的数量
  ElfW(Addr)    ARM_exidx;            // +50: -A8 v56
  size_t        ARM_exidx_count;      // +54: -A4 v57
  ElfW(Addr)    bucket_;              // +3C: Hash 表的偏移，每一项4字节, load_size_=Header.nbucket_ * 4
  ElfW(Addr)    strtab_;              // +10: .dynstr, load_size_=Header.bucket_ - Header.strtab_ - 8; 因为字符串表下面就是bucket
  ElfW(Addr)    symtab_;              // +14: .dynsym, load_size_=Header.nchain_ * 0x10; nchain_ 表示符号表的个数
  ElfW(Addr)    plt_rel_;             // +40: DT_JMPREL .rel.plt的偏移
  ElfW(Addr)    rel_;                 // +4C: DT_REL .rel.dyn的偏移

  size_t        plt_rel_count_;       // +44: DT_PLTRELSZ .rel.plt的数量，每一项8字节
  size_t        rel_count_;           // +48: DT_RELSZ .rel.dyn的数量，每一项8字节
  size_t        init_array_count_;    // +2A: 因为没有使用，这是一个猜测
  size_t        fini_array_count_;    // +28: 因为没有使用，这是一个猜测

  ElfW(Addr)    init_func_;           // +18: 初始化函数的偏移
  ElfW(Addr)    fini_func_;           // +20: 因为没有使用，这是一个猜测

  ElfW(Addr)    init_array_;          // +1C: 初始化函数数组的偏移
  ElfW(Addr)    fini_array_;          // +24: 因为没有使用，这是一个猜测

  size_t        needed_count_;        // +2C: 在执行解压代码前，需要加载多少个依赖的lib
  ElfW(Addr)    needed_strtab_;       // +30: 指定了需要被加载的library字符串表的偏移
};

// sizeof = 0x18
struct LoadSegment {
  ElfW(Addr) p_vaddr;               // +00:
  ElfW(Addr) p_memsz;               // +04:
  ElfW(Off)  p_offset;              // +08: 数据距离 Header 的偏移
  ElfW(Addr) p_filesz;              // +0C: 数据在文件中占用的实际大小
  ElfW(Word) p_flags;               // +10: 标识了读，写，执行
};
#pragma pack(pop)

typedef int (*PFUNC_JNI_OnLoad)(void *vm, void *reserved);

#ifdef __cplusplus
extern "C" {
#endif

__attribute__ ((visibility ("hidden"))) extern soinfo *g_self_si;
__attribute__ ((visibility ("hidden"))) extern soinfo *g_parasitic;
__attribute__ ((visibility ("hidden"))) extern p_munmap g_munmap;
#ifdef MYLOG
__attribute__ ((visibility ("hidden"))) extern p___android_log_print g_LogFun;
#endif

__inline int CACHEFLUSH(ElfW(Addr) start, ElfW(Addr) end) {
  const int syscall = 0xF0002;
  __asm __volatile (
    "MOV     R0, %0      \n"
    "MOV     R1, %1      \n"
    "MOV     R7, %2\n"
    "MOV     R2, #0x0    \n"
    "SVC     0x00000000  \n"
    :
    : "r" (start), "r" (end), "r" (syscall)
    : "r0",        "r1",      "r7");
}


SECTION(".text.00")
__attribute__ ((visibility ("hidden")))
__inline
void Rc4Initialise(Rc4Context* Context, void const* Key, uint32_t KeySize, uint32_t DropN);

SECTION(".text.00")
__attribute__ ((visibility ("hidden")))
__inline
void Rc4Xor(Rc4Context* Context, void const* InBuffer, void* OutBuffer, uint32_t Size);

SECTION(".text.00")
__attribute__ ((visibility ("hidden")))
__inline
uint16_t func_global_0001(uint16_t iSeed, uint32_t iMagic1, uint32_t iMagic2, int iCount);

SECTION(".text.00")
__attribute__ ((visibility ("hidden")))
__inline
uint32_t func_global_0005(uint32_t iSeed, uint32_t iMagic1, uint32_t iMagic2, uint32_t iMagic3);

// DT_INIT
SECTION(".text.01")
__attribute__ ((visibility ("hidden")))
__unused
void _init();

// DT_FINI
__attribute__ ((visibility ("hidden")))
__unused
void _fini();

//SECTION(".text.startup.after")
__attribute__ ((visibility ("hidden")))
void null_func(...);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
int is_symbol_global_and_defined(const ElfW(Sym) *s);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
uint32_t symbol_checksum(const char *name);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
uint32_t elf_hash(const char *name);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
ElfW(Addr) elf_lookup(uint32_t hash, uint32_t checksum);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
int get_path(char *buf, soinfo *si);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
void TEA_Decrypt(uint32_t *key, uint32_t *buf, int size, int round);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
void fix_symtab(size_t nchain, ElfW(Sym) *symtab, ElfW(Addr) load_bias, ElfW(Addr) self_load_bias);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
void relocate(soinfo *si, ElfW(Rel) *rels, int rel_cnt, void **lib_buf, int lib_buf_cnt);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
bool elf_reader_Load(int fd, off64_t file_offset, off64_t file_size, soinfo &si, Header &header);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
bool link_image(soinfo &si, Header &header);

SECTION(".text.startup.after")
DLL_LOCAL
INLINE_FUNC
void load_library(const char* name);

// .text.startup DT_INIT_ARRAY
// 必须隐藏符号
__attribute__ ((visibility ("hidden")))
CONSTRUCTOR(1)
__unused void load();

#ifdef __cplusplus
}
#endif

#endif //TXLEGU_FINALLY_H
