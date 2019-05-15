#ifndef HEADER_H_
#define HEADER_H_

#include <stdint.h>
#include <elf.h>

#pragma pack(push)
#pragma pack(1)

struct SectionTable {
  ElfW(Off)  shoff;
  ElfW(Half) shnum;
  ElfW(Half) shentsize;
  ElfW(Half) shstrndx;
  ElfW(Addr) mapping_base_;

  bool section_table_get_strtab_section(ElfW(Shdr) &strtab);
  bool section_table_get_symtab_section(ElfW(Shdr) &symtab);
  bool section_table_get_hash_section(ElfW(Shdr)   &hash);
};

// sizeof = 0x58
struct Header {
  ElfW(Addr)    min_vaddr;            // +00: 最小虚拟地址 希望内存被分布的地址
  size_t        load_size_;           // +04: 所有可加载段
  size_t        load_seg_num_;        // +0A: 可加载段的数量
  ElfW(Addr)    ARM_exidx;            // +50: -A8 v56
  size_t        ARM_exidx_count;      // +54: -A4 v57
  uint32_t      nbucket_;             // +34: bucket_ 的数量
  uint32_t      nchain_;              // +38: chanin_ 的数量
  ElfW(Addr)    bucket_;              // +3C: Hash 表的偏移，每一项4字节, load_size_=Header.nbucket_ * 4
  ElfW(Addr)    strtab_;              // +10: .dynstr, load_size_=Header.bucket_ - Header.strtab_ - 8; 因为字符串表下面就是bucket
  ElfW(Addr)    symtab_;              // +14: .dynsym, load_size_=Header.nchain_ * 0x10; nchain_ 表示符号表的个数
  ElfW(Addr)    plt_rel_;             // +40: DT_JMPREL .rel.plt的偏移
  ElfW(Addr)    rel_;                 // +4C: DT_REL .rel.dyn的偏移

  size_t   strtab_size_;
  size_t   plt_rel_count_;       // +44: DT_PLTRELSZ .rel.plt的数量，每一项8字节
  size_t   rel_count_;           // +48: DT_RELSZ .rel.dyn的数量，每一项8字节
  size_t   init_array_count_;    // +2A: 因为没有使用，这是一个猜测
  size_t   fini_array_count_;    // +28: 因为没有使用，这是一个猜测

  ElfW(Addr)    init_func_;           // +18: 初始化函数的偏移
  ElfW(Addr)    fini_func_;           // +20: 因为没有使用，这是一个猜测

  ElfW(Addr)    init_array_;          // +1C: 初始化函数数组的偏移
  ElfW(Addr)    fini_array_;          // +24: 因为没有使用，这是一个猜测

  size_t        needed_count_;        // +2C: 在执行解压代码前，需要加载多少个依赖的lib
  ElfW(Addr)    needed_strtab_;       // +30: 指定了需要被加载的library字符串表的偏移
};

// sizeof = 0x18
struct Loadable {
  ElfW(Addr) p_vaddr;               // +00:
  ElfW(Addr) p_memsz;               // +04:
  ElfW(Off)  p_offset;              // +08: 数据距离 Header 的偏移
  ElfW(Addr) p_filesz;              // +0C: 数据在文件中占用的实际大小
  ElfW(Word) p_flags;               // +10: 标识了读，写，执行
  uint8_t*   data;
};


struct Header_ {
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

#ifdef __LP64__
  Elf64_Xword   plt_rel_count_;
  Elf64_Xword   rel_count_;
  Elf64_Xword   init_array_count_;    // +2A: 因为没有使用，这是一个猜测
  Elf64_Xword   fini_array_count_;    // +28: 因为没有使用，这是一个猜测
#else
  Elf32_Sword   plt_rel_count_;       // +44: DT_PLTRELSZ .rel.plt的数量，每一项8字节
  Elf32_Sword   rel_count_;           // +48: DT_RELSZ .rel.dyn的数量，每一项8字节
  Elf32_Sword   init_array_count_;    // +2A: 因为没有使用，这是一个猜测
  Elf32_Sword   fini_array_count_;    // +28: 因为没有使用，这是一个猜测
#endif

  ElfW(Addr)    init_func_;           // +18: 初始化函数的偏移
  ElfW(Addr)    fini_func_;           // +20: 因为没有使用，这是一个猜测

  ElfW(Addr)    init_array_;          // +1C: 初始化函数数组的偏移
  ElfW(Addr)    fini_array_;          // +24: 因为没有使用，这是一个猜测

  size_t        needed_count_;        // +2C: 在执行解压代码前，需要加载多少个依赖的lib
  ElfW(Addr)    needed_strtab_;       // +30: 指定了需要被加载的library字符串表的偏移
};


#pragma pack(pop)

#endif