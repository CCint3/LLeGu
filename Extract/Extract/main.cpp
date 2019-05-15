
#include <vector>

#include <elf.h>
#include <linker.h>
#include <linker_phdr.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>  

#include "LibraryLoader.h"
#include "Header.h"
#include "file.h"
#include "zlib.h"
#include "TEA.h"

#pragma comment(lib, "zlib.lib")

#define SETTINGS "#ifndef SETTINGS_H_\r\n"         \
                 "#define SETTINGS_H_\r\n"         \
                 "#define TEA_KEYS_0  0x%08X\r\n"  \
                 "#define TEA_KEYS_1  0x%08X\r\n"  \
                 "#define TEA_KEYS_2  0x%08X\r\n"  \
                 "#define TEA_KEYS_3  0x%08X\r\n"  \
                 "#define MAGIC_01    0x%08X\r\n"  \
                 "#define TEA_ROUND   0x%08X\r\n"  \
                 "#define STRTAB_SIZE 0x%08X\r\n"  \
                 "#define SYMTAB_SIZE 0x%08X\r\n"  \
                 "#define HASH_SIZE   0x%08X\r\n"  \
                 "#define RANDOM_00   0x%08X\r\n"  \
                 "#define RANDOM_01   0x%08X\r\n"  \
                 "#define RANDOM_02   0x%08X\r\n"  \
                 "#define RANDOM_03   0x%08X\r\n"  \
                 "#define RANDOM_04   0x%08X\r\n"  \
                 "#define RANDOM_05   0x%08X\r\n"  \
                 "#define RANDOM_06   0x%08X\r\n"  \
                 "#define RANDOM_07   0x%08X\r\n"  \
                 "#endif\r\n"                      \

#define LD_SCRIPT "PHDRS {\r\n"  \
                  "  headers PT_PHDR         PHDRS  FLAGS(4);\r\n"  \
                  "  text    PT_LOAD FILEHDR PHDRS  FLAGS(5);\r\n"  \
                  "  data    PT_LOAD                FLAGS(6);\r\n"  \
                  "  dynamic PT_DYNAMIC             FLAGS(6);\r\n"  \
                  "}\r\n"  \
                  "\r\n"  \
                  "SECTIONS {\r\n"  \
                  "\r\n"  \
                  "  .rel.dyn SIZEOF_HEADERS : {\r\n"  \
                  "    *(.rel.dyn)\r\n"  \
                  "  } :text\r\n"  \
                  "\r\n"  \
                  "  .rel.plt : {\r\n"  \
                  "    *(.rel.plt)\r\n"  \
                  "  } :text\r\n"  \
                  "\r\n"  \
                  "  .text : {\r\n"  \
                  "    *(.text.00)\r\n"  \
                  "    *(.text.01)\r\n"  \
                  "    *(.text.startup)\r\n"  \
                  "    *(.text.startup.*)\r\n"  \
                  "    *(.text*)\r\n"  \
                  "  } :text\r\n"  \
                  "\r\n"  \
                  "  .plt : {\r\n"  \
                  "    *(.plt)\r\n"  \
                  "  } :text\r\n"  \
                  "\r\n"  \
                  "  .rodata : {\r\n"  \
                  "    *(.rodata*)\r\n"  \
                  "  } :text\r\n"  \
                  "\r\n"  \
                  "  .dynamic (.+0xFFF)&0xFFFFF000 : {\r\n"  \
                  "    *(.dynamic)\r\n"  \
                  "  } :data :dynamic\r\n"  \
                  "\r\n"  \
                  "  .bss : {\r\n"  \
                  "    *(.bss)\r\n"  \
                  "  } :data\r\n"  \
                  "\r\n"  \
                  "  .got : {\r\n"  \
                  "    *(.got)\r\n"  \
                  "  } :data\r\n"  \
                  "\r\n"  \
                  "  .data : {\r\n"  \
                  "    *(.data*)\r\n"  \
                  "  } :data\r\n"  \
                  "\r\n"  \
                  "  .dynsym ADDR(.data) + SIZEOF(.data) : {\r\n"  \
                  "     *(.dynsym)\r\n"  \
                  "   } :data\r\n"  \
                  "\r\n"  \
                  "  .dynstr ADDR(.dynsym) + 0x%08X : {\r\n"  \
                  "     *(.dynstr)\r\n"  \
                  "   } :data\r\n"  \
                  "\r\n"  \
                  "  .hash ADDR(.dynstr) + ((0x%08X+4)&(-4)) : {\r\n"  \
                  "     *(.hash)\r\n"  \
                  "   } :data\r\n"  \
                  "\r\n"  \
                  "  .init_array ADDR(.hash) + 0x%08X : {\r\n"  \
                  "     *(.init_array*)\r\n"  \
                  "  } :data\r\n"  \
                  "\r\n"  \
                  "  .gnu.version   : { *(.gnu.version)   } :data\r\n"  \
                  "  .gnu.version_d : { *(.gnu.version_d) } :data\r\n"  \
                  "  .gnu.version_r : { *(.gnu.version_r) } :data\r\n"  \
                  "}\r\n"  \

#define SwapBytes( Value1, Value2 )                 \
{                                                   \
    uint8_t temp = Value1;                          \
    Value1 = Value2;                                \
    Value2 = temp;                                  \
}

uint32_t random_magic() {
  uint32_t ret = 0;
  for (int i = 0; i < 4; i++) {
    ret |= (rand() & 0xFF) << i * 8;
  }
  return ret;
}

uint32_t g_random_magic_00 = 0;
uint32_t g_random_magic_01 = 0;
uint32_t g_random_magic_02 = 0;
uint32_t g_random_magic_03 = 0;
uint32_t g_random_magic_04 = 0;
uint32_t g_random_magic_05 = 0;
uint32_t g_random_magic_06 = 0;
uint32_t g_random_magic_07 = 0;

typedef struct __tagKey {
  uint32_t k1;
  uint32_t k2;
} Key;

typedef struct __tagExchange {
  uint32_t m0 : 4;
  uint32_t m1 : 4;
  uint32_t m2 : 4;
  uint32_t m3 : 4;

  uint32_t m4 : 4;
  uint32_t m5 : 4;
  uint32_t m6 : 4;
  uint32_t m7 : 4;
} Exchange;

typedef struct {
  uint32_t     i;
  uint32_t     j;
  uint8_t      S[256];
} Rc4Context;

uint16_t func_global_0001(uint16_t iSeed, uint32_t iMagic1, uint32_t iMagic2, int iCount) {
  int i = 0, j = 0;
  uint16_t iMagic = 0xFFFE;
  for (i = 0; i != iCount; i++) {
    iMagic ^= (i < 2 ? iSeed >> i * 8 : 0xCC) << 8;
    for (j = 0; j != 8; j++) {
      if ((int16_t)iMagic >= 0) {
        iMagic <<= 1;
      } else if ((int8_t)iMagic >= 0) {
        iMagic = iMagic << 1 ^ iMagic1;
      } else {
        iMagic = iMagic << 1 ^ iMagic2;
      }
    }
  }
  return iMagic & 0xFFFF;
}

uint32_t func_global_0005(uint32_t iSeed, uint32_t iMagic1, uint32_t iMagic2, uint32_t iMagic3) {
  register uint32_t p = ((((~iSeed >> 5) ^ (~iSeed << 4)) + ~iSeed) ^ iMagic1) + iSeed;
  register uint32_t q = ((((p >> 5) ^ (p << 4)) + p) ^ iMagic2) + ~iSeed;
  return ((((q >> 5) ^ (q << 4)) + q) ^ iMagic3) + p;
}

void Rc4Initialise(Rc4Context *Context, void const *Key, uint32_t KeySize, uint32_t DropN) {
  uint32_t        i;
  uint32_t        j;
  uint32_t        n;

  // Setup key schedule
  for (i = 0; i < 256; i++) {
    Context->S[i] = (uint8_t)i;
  }

  j = 0;
  for (i = 0; i < 256; i++) {
    j = (j + Context->S[i] + ((uint8_t*)Key)[i % KeySize]) % 256;
    SwapBytes(Context->S[i], Context->S[j]);
  }

  i = 0;
  j = 0;

  // Drop first bytes (if requested)
  for (n = 0; n < DropN; n++) {
    i = (i + 1) % 256;
    j = (j + Context->S[i]) % 256;
    SwapBytes(Context->S[i], Context->S[j]);
  }

  Context->i = i;
  Context->j = j;
}

void Rc4Xor(Rc4Context *Context, void const *InBuffer, void *OutBuffer, uint32_t Size) {
  uint32_t    n;

  for (n = 0; n < Size; n++) {
    Context->i = (Context->i + 1) % 256;
    Context->j = (Context->j + Context->S[Context->i]) % 256;
    SwapBytes(Context->S[Context->i], Context->S[Context->j]);

    ((uint8_t*)OutBuffer)[n] = ((uint8_t*)InBuffer)[n]
      ^ (Context->S[(Context->S[Context->i] + Context->S[Context->j]) % 256]);
  }
}

void exchange(uint8_t *exchange_buf, uint32_t exchange_size) {
  Exchange *ex;
  Key key;

  key.k1 = func_global_0005(exchange_size + g_random_magic_00, g_random_magic_01, g_random_magic_02, g_random_magic_03);
  key.k2 = func_global_0001(key.k1, g_random_magic_04, g_random_magic_05, (exchange_size & 0xFF) + 2);
  key.k2 <<= 0x10;
  ex = (Exchange *)&key.k2;
  ex->m4 ^= ex->m7;
  ex->m7 ^= ex->m4;
  ex->m4 ^= ex->m7;
  ex->m5 ^= ex->m6;
  ex->m6 ^= ex->m5;
  ex->m5 ^= ex->m6;
  key.k2 |= func_global_0001((key.k2 >> 0x10) + ex->m6, g_random_magic_06, g_random_magic_07, ex->m5 + 2);

  Rc4Context rc4;
  Rc4Initialise(&rc4, &key, sizeof(key), 0);
  Rc4Xor(&rc4, exchange_buf, exchange_buf, exchange_size);
}


bool SectionTable::section_table_get_strtab_section(ElfW(Shdr) &strtab) {
  ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mapping_base_ + shoff);
  const ElfW(Shdr) &shstrtab = shdr[shstrndx];
  for (; shdr != shdr + shnum; shdr++) {
    if (shdr->sh_type == SHT_STRTAB) {
      const char *name = (const char *)(mapping_base_ + shstrtab.sh_offset + shdr->sh_name);
      if (strcmp(name, ".dynstr") == 0) {
        memcpy(&strtab, shdr, sizeof(*shdr));
        return true;
      }
    }
  }
  return false;
}


bool SectionTable::section_table_get_symtab_section(ElfW(Shdr) &symtab) {
  ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mapping_base_ + shoff);
  const ElfW(Shdr) &shstrtab = shdr[shstrndx];
  for (; shdr != shdr + shnum; shdr++) {
    if (shdr->sh_type == SHT_DYNSYM) {
      const char *name = (const char *)(mapping_base_ + shstrtab.sh_offset + shdr->sh_name);
      if (strcmp(name, ".dynsym") == 0) {
        memcpy(&symtab, shdr, sizeof(*shdr));
        return true;
      }
    }
  }
  return false;
}

bool SectionTable::section_table_get_hash_section(ElfW(Shdr) &hash) {
  ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mapping_base_ + shoff);
  const ElfW(Shdr) &shstrtab = shdr[shstrndx];
  for (; shdr != shdr + shnum; shdr++) {
    if (shdr->sh_type == SHT_HASH) {
      const char *name = (const char *)(mapping_base_ + shstrtab.sh_offset + shdr->sh_name);
      if (strcmp(name, ".hash") == 0) {
        memcpy(&hash, shdr, sizeof(*shdr));
        return true;
      }
    }
  }
  return false;
}

int main(int argc, char *argv[], char *envp[]) {
  srand((uint32_t)time(NULL));
  g_random_magic_00 = random_magic();
  g_random_magic_01 = random_magic();
  g_random_magic_02 = random_magic();
  g_random_magic_03 = random_magic();
  g_random_magic_04 = random_magic();
  g_random_magic_05 = random_magic();
  g_random_magic_06 = random_magic();
  g_random_magic_07 = random_magic();
  uint32_t magic = random_magic();

  if (argc < 2) {
    printf("Usage:\r\n%s <SO_PATH>\r\n", argv[0]);
    return 0;
  }

  const char *file_name = argv[1];
  off64_t file_offset = 0;

  LibraryLoader lb_loader(file_name);
  if (lb_loader.Load(0) == false) {
    return 0;
  }

  Header &header = lb_loader.header_;
  soinfo *si = lb_loader.si_;
  std::vector<Loadable> &vload = lb_loader.vload_;

  // clear before programe header at the first loadable.
  for (size_t i = 0; i < si->phnum; i++) {
    const ElfW(Phdr)& phdr = si->phdr[i];
    if (phdr.p_type == PT_LOAD) {
      break;
    }
    for (size_t j = 0; j < vload.size(); j++) {
      if (phdr.p_vaddr >= vload[j].p_vaddr
        && vload[j].p_filesz + vload[j].p_vaddr > phdr.p_vaddr + phdr.p_filesz) {
        memset((void *)(vload[j].data + phdr.p_vaddr), 0, phdr.p_filesz);
        break;
      }
    }
  }

  // clear elf header
  memset(vload[0].data, 0, sizeof(ElfW(Ehdr)));

  // write DT_NEEDED
#ifdef __LP64__
  std::vector<Elf64_Xword> needed_tab;
#else
  std::vector<Elf32_Sword> needed_tab;
#endif
  for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_NEEDED) {
      needed_tab.push_back(d->d_un.d_val);
    }
  }
  if (needed_tab.size() != 0) {
    header.needed_strtab_ = vload[0].p_vaddr;
    uint32_t total_size = needed_tab.size() * sizeof(needed_tab[0]);
    if (total_size > si->phnum * sizeof(ElfW(Phdr)) + sizeof(ElfW(Ehdr))) {
      DL_ERR("DT_NEEDED too much.");
      return 0;
    }
    for (size_t i = 0; i < needed_tab.size(); i++) {
#ifdef __LP64__
      ((Elf64_Xword *)vload[0].data)[i] = needed_tab[i];
#else
      ((Elf32_Sword *)vload[0].data)[i] = needed_tab[i];
#endif
    }
  }

  // init TEA encrypt
  // 128-bits key
  struct {
    uint32_t key1;
    uint32_t key2;
    uint32_t key3;
    uint32_t key4;
  } tea_keys = { 0 };
  tea_keys.key1 = random_magic();
  tea_keys.key2 = random_magic();
  tea_keys.key3 = random_magic();
  tea_keys.key4 = random_magic();

  // TEA encrypt round count. 0x10 ~ 0x3F
  int tea_round = random_magic() & 0x3F;
  tea_round = tea_round == 0 ? 0x10 : tea_round;

  // deflate and TEA encrypt
  for (size_t i = 0; i < vload.size(); i++) {
    Loadable &l = vload[i];

    // init zlib stream
    z_stream s = { 0 };
    s.avail_in = l.p_filesz;
    s.next_in = l.data;
    s.avail_out = l.p_filesz;
    s.next_out = l.data;
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, 0) != Z_OK) {
      DL_ERR("zlib init failed.");
      return 0;
    }

    // compress
    int rc;
    INFO("compress before: 0x%08X", *(uint32_t *)l.data);
    if ((rc = deflate(&s, Z_FINISH)) != Z_STREAM_END) {
      DL_ERR("zlib stream error: %d", rc);
      return 0;
    }
    INFO("compress after: 0x%08X", *(uint32_t *)l.data);

    // release zlib stream
    l.p_filesz -= s.avail_out;
    deflateEnd(&s);

    // TEA encrypt.
    size_t j = 0;
    while (j < l.p_filesz) {
      size_t cur_size = j + PAGE_SIZE < l.p_filesz ? PAGE_SIZE : l.p_filesz - j;
      encrypt((uint32_t *)&tea_keys, (uint32_t *)(l.data + j), (cur_size >> 3) << 3, tea_round);
      j += cur_size;
    }
    INFO("encrypt after: 0x%08X", *(uint32_t *)l.data);
  }
  // read .dynstr
  ElfW(Shdr) *strtab = lb_loader.elf_reader_->section_table_find((ElfW(Addr))lb_loader.file_base_, SHT_STRTAB, ".dynstr");
  if (strtab == NULL) {
    DL_ERR("the elf file can not found .dynstr section.");
    return 0;
  }

  // read .dynsym
  ElfW(Shdr) *symtab = lb_loader.elf_reader_->section_table_find((ElfW(Addr))lb_loader.file_base_, SHT_DYNSYM, ".dynsym");
  if (symtab == NULL) {
    DL_ERR("the elf file can not found .dynsym section.");
    return 0;
  }

  // read .hash
  ElfW(Shdr) *hash = lb_loader.elf_reader_->section_table_find((ElfW(Addr))lb_loader.file_base_, SHT_HASH, ".hash");
  if (hash == NULL) {
    DL_ERR("the elf file can not found .hash section.");
    return 0;
  }

  // write config
  FILE* fd_public = fopen("settings.h", "w+b");
  fprintf(fd_public, SETTINGS,
    tea_keys.key1,
    tea_keys.key2,
    tea_keys.key3,
    tea_keys.key4,
    magic,
    tea_round,
    strtab->sh_size,
    symtab->sh_size,
    hash->sh_size,
    g_random_magic_00,
    g_random_magic_01,
    g_random_magic_02,
    g_random_magic_03,
    g_random_magic_04,
    g_random_magic_05,
    g_random_magic_06,
    g_random_magic_07);
  fclose(fd_public);

  // write linker script
  FILE* fd_ldscript = fopen("ldscript", "w+b");
  fprintf(fd_ldscript, LD_SCRIPT, symtab->sh_size, strtab->sh_size, hash->sh_size);
  fclose(fd_ldscript);

  // use batch file to compile.
  system("cmd.exe /c run_make.bat");

  system("copy shell.so shell_bak.so");

  LibraryLoader lb_loader_s("shell_bak.so");
  if (lb_loader_s.Load(0) == false) {
    return 0;
  }

  ElfReader *elf_reader_s = lb_loader_s.elf_reader_;
  Header &header_s = lb_loader_s.header_;
  std::vector<Loadable> &vload_s = lb_loader_s.vload_;

  ElfW(Dyn) *dynamic;
  ElfW(Word) dynamic_flags = 0;
  phdr_table_get_dynamic_section(elf_reader_s->phdr_table(), elf_reader_s->phdr_count(), lb_loader_s.file_base_, &dynamic, &dynamic_flags);
  ElfW(Addr) init_array_0 = 0;
  while (dynamic->d_tag != DT_NULL) {
    switch (dynamic->d_tag) {
      case DT_STRSZ: {
        dynamic->d_un.d_val = strtab->sh_size;
        break;
      }
      case DT_HASH: {
        ((uint32_t *)(lb_loader_s.file_base_ + dynamic->d_un.d_ptr))[0] = header.nbucket_;
        ((uint32_t *)(lb_loader_s.file_base_ + dynamic->d_un.d_ptr))[1] = header.nchain_;
        break;
      }
      case DT_INIT_ARRAY: {
        ElfW(Addr) init_array_off = dynamic->d_un.d_ptr;
        if (init_array_off >= lb_loader_s.file_stat_.st_size) {
          printf("DT_INIT_ARRAY read error: 0x%08X", init_array_off);
          return 0;
        }
        dynamic->d_un.d_ptr = magic ^ init_array_off;
        init_array_0 = *(ElfW(Addr) *)(lb_loader_s.file_base_ + init_array_off);
        *(ElfW(Addr) *)(lb_loader_s.file_base_ + init_array_off) = init_array_0 ^ dynamic->d_un.d_ptr;
        break;
      }
    }
    dynamic++;
  }
  exchange((uint8_t *)(lb_loader_s.file_base_ + init_array_0), vload_s[0].p_filesz - init_array_0);

  // clear .shstrtab
  ElfW(Shdr) *shstrtab = elf_reader_s->shdr_table() + elf_reader_s->header().e_shstrndx;
  memset((void *)(lb_loader_s.file_base_ + shstrtab->sh_offset), 0, shstrtab->sh_size);

  // modify section table
  for (size_t i = 0; i < elf_reader_s->shdr_count(); i++) {
    ElfW(Shdr) &shdr = elf_reader_s->shdr_table()[i];
    if (shdr.sh_type == SHT_NULL || i == elf_reader_s->header().e_shstrndx) {
      continue;
    }
    shdr.sh_addr = 0;
    shdr.sh_offset = 0;
    shdr.sh_size = 0;
  }

  Header_ new_h = { 0 };
  new_h.min_vaddr = header.min_vaddr;
  new_h.load_size_ = header.load_size_;
  new_h.load_seg_num_ = header.load_seg_num_;

  new_h.ARM_exidx = header.ARM_exidx;
  new_h.ARM_exidx_count = header.ARM_exidx_count;

  new_h.bucket_ = header.bucket_;
  new_h.strtab_ = header.strtab_;
  new_h.symtab_ = header.symtab_;
  new_h.plt_rel_ = header.plt_rel_;
  new_h.rel_ = header.rel_;

  new_h.plt_rel_count_ = header.plt_rel_count_;
  new_h.rel_count_ = header.rel_count_;
  new_h.init_array_count_ = header.init_array_count_;
  new_h.fini_array_count_ = header.fini_array_count_;

  new_h.init_func_ = header.init_func_;
  new_h.fini_func_ = header.fini_func_;
  new_h.init_array_ = header.init_array_;
  new_h.fini_array_ = header.fini_array_;

  new_h.needed_count_ = header.needed_count_;
  new_h.needed_strtab_ = header.needed_strtab_;
  new_h.self_size_ = sizeof(new_h);

  // write header
  LONG offset = elf_reader_s->header().e_shoff + elf_reader_s->header().e_shnum * sizeof(ElfW(Shdr));
  LONG pos_hight = 0;
  SetFilePointer(lb_loader_s.fd_, offset, &pos_hight, FILE_BEGIN);
  DWORD test = 0;
  WriteFile(lb_loader_s.fd_, &new_h, new_h.self_size_, &test, NULL);

  offset = new_h.self_size_;

  // write Loadable
  for (size_t i = 0; i < vload.size(); i++) {
    Loadable &l = vload[i];
    l.p_offset = offset + vload.size() * (sizeof(Loadable) - sizeof(void *));
    WriteFile(lb_loader_s.fd_, &l, sizeof(Loadable) - sizeof(void *), &test, NULL);
    offset += l.p_filesz;
  }

  // write Loadable data
  for (size_t i = 0; i < vload.size(); i++) {
    Loadable &l = vload[i];
    WriteFile(lb_loader_s.fd_, l.data, l.p_filesz, &test, NULL);
  }

  return 0;
}
