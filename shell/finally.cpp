

#define __work_around_b_19059885__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <elf.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/cachectl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zlib.h>
#include <math.h>

#include "public.h"
#include "finally.h"
#include "include/linker_relocs.h"
#include "settings.h"


// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //

soinfo *g_self_si = NULL;
soinfo *g_parasitic = NULL;
p_munmap g_munmap = NULL;
#ifdef MYLOG
p___android_log_print g_LogFun = NULL;
#endif

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //


// // // // // // // // // // // // // //
// encrypt and decrypt begin
// // // // // // // // // // // // // //
uint16_t func_global_0001(uint16_t iSeed, uint32_t iMagic1, uint32_t iMagic2, int iCount) {
  int i = 0, j = 0;
  uint16_t iMagic = 0xFFFE;
  for (i = 0; i != iCount; i++) {
    iMagic ^= (i < 2 ? iSeed >> i * 8 : 0xCC) << 8;
    for (j = 0; j != 8; j++) {
      if ((int16_t)iMagic >= 0) {
        iMagic <<= 1;
      } else if ((int8_t)iMagic >= 0) {
        iMagic = (uint16_t)((iMagic << 1) ^ iMagic1);
      } else {
        iMagic = (uint16_t)((iMagic << 1) ^ iMagic2);
      }
    }
  }
  return (uint16_t)iMagic;
}

uint32_t func_global_0005(uint32_t iSeed, uint32_t iMagic1, uint32_t iMagic2, uint32_t iMagic3) {
  register uint32_t p = ((((~iSeed >> 5) ^ (~iSeed << 4)) + ~iSeed) ^ iMagic1) + iSeed;
  register uint32_t q = ((((p >> 5) ^ (p << 4)) + p) ^ iMagic2) + ~iSeed;
  return ((((q >> 5) ^ (q << 4)) + q) ^ iMagic3) + p;
}

// // // // // // // // // // // // // //
// encrypt and decrypt end
// // // // // // // // // // // // // //

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //

// // // // // // // // // // // // // //
// Rc4.c begin
// // // // // // // // // // // // // //
void Rc4Initialise(Rc4Context* Context, void const* Key, uint32_t KeySize, uint32_t DropN) {
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


void Rc4Xor(Rc4Context* Context, void const* InBuffer, void* OutBuffer, uint32_t Size) {
  uint32_t    n;

  for (n = 0; n < Size; n++) {
    Context->i = (Context->i + 1) % 256;
    Context->j = (Context->j + Context->S[Context->i]) % 256;
    SwapBytes(Context->S[Context->i], Context->S[Context->j]);

    ((uint8_t*)OutBuffer)[n] = ((uint8_t*)InBuffer)[n] ^ (Context->S[(Context->S[Context->i] + Context->S[Context->j]) % 256]);
  }
}
// // // // // // // // // // // // // //
// Rc4.c end
// // // // // // // // // // // // // //

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // //

// // // // // // // // // // // // // //
// dlsym.cpp begin
// // // // // // // // // // // // // //

void null_func(...) {
  return;
}

int is_symbol_global_and_defined(const ElfW(Sym) *s) {
  if (ELF_ST_BIND(s->st_info) == STB_GLOBAL ||
      ELF_ST_BIND(s->st_info) == STB_WEAK) {
    return s->st_shndx != SHN_UNDEF;
  }
  return 0;
}


uint32_t symbol_checksum(const char *name) {
  const uint8_t* name_ = (const uint8_t*)name;
  uint16_t sum = 0;
  uint16_t cnt = 0;
  while (*name_) {
    sum += *name_++;
    cnt++;
  }
  return (uint32_t)((sum << 0x10) | (cnt & 0xFFFF));
}

uint32_t elf_hash(const char *name) {
  const uint8_t* name_ = (const uint8_t*)name;
  uint32_t h = 0, g;
  while (*name_) {
    h = (h << 4) + *name_++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }
  return h;
}

ElfW(Addr) elf_lookup(uint32_t hash, uint32_t checksum) {

  soinfo_list_entry_t *entry = g_self_si->children_.head_;
  while (entry) {

    soinfo *si = entry->element;
    for (uint32_t i = 0; i != si->nbucket_; i++) {
      for (uint32_t n = si->bucket_[i]; n != 0; n = si->chain_[n]) {
        ElfW(Sym) *s = si->symtab_ + n;
        if (elf_hash(si->strtab_ + s->st_name) == hash &&
            symbol_checksum(si->strtab_ + s->st_name) == checksum &&
            is_symbol_global_and_defined(s)) {
          return si->load_bias + s->st_value;
        }
      }
    }

    entry = entry->next;
  }

  return (ElfW(Addr))&null_func;
}
// // // // // // // // // // // // // //
// dlsym.cpp end
// // // // // // // // // // // // // //

void TEA_Decrypt(uint32_t *key, uint32_t *buf, int size, int round) {
  int i, j;
  uint32_t magic_;
  uint32_t buf_0_;
  uint32_t buf_1_;

  int round_count_ = size >> 3;
  uint32_t key_0_ = key[(round_count_ & 1) * 2 + 0];
  uint32_t key_1_ = key[(round_count_ & 1) * 2 + 1];

  if (buf && !(size & 7) && round) {
    for (i = 0; i < round_count_; i++, buf += 2) {
      buf_0_ = buf[0] ^ key_0_;
      buf_1_ = buf[1] ^ key_1_;
      for (j = 0, magic_ = 0x9E3779B9 * round; j < round; j++, magic_ += 0x61C88647) {
        buf_1_ -= ((buf_0_ << 4) + key[2]) ^ (buf_0_ + magic_) ^ ((buf_0_ >> 5) + key[3]);
        buf_0_ -= ((buf_1_ << 4) + key[0]) ^ (buf_1_ + magic_) ^ ((buf_1_ >> 5) + key[1]);
      }
      buf[0] = buf_0_;
      buf[1] = buf_1_;
    }
  }
}

void fix_symtab(size_t nchain, ElfW(Sym) *symtab, ElfW(Addr) load_bias, ElfW(Addr) self_load_bias) {
  // symtab_ 的数量和 nchain_ 相等
  for (int i = 0; i < nchain; i++) {
    ElfW(Sym) *sym = &symtab[i];
    if ((sym->st_info >> 4) && (sym->st_info >> 4 <= 2) && (sym->st_shndx)) {
      sym->st_value += load_bias - self_load_bias;
    }
  }
}

// relocate
void relocate(soinfo *si, ElfW(Rel) *rels, int rel_cnt, void **lib_buf, int lib_buf_cnt) {
  for (int i = 0; i < rel_cnt; i++) {
    ElfW(Rel) *rel = &rels[i];
    //ELF32_R_TYPE()
    //ELF32_R_SYM()
    ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
    ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);

    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(si->load_bias + rel->r_offset);
    ElfW(Addr) sym_addr = 0;
    const char *sym_name = NULL;

    if (type == R_GENERIC_NONE) {
      continue;
    }

    const ElfW(Sym)* s = NULL;

    if (sym != 0) {
      sym_name = si->strtab_ + si->symtab_[sym].st_name;
      //ALOGE(LOG_TAG, "found %s", sym_name);

      // found in DT_NEEDED
      for (int j = 0; j < lib_buf_cnt; j++) {
        sym_addr = ElfW(Addr) CALL(dlsym, lib_buf[j], sym_name);
        if (sym_addr != NULL) {
          //ALOGE(LOG_TAG, "founded in %s", lsi->soname_);
          break;
        }
      }

      // found in self
      if (sym_addr == NULL) {
        sym_addr = ElfW(Addr) CALL(dlsym, si, sym_name);
        if (sym_addr != NULL) {
          //ALOGE(LOG_TAG, "founded in self");
        }
      }

      if (sym_addr == NULL) {
        ALOGE(LOG_TAG, "sym_addr == NULL %s", sym_name);
        // We only allow an undefined symbol if this is a weak reference...
        s = &si->symtab_[sym];
        if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
          return ;
        }
      }
    }

    if (type == R_ARM_ABS32) {
      *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
    } else if (type == R_ARM_REL32) {
      *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr - rel->r_offset;
    } else if (type == R_GENERIC_GLOB_DAT || type == R_GENERIC_JUMP_SLOT) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
    } else if (type == R_GENERIC_RELATIVE) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) += si->load_bias;
    }

  }
  return;
}

int get_path(char *buf, soinfo *si) {
  int ret = 0;
  char szLine[0x400];
  char szTmp[0x400];
  FILE *fd;
  ElfW(Addr) begin, end;
  ElfW(Addr) load_bias = si->load_bias;

  if (si->link_map_head.l_name != NULL) {
    CALL(memcpy, buf, si->link_map_head.l_name, CALL(strlen, si->link_map_head.l_name) + 1);
    ret = 1;
  } else {
    fd = CALL(fopen, "/proc/self/maps", "r");

    while(!CALL(feof, fd)) {
      CALL(fgets, szLine, sizeof(szLine), fd);
      CALL(sscanf, szLine, "%p-%p %s %s %s %s %s", (void *)&begin, (void *)&end, szTmp, szTmp, szTmp, szTmp, buf);
      if (load_bias >= begin && load_bias < end) {
        ret = 1;
        break;
      }
    }
  }
  ALOGE(LOG_TAG, "get_path ret: %d, path: %s", ret, buf);
  return ret;
}

bool elf_reader_Load(int fd, off64_t file_offset, off64_t file_size, soinfo &si, Header &header) {
  // Read Header
  ssize_t rc = MY_TEMP_FAILURE_RETRY(CALL(pread64, fd, &header, sizeof(header), file_offset));
  if (rc < 0 || rc != sizeof(header)) {
    return false;
  }

  // Verify Header
  if (header.load_seg_num_ < 1 || header.load_seg_num_ > 65536 / sizeof(ElfW(Phdr))) {
    return false;
  }

  // ReserveAddressSpace
  si.size = header.load_size_;
  if (header.load_size_ == 0) {
    return false;
  }
  uint8_t* addr = reinterpret_cast<uint8_t*>(header.min_vaddr);
  void* start = CALL(mmap, 0, header.load_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (start == MAP_FAILED) {
    return false;
  }

  si.base = reinterpret_cast<ElfW(Addr)>(start);
  si.load_bias = reinterpret_cast<uint8_t*>(start) - addr;
  ALOGE(LOG_TAG, "mmap: %p, load_size: 0x%08X load_bias: %p", start, header.load_size_, si.load_bias);

  // Load Segments
  LoadSegment *phdr = (LoadSegment *)alloca(sizeof(LoadSegment));
  for (size_t i = 0; i < header.load_seg_num_; ++i) {
    rc = MY_TEMP_FAILURE_RETRY(CALL(pread64, fd,
                                       phdr,
                                       sizeof(LoadSegment),
                                       file_offset + header.self_size_ + sizeof(LoadSegment) * i));
    if (rc < 0 || rc != sizeof(LoadSegment)) {
      return false;
    }

    ElfW(Addr) seg_start = si.load_bias + phdr->p_vaddr;
    ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

    ElfW(Addr) seg_page_start = PAGE_START(seg_start);
    ElfW(Addr) seg_page_end   = PAGE_END(seg_end);
    ElfW(Addr) seg_page_size  = seg_page_end - seg_page_start;

    //ElfW(Addr) seg_file_end   = seg_start + phdr->p_filesz;

    // File offsets.
    ElfW(Addr) file_start = phdr->p_offset + (ElfW(Addr))file_offset;
    ElfW(Addr) file_end   = file_start + phdr->p_filesz;

    ElfW(Addr) file_page_start = PAGE_START(file_start);
    ElfW(Addr) file_length     = file_end - file_page_start;

    if (file_size <= 0) {
      return false;
    }

    if (file_end > static_cast<size_t>(file_size)) {
      return false;
    }

    if (file_length != 0) {
      void *seg_addr = CALL(mmap, reinterpret_cast<void *>(seg_page_start),
                            seg_page_size,
                            PROT_READ | PROT_WRITE,
                            MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                            -1,
                            0);
      if (seg_addr == MAP_FAILED) {
        return false;
      }
      ALOGE(LOG_TAG, "idx: %d seg_addr: %p seg_page_size: 0x%08X", i, seg_addr, seg_page_size);

      // init TEA encrypt 128-bits key
      struct {
        uint32_t key0;
        uint32_t key1;
        uint32_t key2;
        uint32_t key3;
      } tea_keys = { 0 };
      tea_keys.key0 = TEA_KEYS_0;
      tea_keys.key1 = TEA_KEYS_1;
      tea_keys.key2 = TEA_KEYS_2;
      tea_keys.key3 = TEA_KEYS_3;
      ALOGE(LOG_TAG, "TEA round: %d key0: 0x%08X, key1: 0x%08X, key2: 0x%08X, key3: 0x%08X", TEA_ROUND, TEA_KEYS_0, TEA_KEYS_1, TEA_KEYS_2, TEA_KEYS_3);

      // init zlib stream
      z_stream zStream;
      CALL(memset, &zStream, 0, sizeof(zStream));
      if(CALL(inflateInit2_, &zStream, -15, ZLIB_VERSION, (int)sizeof(z_stream)) != Z_OK) {
        ALOGE(LOG_TAG, "idx: %d inflate init failed.", i);
        return false;
      }

      // decrypt and decompress
      ElfW(Addr) j = 0, it = 0;
      size_t current_size = 0;
      uint8_t *buf = (uint8_t *)alloca(PAGE_SIZE);
      while (j < phdr->p_filesz) {
        // 每次解密解压最多0x1000字节，直到所有数据均被解密解压
        current_size = j + PAGE_SIZE <= phdr->p_filesz ? PAGE_SIZE : phdr->p_filesz - j;
        rc = MY_TEMP_FAILURE_RETRY(CALL(pread64, fd, buf, current_size, file_start + j));
        if (rc != current_size) {
          return false;
        }

        j == 0 ? ALOGE(LOG_TAG, "idx: %d decrypt before: 0x%08X", i, *(uint32_t *)buf) : 0;

        // TEA 解密大小必须整除 8
        TEA_Decrypt((uint32_t *)&tea_keys, (uint32_t *)buf, (current_size >> 3) << 3, TEA_ROUND);

        j == 0 ? ALOGE(LOG_TAG, "idx: %d decrypt after : 0x%08X", i, *(uint32_t *)buf) : 0;

        // 解压
        zStream.avail_in = current_size;
        zStream.next_in = buf;
        zStream.avail_out = seg_page_size - it;
        zStream.next_out = (Bytef *)(seg_start + it);
        int inflate_retval = CALL(inflate, &zStream, Z_NO_FLUSH);
        if (inflate_retval < Z_OK) {
          ALOGE(LOG_TAG, "idx: %d inflate failed. ret: %d", i, inflate_retval);
          return false;
        }
        j == 0 ? ALOGE(LOG_TAG, "idx %d decompress after: 0x%08X", i, *(uint32_t *)seg_start) : 0;
        // 解压前可用的缓冲区大小 - 解压后可用的缓冲区大小 = 成功解压出的数据大小
        it += seg_page_size - it - zStream.avail_out;
        if (inflate_retval == Z_STREAM_END) {
          break;
        }
        j += current_size;
      }
      CALL(inflateEnd, &zStream);
      ALOGE(LOG_TAG, "idx: %d inflate: 0x%08X", i, it);

      // 如果段是可写的，并且段结束不在页边界，那么将剩余字节归零。
      if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(it) > 0) {
        CALL(memset, reinterpret_cast<void*>(seg_start + it) , 0, PAGE_SIZE - PAGE_OFFSET(seg_start + it));
      }

      // 刷新缓存
      for (j = seg_page_start; j < seg_page_end; j += PAGE_SIZE) {
        CACHEFLUSH(j, j + PAGE_SIZE);
      }
    }
  } // end for (size_t i = 0; i < elf_reader.phdr_num_; ++i)
  g_self_si->strtab_size_ = STRTAB_SIZE;
  // link_image
  ALOGE(LOG_TAG, "LINK IMAGE");
  link_image(si, header);

  // 恢复内存保护属性
  for (size_t i = 0; i < header.load_seg_num_; ++i) {
    rc = MY_TEMP_FAILURE_RETRY(CALL(pread64, fd,
                                       phdr,
                                       sizeof(LoadSegment),
                                       file_offset + header.self_size_ + sizeof(LoadSegment) * i));
    if (rc < 0 || rc != sizeof(LoadSegment)) {
      return false;
    }

    ElfW(Addr) seg_start = si.load_bias + phdr->p_vaddr;
    ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

    ElfW(Addr) seg_page_start = PAGE_START(seg_start);
    ElfW(Addr) seg_page_end   = PAGE_END(seg_end);
    ElfW(Addr) seg_page_size  = seg_page_end - seg_page_start;

    ALOGE(LOG_TAG, "idx: %d mprotect: %p size: 0x%08X flags: %d", i, seg_page_start, seg_page_size, PFLAGS_TO_PROT(phdr->p_flags));
    CALL(mprotect, (void *)seg_page_start, seg_page_size, PFLAGS_TO_PROT(phdr->p_flags));
  }
  return true;
}

bool link_image(soinfo &si, Header &header) {
  ElfW(Addr) self_load_bias = g_self_si->load_bias;
  si.flags_ = 0;

  // .dynsym
  si.symtab_ = (ElfW(Sym) *) (si.load_bias + header.symtab_);

  // .dynstr
  si.strtab_ = (char *) (si.load_bias + header.strtab_);

  // .hash
  si.nbucket_ = g_self_si->nbucket_;
  si.nchain_ = g_self_si->nchain_;
  si.bucket_ = (uint32_t *) (si.load_bias + header.bucket_);
  si.chain_ = (uint32_t *) (si.load_bias + header.bucket_ + si.nbucket_ * sizeof(si.bucket_));

  // .rel.dyn
  si.rel_ = (ElfW(Rel) *) (si.load_bias + header.rel_);
  si.rel_count_ = header.rel_count_;

  // .rel.plt
  si.plt_rel_ = (ElfW(Rel) *) (si.load_bias + header.plt_rel_);
  si.plt_rel_count_ = header.plt_rel_count_;

  // DT_INIT
  si.init_func_ = header.init_func_ ? (linker_function_t) (si.load_bias + header.init_func_) : NULL;
  // DT_INIT_ARRAY
  si.init_array_ = header.init_array_ ? (linker_function_t *) (si.load_bias + header.init_array_) : NULL;
  // DT_INIT_ARRAYSZ
  si.init_array_count_ = header.init_array_count_;

  // DT_FINI
  si.fini_func_ = header.fini_func_ ? (linker_function_t) (si.load_bias + header.init_func_) : NULL;
  // DT_FINI_ARRAY
  si.fini_array_ = header.fini_array_ ? (linker_function_t *) (si.load_bias + header.fini_array_) : NULL;
  // DT_FINI_ARRAYSZ
  si.fini_array_count_ = header.fini_array_count_;

  si.ARM_exidx = (uint32_t *) (si.load_bias + header.ARM_exidx);
  si.ARM_exidx_count = header.ARM_exidx_count;

  // load DT_NEEDED
  soinfo **needed_si = (soinfo **)alloca(sizeof(soinfo *) * header.needed_count_);
  ElfW(Addr) *needed_strtab = (ElfW(Addr) *)(si.load_bias + header.needed_strtab_);
  for (int i = 0; i < header.needed_count_; i++) {
    ALOGE(LOG_TAG, "load dt_needed %s", si.strtab_ + needed_strtab[i]);
    needed_si[i] = (soinfo *) CALL(dlopen, si.strtab_ + needed_strtab[i], 0);
    if (needed_si[i] == NULL) {
      return false;
    }
  }

  // .rel.dyn: [DT_REL] ELF REL Relocation Table
  ALOGE(LOG_TAG, "relocate rel_: %p count_: 0x%08X", si.rel_, si.rel_count_);
  relocate(&si, si.rel_, si.rel_count_, (void **) needed_si, header.needed_count_);
  CALL(memset, si.rel_, 0, sizeof(ElfW(Rel)) * si.rel_count_);

  // .rel.plt: [DT_JMPREL] ELF JMPREL Relocation Table
  ALOGE(LOG_TAG, "relocate plt_rel_: %p count_: 0x%08X", si.plt_rel_, si.plt_rel_count_);
  relocate(&si, si.plt_rel_, si.plt_rel_count_, (void **) needed_si, header.needed_count_);
  CALL(memset, si.plt_rel_, 0, sizeof(ElfW(Rel)) * si.plt_rel_count_);

  ALOGE(LOG_TAG, "fix symtab: %p nchain: 0x%08X", si.symtab_, g_self_si->nchain_);
  fix_symtab(g_self_si->nchain_, si.symtab_, si.load_bias, self_load_bias);

  ALOGE(LOG_TAG, "move symtab: from %p to %p size 0x%08X", si.symtab_, g_self_si->symtab_, SYMTAB_SIZE);
  CALL(memcpy, g_self_si->symtab_, si.symtab_, SYMTAB_SIZE);
  CALL(memset, si.symtab_, 0, SYMTAB_SIZE);

  ALOGE(LOG_TAG, "move strtab: from %p to %p size 0x%08X", si.strtab_, g_self_si->strtab_, STRTAB_SIZE);
  CALL(memcpy, g_self_si->strtab_, si.strtab_, STRTAB_SIZE);
  CALL(memset, si.strtab_, 0, STRTAB_SIZE);

  ALOGE(LOG_TAG, "move hash: from %p to %p size 0x%08X", si.bucket_, g_self_si->bucket_, HASH_SIZE-8);
  CALL(memcpy, g_self_si->bucket_, si.bucket_, HASH_SIZE-8);
  CALL(memset, si.bucket_, 0, HASH_SIZE-8);
  return true;
}

void load_library(const char* name) {
  // Open the file.;
  int fd = MY_TEMP_FAILURE_RETRY(CALL(open, name, O_RDONLY | O_CLOEXEC));
  ALOGE(LOG_TAG, "load_library open fd: 0x%08X", fd);

  struct stat file_stat;
  MY_TEMP_FAILURE_RETRY(CALL(fstat, fd, &file_stat));
  if (file_stat.st_size < 0 || file_stat.st_size < sizeof(ElfW(Ehdr))) {
    return;
  }

  ElfW(Ehdr) ehdr;
  ssize_t rc = MY_TEMP_FAILURE_RETRY(CALL(pread, fd, &ehdr, sizeof(ElfW(Ehdr)), 0));
  if (rc < 0 || rc != sizeof(ElfW(Ehdr))) {
    return;
  }
  ALOGE(LOG_TAG, "read ehdr, sizeof=0x%08X", rc);

  off64_t file_offset = ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shnum;
  if (file_offset < 0 || file_offset % 4 != 0 || file_offset >= file_stat.st_size) {
    return;
  }
  ALOGE(LOG_TAG, "file_offset: 0x%016X", file_offset);

  g_parasitic = (soinfo *)CALL(malloc, sizeof(soinfo));
  soinfo &si = *g_parasitic;
  Header header;
  ALOGE(LOG_TAG, "Header size: 0x%08X, LoadSegment size: 0x%08X", sizeof(Header), sizeof(LoadSegment));
  if (!elf_reader_Load(fd, file_offset, file_stat.st_size, si, header)) {
    return;
  }

  if (si.init_func_ != NULL) {
    ALOGE(LOG_TAG, "calling DT_INIT: 0x%08X", si.init_func_);
    si.init_func_();
    si.init_func_ = NULL;
  }

  for (int i = 0; i < si.init_array_count_; i++) {
    if (si.init_array_[i] != NULL) {
      ALOGE(LOG_TAG, "calling DT_INIT_ARRAY_%02X: 0x%08X", i, si.init_array_[i]);
      si.init_array_[i]();
      si.init_array_[i] = NULL;
    }
  }
  CALL(close, fd);
}


__unused void load() {
  soinfo *si;
  __asm__ __volatile__(
  "MOV %0, R6\n"
  :
  "=r" (si)
  );
  g_self_si = si;
  char szPath[0x400];
  while (get_path(szPath, si) == 0);
  load_library(szPath);
}

__unused void _fini() {
#ifdef MYLOG
  g_LogFun(6, LOG_TAG, "DT_FINI called.");
#endif

  if (g_parasitic == NULL) {
    return;
  }
  soinfo &si = *g_parasitic;

  for (size_t i = 0; i < si.fini_array_count_; i++) {
    if (si.fini_array_[i] != NULL) {
#ifdef MYLOG
      g_LogFun(6, LOG_TAG, "calling DT_FINI_ARRAY_%02X: 0x%08X", i, si.fini_array_[i]);
#endif
      si.fini_array_[i]();
      si.fini_array_[i] = NULL;
    }
  }

  if (si.fini_func_ != NULL) {
#ifdef MYLOG
    g_LogFun(6, LOG_TAG, "calling DT_FINI: 0x%08X", si.fini_func_);
#endif
    si.fini_func_();
  }

  __unused int rc = g_munmap((void *)si.base, si.size);
#ifdef MYLOG
  g_LogFun(6, LOG_TAG, "munmap ret: %d", rc);
#endif
  CALL(free, g_parasitic);
}


__unused void _init() {
  soinfo *si;
  __asm__ __volatile__(
  "MOV %0, R6\n"
  :
  "=r" (si)
  );
  //__builtin_return_address(0);
  ElfW(Addr) load_bias = si->load_bias;

  // 读取第一个 Loadable Segment 地址和它的文件大小
  const ElfW(Phdr) *phdr = si->phdr;

  int phnum = si->phnum;
  ElfW(Addr) loadable0_vaddr = 0;
  ElfW(Word) loadable0_filesz = 0;
  ElfW(Word) loadable0_flags = 0;
  while (phnum >= 0) {
    if (phdr[phnum].p_type == 1) {
      loadable0_vaddr = phdr[phnum].p_vaddr;
      loadable0_filesz = phdr[phnum].p_filesz;
      loadable0_flags = phdr[phnum].p_flags;
    }
    phnum--;
  }

  // 读取 DT_INIT_ARRAYSZ
  int init_array_num = 0;

  ElfW(Dyn) *dynamic = si->dynamic;
  while (dynamic->d_tag != 0) {
    if (dynamic->d_tag == DT_INIT_ARRAYSZ) {
      init_array_num = dynamic->d_un.d_val / sizeof(ElfW(Addr));
      break;
    }
    dynamic++;
  }

  // 修复 01: init_array 和 DT_INIT_ARRAY
  ElfW(Addr) xor_ = (ElfW(Addr))si->init_array_ - load_bias;
  ElfW(Addr) *init_array_ = (ElfW(Addr) *)(load_bias + (xor_ ^ MAGIC_01));

  // 计算解密起始位置和结束位置
  ElfW(Word) decrypt_begin = (*init_array_ - load_bias) ^ xor_;
  ElfW(Word) decrypt_size = loadable0_filesz - decrypt_begin;

  // 检查：判断开始和结束是否超过界限
  while (decrypt_begin == 0 || decrypt_size == 0 || decrypt_begin < loadable0_vaddr || (decrypt_begin + decrypt_size) > (loadable0_vaddr + loadable0_filesz)) {
    decrypt_begin = 0;
  }

  Key key;
  key.k1 = func_global_0005(decrypt_size + RANDOM_00, RANDOM_01, RANDOM_02, RANDOM_03);
  key.k2 = func_global_0001((uint16_t)key.k1, RANDOM_04, RANDOM_05, (decrypt_size & 0xFF) + 2);
  key.k2 <<= 0x10;
  Exchange *ex = (Exchange *)&key.k2;
  ex->m4 ^= ex->m7;
  ex->m7 ^= ex->m4;
  ex->m4 ^= ex->m7;
  ex->m5 ^= ex->m6;
  ex->m6 ^= ex->m5;
  ex->m5 ^= ex->m6;
  key.k2 |= func_global_0001((uint16_t)((key.k2 >> 0x10) + ex->m6), RANDOM_06, RANDOM_07, ex->m5 + 2);

  g_self_si = si;

#ifdef MYLOG
#ifdef DYNAMIC_CALL
  g_LogFun = (p___android_log_print)elf_lookup(ELF_HASH___android_log_print, CHECKSUM___android_log_print);
#else
  g_LogFun = &__android_log_print;
#endif
#endif

#ifdef DYNAMIC_CALL
  g_munmap = (p_munmap)elf_lookup(ELF_HASH_munmap, CHECKSUM_munmap);
#else
  g_munmap = &munmap;
#endif

  CALL(mprotect, (void *)PAGE_START(load_bias + loadable0_vaddr), PAGE_END(loadable0_filesz), PROT_READ | PROT_WRITE | PROT_EXEC);

  Rc4Context rc4;
  Rc4Initialise(&rc4, &key, sizeof(key), 0);
  Rc4Xor(&rc4, (void *)(load_bias + decrypt_begin), (void *)(load_bias + decrypt_begin), decrypt_size);

  CALL(mprotect, (void *)PAGE_START(load_bias + loadable0_vaddr), PAGE_END(loadable0_filesz), PFLAGS_TO_PROT(loadable0_flags));
  {
    int rc = CACHEFLUSH(load_bias, load_bias + PAGE_END(si->size));
    ALOGE(LOG_TAG, "cacheflush : 0x%08X", rc);
  }


  // 修复 01: init_array
  si->init_array_ = (linker_function_t *)init_array_;
  while (init_array_num > 0) {
    *init_array_ = (*init_array_ - load_bias) ^ xor_;
    xor_ ^= *init_array_;
    *init_array_ += load_bias;
    init_array_++;
    init_array_num--;
  }
  ALOGE(LOG_TAG, "_init finished");
  return ;
}