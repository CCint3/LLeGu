/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef LINKER_PHDR_H
#define LINKER_PHDR_H

 /* Declarations related to the ELF program header table and segments.
  *
  * The design goal is to provide an API that is as close as possible
  * to the ELF spec, and does not depend on linker-specific data
  * structures (e.g. the exact layout of struct soinfo).
  */

#include "linker.h"
#include <vector>
#include <Windows.h>
#include "Header.h"

  /* New code should use sysconf(_SC_PAGE_SIZE) instead. */
#ifndef WINDOWS_PAGE_SIZE
#define WINDOWS_PAGE_SIZE 65536
#endif
#ifndef WINDOWS_PAGE_SIZE
#define  WINDOWS_PAGE_SIZE  WINDOWS_PAGE_SIZE
#endif

/* glibc's PAGE_MASK is the bitwise negation of BSD's! TODO: remove? */
#define WINDOWS_PAGE_MASK (~(WINDOWS_PAGE_SIZE - 1))


// Returns the address of the page containing address 'x'.
#define WINDOWS_PAGE_START(x)  ((x) & WINDOWS_PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define WINDOWS_PAGE_OFFSET(x) ((x) & ~WINDOWS_PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define WINDOWS_PAGE_END(x)    WINDOWS_PAGE_START((x) + (WINDOWS_PAGE_SIZE-1))

class ElfReader {
public:
  ElfReader(const char* name, HANDLE fd, HANDLE mapping, off64_t file_offset, off64_t file_size);
  ~ElfReader();

  bool Load(const android_dlextinfo* extinfo);

  size_t phdr_count() { return phdr_num_; }
  ElfW(Addr) load_start() { return reinterpret_cast<ElfW(Addr)>(load_start_); }
  size_t load_size() { return load_size_; }
  ElfW(Addr) load_bias() { return load_bias_; }
  const ElfW(Phdr)* loaded_phdr() { return loaded_phdr_; }

  // add by zwp
  ElfW(Addr) min_vaddr() { return min_vaddr_; }
  const char* name() { return name_; }
  void get_section_table(SectionTable &s_table);
  ElfW(Phdr)* phdr_table() { return phdr_table_; }
  ElfW(Shdr)* shdr_table() { return shdr_table_; }
  size_t shdr_count() { return shdr_num_; }
  ElfW(Shdr)* section_table_find(ElfW(Addr) file_base, ElfW(Word) sht_type, const char *name);
  ElfW(Ehdr)& header() { return header_; }

private:
  bool ReadElfHeader();
  bool VerifyElfHeader();
  bool ReadProgramHeader();
  bool ReadSectionHeader();
  bool ReserveAddressSpace(const android_dlextinfo* extinfo);
  bool LoadSegments();
  bool FindPhdr();
  bool CheckPhdr(ElfW(Addr) loaded);

  const char* name_;
  HANDLE fd_; // update by zwp
  off64_t file_offset_;
  off64_t file_size_;

  ElfW(Ehdr) header_;
  size_t phdr_num_;
  size_t shdr_num_; // zwp

  void* phdr_mmap_;
  void* shdr_mmap_; // zwp

  ElfW(Phdr)* phdr_table_;
  ElfW(Shdr)* shdr_table_; // zwp

  ElfW(Addr) phdr_size_;
  ElfW(Addr) shdr_size_; // zwp

  // First page of reserved address space.
  void* load_start_;
  // Size in bytes of reserved address space.
  size_t load_size_;
  // Load bias.
  ElfW(Addr) load_bias_;

  // Loaded phdr.
  const ElfW(Phdr)* loaded_phdr_;

  // add by zwp
  ElfW(Addr) min_vaddr_;
  HANDLE mapping_;
  HANDLE mapping_reserve_space_;
};

size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr)* min_vaddr = nullptr, ElfW(Addr)* max_vaddr = nullptr);

int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_serialize_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias, int fd);

int phdr_table_map_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias, int fd);

#if defined(__arm__)
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias, ElfW(Addr)** arm_exidx, size_t* arm_exidix_count);
#endif

void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias, ElfW(Dyn)** dynamic, ElfW(Word)* dynamic_flags);


#endif /* LINKER_PHDR_H */
