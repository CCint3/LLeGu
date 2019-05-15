
#ifndef LIBRARY_LOADER_H_
#define LIBRARY_LOADER_H_

#include <Windows.h>
#include <sys/stat.h>
#include <linker.h>
#include <linker_phdr.h>
#include <vector>

#include "Header.h"

class LibraryLoader {
public:
  LibraryLoader(const char *name);
  ~LibraryLoader();

  bool Load(off64_t file_offset);

public:
  const char *name_;
  HANDLE fd_;
  HANDLE mapping_;
  ElfW(Addr) file_base_;
  struct _stat64 file_stat_;
  ElfReader* elf_reader_;
  soinfo* si_;
  Header header_;
  std::vector<Loadable> vload_;
};

#endif