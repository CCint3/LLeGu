#include "LibraryLoader.h"
#include "file.h"


LibraryLoader::LibraryLoader(const char *name)
  : name_(name), fd_(NULL), mapping_(NULL), header_({ 0 }) {
}


LibraryLoader::~LibraryLoader() {
}


bool LibraryLoader::Load(off64_t file_offset) {
  fd_ = CreateFile(name_, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (fd_ == INVALID_HANDLE_VALUE) {
    DL_ERR("can't open file \"%s\": %s", name_, my_strerror(GetLastError()));
    return false;
  }

  if (_stat64(name_, &file_stat_) != 0) {
    DL_ERR("can't _stat64 file \"%s\"", name_);
    return false;
  }

  mapping_ = CreateFileMapping(fd_, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (mapping_ == NULL) {
    DL_ERR("can't mapping file \"%s\": %s", name_, my_strerror(GetLastError()));
    return false;
  }
  file_base_ = (ElfW(Addr))mmap64(0, 0, 0, 0, mapping_, 0);

  elf_reader_ = new ElfReader(name_, fd_, mapping_, file_offset, file_stat_.st_size);
  if (elf_reader_->Load(NULL) == false) {
    DL_ERR("elf reader failed.");
    return false;
  }

  for (size_t i = 0; i < elf_reader_->phdr_count(); i++) {
    const ElfW(Phdr) &phdr = elf_reader_->loaded_phdr()[i];
    if (phdr.p_type != PT_LOAD) {
      continue;
    }
    header_.load_seg_num_++;
    Loadable load;
    load.p_vaddr = phdr.p_vaddr;
    load.p_offset = phdr.p_offset;
    load.p_filesz = phdr.p_filesz;
    load.p_memsz = phdr.p_memsz;
    load.p_flags = phdr.p_flags;
    load.data = (uint8_t *)malloc(phdr.p_filesz);
    ssize_t rc = pread64(fd_, load.data, phdr.p_filesz, file_offset + phdr.p_offset);
    if (rc == -1 || rc != phdr.p_filesz) {
      DL_ERR("read loadable data failed, index: %d.", i);
      return  false;
    }
    vload_.push_back(load);
  }

  si_ = soinfo_alloc(name_, &file_stat_, file_offset, 0);
  if (si_ == nullptr) {
    DL_ERR("can't alloc space for soinfo.");
    return false;
  }

  si_->base = elf_reader_->load_start();
  si_->size = elf_reader_->load_size();
  si_->load_bias = elf_reader_->load_bias();
  si_->phnum = elf_reader_->phdr_count();
  si_->phdr = elf_reader_->loaded_phdr();

  si_->prelink_image(header_);

  header_.min_vaddr = elf_reader_->min_vaddr();
  header_.load_size_ = elf_reader_->load_size();

  return true;
}