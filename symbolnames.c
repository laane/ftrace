
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include "ftrace.h"

sym_strtab	*get_sym_strtab(char const* bin)
{
  Elf*		e;
  GElf_Ehdr	ehdr;
  int		fd;

  if ((fd = open(bin, O_RDONLY, 0)) == -1)
    exit_error("open() fail");
  if (elf_version(EV_CURRENT) == EV_NONE)
    exit_error("elf_version() fail");
  if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    exit_error("elf_begin() fail");
  if (elf_kind(e) != ELF_K_ELF)
    exit_error("file to execute is not an ELF file");
  if (gelf_getehdr(e, &ehdr) == NULL)
    exit_error("gelf_getehdr() fail");

  elf_end(e);
  close(fd);
  return NULL;
}
