
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include "ftrace.h"

sym_strtab	*get_sym_strtab(char const* bin)
{
  Elf*		e;
  GElf_Ehdr	ehdr;
  Elf_Scn	scn;
  GElf_Shdr	shdr;
  int		fd;
  size_t	shstrndx;

  if ((fd = open(bin, O_RDONLY, 0)) == -1)
    exit_error("open() fail");
  if (elf_version(EV_CURRENT) == EV_NONE)
    exit_error("elf_version() fail");
  if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    exit_error("elf_begin() fail");
  if (elf_kind(e) != ELF_K_ELF)
    exit_error("file to execute is not an ELF file");
  elf_getshdrstrndx(e, &shstrndx);
  /* scn = NULL; */
  /* while (scn = elf_nextscn(e, scn)) */
  /*   { */
  /*     printf("section N. %d\n", elf_ndxscn(scn)); */
  /*   } */

  elf_end(e);
  close(fd);
  return NULL;
}
