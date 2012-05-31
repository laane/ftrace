
#include <fcntl.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include "ftrace.h"

static void	init_libelf(int *fd, Elf **e, char const* bin)
{
  if ((*fd = open(bin, O_RDONLY, 0)) == -1)
    exit_error("open() fail");
  if (elf_version(EV_CURRENT) == EV_NONE)
    exit_error("elf_version() fail");
  if ((*e = elf_begin(*fd, ELF_C_READ, NULL)) == NULL)
    exit_error("elf_begin() fail");
  if (elf_kind(*e) != ELF_K_ELF)
    exit_error("file to execute is not an ELF file");
}

static Elf_Scn	*get_sym_shdr(Elf *e)
{
  Elf_Scn	*scn;
  Elf64_Shdr	*shdr;

  scn = NULL;
  while ((scn = elf_nextscn(e, scn)))
    {
      if ((shdr = elf64_getshdr(scn)) == NULL)
      	exit_error("gelf_getshdr() fail");
      if (shdr->sh_type == SHT_SYMTAB)
	break;
    }
  if (!scn)
    exit_error("symtab not found omg");
  return scn;
}

static void	add_symbol(sym_strtab **list, Elf64_Sym *sym, char const* name)
{
  sym_strtab	*elem;

  if ((elem = malloc(sizeof(*elem))) == NULL)
    return ;
  elem->addr = sym->st_value;
  if (name)
    strcpy(elem->name, name);
  elem->next = *list;
  *list = elem;
}

static void	load_symtab(sym_strtab **list, Elf *e, Elf_Scn *sym_scn)
{
  Elf_Data	*data;
  Elf64_Shdr	*sym_shdr;
  Elf64_Sym	*symtab;
  size_t	nb_symbols;

  sym_shdr = elf64_getshdr(sym_scn);
  data = elf_getdata(sym_scn, NULL);

  symtab = (Elf64_Sym*) data->d_buf;
  nb_symbols = sym_shdr->sh_size / sym_shdr->sh_entsize;

  for (size_t i = 1; i < nb_symbols; ++i)
    {
      if ((symtab[i].st_info & 15) != STT_FILE
          && (symtab[i].st_info & 15) != STT_SECTION)
	add_symbol(list, &symtab[i], elf_strptr(e, sym_shdr->sh_link, symtab[i].st_name));
    }
}

sym_strtab	*get_sym_strtab(char const* bin)
{
  Elf		*e;
  Elf_Scn	*sym_scn;
  int		fd;
  sym_strtab	*list = NULL;

  init_libelf(&fd, &e, bin);
  sym_scn = get_sym_shdr(e);
  load_symtab(&list, e, sym_scn);

  elf_end(e);
  close(fd);
  return list;
}
