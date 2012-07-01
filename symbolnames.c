#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include "ftrace.h"

static int		fd_bak;
static Elf		*e = NULL;
static Elf64_Sym	*symtab = NULL;
static Elf64_Shdr	*sym_shdr = NULL;
static Elf64_Sym	*dynsym_tab = NULL;
static char		*dynsym_strtab = NULL;

static void	init_libelf(int *fd, char const* bin)
{
  if ((*fd = open(bin, O_RDONLY, 0)) == -1)
    exit_error("open() fail");
  if (elf_version(EV_CURRENT) == EV_NONE)
    exit_error("elf_version() fail");
  if ((e = elf_begin(*fd, ELF_C_READ, NULL)) == NULL)
    exit_error("elf_begin() fail");
  if (elf_kind(e) != ELF_K_ELF)
    exit_error("file to execute is not an ELF file");
  fd_bak = *fd;
}

static Elf_Scn	*get_sym_shdr(void)
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

static void		add_symbol(sym_strtab **list, size_t value,
				   char const* name)
{
  sym_strtab		*elem;

  if (value == 0)
    return ;
  if ((elem = malloc(sizeof(*elem))) == NULL)
    return ;
  elem->addr = value;
  if (name)
    strcpy(elem->name, name);
  elem->calls = NULL;
  elem->next = *list;
  elem->is_rel = 0;
  *list = elem;
}

static void		add_symbol_rel(sym_strtab **list, size_t value,
				   char const* name)
{
  sym_strtab		*elem;

  if (value == 0)
    return ;
  if ((elem = malloc(sizeof(*elem))) == NULL)
    return ;
  elem->addr = value;
  if (name)
    strcpy(elem->name, name);
  elem->calls = NULL;
  elem->next = *list;
  elem->is_rel = 1;
  *list = elem;
}

static void	load_symtab(sym_strtab **list, Elf_Scn *sym_scn)
{
  Elf_Data	*data;
  size_t	nb_symbols;

  sym_shdr = elf64_getshdr(sym_scn);
  data = elf_getdata(sym_scn, NULL);

  symtab = (Elf64_Sym*)data->d_buf;
  nb_symbols = sym_shdr->sh_size / sym_shdr->sh_entsize;

  for (size_t i = 0; i < nb_symbols; ++i)
    if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC
	|| ELF64_ST_TYPE(symtab[i].st_info) == STT_NOTYPE)
      add_symbol(list, symtab[i].st_value,
		 elf_strptr(e, sym_shdr->sh_link, symtab[i].st_name));
}

static void	reloc_treatment(Elf_Scn *scn, Elf64_Shdr *shdr, sym_strtab **list)
{
  Elf_Data	*data;
  Elf64_Rela	*relatab;
  size_t	len;

  data = elf_getdata(scn, NULL);
  len = shdr->sh_size / shdr->sh_entsize;
  relatab = (Elf64_Rela*)data->d_buf;

  for (size_t i = 0; i < len; ++i)
    {
      if (ELF64_R_TYPE(relatab[i].r_info) == R_386_JMP_SLOT
	  && ELF64_R_SYM(relatab[i].r_info) != STN_UNDEF)
	{
	  lseek(fd_bak, relatab[i].r_offset - 0x600000, SEEK_SET);
	  long unsigned int toto;
	  read(fd_bak, &toto, 8);
	add_symbol_rel(list, toto,
		   &dynsym_strtab[dynsym_tab[ELF64_R_SYM(relatab[i].r_info)].st_name]);
	}
    }
}

static void	resolve_relocations(sym_strtab **list)
{
  Elf_Scn	*scn;
  Elf64_Shdr	*shdr;

  scn = NULL;
  while ((scn = elf_nextscn(e, scn)))
    {
      if ((shdr = elf64_getshdr(scn)) == NULL)
      	exit_error("gelf_getshdr() fail");
      if (shdr->sh_type == SHT_DYNSYM)
	{
	  Elf_Data	*data;
	  data = elf_getdata(scn, NULL);
	  dynsym_tab = (Elf64_Sym*)data->d_buf;
	}
      if (shdr->sh_type == SHT_STRTAB && shdr->sh_flags == SHF_ALLOC)
	{
	  Elf_Data	*data;
	  data = elf_getdata(scn, NULL);
	  dynsym_strtab = (char*)data->d_buf;
	}
    }
  if (!dynsym_tab)
    return;
  scn = NULL;
  while ((scn = elf_nextscn(e, scn)))
    {
      if ((shdr = elf64_getshdr(scn)) == NULL)
      	exit_error("gelf_getshdr() fail");
      if (shdr->sh_type == SHT_RELA)
	reloc_treatment(scn, shdr, list);
    }
}

sym_strtab	*get_syscall_by_name(sym_strtab *list, char *name)
{
  while (list)
    {
      if (strcmp(list->name, name) == 0)
	return list;
      list = list->next;
    }
  return NULL;
}

sym_strtab	*get_sym_strtab(char const* bin)
{
  Elf_Scn	*sym_scn;
  int		fd;
  sym_strtab	*list = NULL;

  init_libelf(&fd, bin);
  sym_scn = get_sym_shdr();
  load_symtab(&list, sym_scn);
  resolve_relocations(&list);
  elf_end(e);
  close(fd);
  return list;
}
