#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "ftrace.h"

static int	get_stopsig(int pid)
{
  siginfo_t	sig;

  sig.si_signo = 0;
  if (-1 == ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig))
    return fprintf(stderr, "Process died\n");
  switch (sig.si_signo) {
  case 0:
  case 5:
  case 17:
  case 18:
  case 19:
  case 20:
  case 25:
  case 28:
    return 0;
  }
  fprintf(stderr, "Killed by signal %d\n",
	  sig.si_signo); /* , strerror(sig.si_errno)); */
  return 1;
}

static unsigned long	get_sib(unsigned char sib, struct user infos, t_rex rex,
				char mod, int pid)
{
  char			scale, index, base;
  unsigned long		result = 0;

  scale = sib & 0xC0;
  index = sib & 0x38;
  base = sib & 0x07;
  switch (index)
    {
    case 0:
	if (rex.x)
	  result += infos.regs.r8;
	else
	  result += infos.regs.rax;
	printf("Adding Rax\n");
      break;
    case 1:
      if (rex.x)
	result += infos.regs.r9;
      else
	result += infos.regs.rcx;
      break;
    case 2:
      if (rex.x)
	result += infos.regs.r10;
      else
	result += infos.regs.rdx;
      break;
    case 3:
      if (rex.x)
	result += infos.regs.r11;
      else
	result += infos.regs.rbx;
      break;
    case 4:
      if (rex.x)
	result += infos.regs.r12;
      break;
    case 5:
      if (rex.x)
	result += infos.regs.r13;
      else
	result += infos.regs.rbp;
      break;
    case 6:
      if (rex.x)
	result += infos.regs.r14;
      else
	result += infos.regs.rsi;
      break;
    case 7:
      if (rex.x)
	result += infos.regs.r15;
      else
	result += infos.regs.rdi;
      break;
    }
  switch (scale)
    {
    case 0:
      break;
    case 1:
      result *= 2;
      break;
    case 2:
      result *= 4;
      break;
    case 3:
      result *= 8;
      break;
    }
  switch (base)
    {
    case 0:
      if (rex.b)
	result += infos.regs.r8;
      else
	result += infos.regs.rax;
      break;
    case 1:
      if (rex.b)
	result += infos.regs.r9;
      else
	result += infos.regs.rcx;
      break;
    case 2:
      if (rex.b)
	result += infos.regs.r10;
      else
	result += infos.regs.rdx;
      break;
    case 3:
      if (rex.b)
	result += infos.regs.r11;
      else
	result += infos.regs.rbx;
      break;
    case 4:
      if (rex.b)
	result += infos.regs.r12;
      else
	result += infos.regs.rsp;
      break;
    case 5:
      if (rex.b && mod)
	result += infos.regs.r13;
      else if (mod)
	result += infos.regs.rbp;
      else
	{
	  result += ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 3) & 0xFFFFFFFF;
	  printf("Adding %#lx\n", ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 3) & 0xFFFFFFFF);
	}
      break;
    case 6:
      if (rex.b)
	result += infos.regs.r14;
      else
	result += infos.regs.rsi;
      break;
    case 7:
      if (rex.b)
	result += infos.regs.r15;
      else
	result += infos.regs.rdi;
      break;
    }
  return (result);
}

static void	addcall(sym_strtab * symlist, sym_strtab *node)
{
  calltree_info	*tmp = node->calls;
  
  while (tmp)
    {
      if (tmp->data == symlist)
	{
	  tmp->nb_called++;
	  symlist->nb_called++;
	  return ;
	}
      tmp = tmp->next;
    }
  tmp = malloc(sizeof(calltree_info));
  tmp->nb_called = 1;
  tmp->data = symlist;
  tmp->next = node->calls;
  node->calls = tmp;
  symlist->nb_called++;
}

static int	call_relative(unsigned long word, int pid, struct user infos,
			      char rexw, sym_strtab *symlist,
			      sym_strtab *node, sym_strtab *symlist_bak)
{
  int		offset;
  unsigned long	call_addr;

  offset = (int)((word >> 8));
  if (rexw)
    {
      offset = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 1);
      call_addr = infos.regs.rip + offset + 9;
    }
  else
    {
      /* int val; */
      /* val = offset & 0xFFFFFF; */
      call_addr = infos.regs.rip + offset + 5;
    }

  while (symlist)
    {
      if (symlist->addr == call_addr)
	{
	  printf("Call to %s\n", symlist->name);
	  addcall(symlist, node);
	  ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
	  trace_process(pid, symlist_bak, symlist);
	  return (0);
	}
      symlist = symlist->next;
    }
  return 0;
}

static int	ret(sym_strtab *node)
{
  if (strcmp("<start>", node->name))
    {
      printf("Returning\n");
      return (-1);
    }
  return (0);
}

static int	call_rm(unsigned long word, int pid, struct user infos,
			t_rex rex, sym_strtab *symlist,
			sym_strtab *node, sym_strtab *symlist_bak)
{
  unsigned char	rmb;
  unsigned long	addr;

  rmb = (word & 0xFF00) >> 8;
  if (rmb >= 0xD0 && rmb <= 0xD7)
    {
      if (!rex.b && rmb == 0xD0)
	addr = infos.regs.rax;
      else if (!rex.b && rmb == 0xD1)
	addr = infos.regs.rcx;
      else if (!rex.b && rmb == 0xD2)
	addr = infos.regs.rdx;
      else if (!rex.b && rmb == 0xD3)
	addr = infos.regs.rbx;
      else if (!rex.b && rmb == 0xD4)
	addr = infos.regs.rsp;
      else if (!rex.b && rmb == 0xD5)
	addr = infos.regs.rbp;
      else if (!rex.b && rmb == 0xD6)
	addr = infos.regs.rsi;
      else if (!rex.b && rmb == 0xD7)
	addr = infos.regs.rdi;
      else if (rex.b && rmb == 0xD0)
	addr = infos.regs.r8;
      else if (rex.b && rmb == 0xD1)
	addr = infos.regs.r9;
      else if (rex.b && rmb == 0xD2)
	addr = infos.regs.r10;
      else if (rex.b && rmb == 0xD3)
	addr = infos.regs.r11;
      else if (rex.b && rmb == 0xD4)
	addr = infos.regs.r12;
      else if (rex.b && rmb == 0xD5)
	addr = infos.regs.r13;
      else if (rex.b && rmb == 0xD6)
	addr = infos.regs.r14;
      else if (rex.b && rmb == 0xD7)
	addr = infos.regs.r15;
      while (symlist)
	{
	  if (symlist->addr == addr)
	    {
	      printf("(ff/2 mod3)Call to %s\n", symlist->name);
	      addcall(symlist, node);
	      ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
	      trace_process(pid, symlist_bak, node);
	      return (0);
	    }
	  symlist = symlist->next;
	}
    }
  else if (rmb >= 0x10 && rmb <= 0x17)
    {
      if (!rex.b && rmb == 0x10)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax);
      else if (!rex.b && rmb == 0x11)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx);
      else if (!rex.b && rmb == 0x12)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx);
      else if (!rex.b && rmb == 0x13)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx);
      else if (rmb == 0x14)
	addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rex, 0, pid));
      else if (rmb == 0x15)
	{
	  unsigned long addb = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 2) & 0xFFFFFFFF;
	  addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 6 + addb);
	}
      else if (!rex.b && rmb == 0x16)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi);
      else if (!rex.b && rmb == 0x17)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi);
      else if (rex.b && rmb == 0x10)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r8);
      else if (rex.b && rmb == 0x11)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r9);
      else if (rex.b && rmb == 0x12)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r10);
      else if (rex.b && rmb == 0x13)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r11);
      else if (rex.b && rmb == 0x16)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r14);
      else if (rex.b && rmb == 0x17)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r15);
      printf("(ff/2 mod0)Call to %#lx\n", addr);
      while (symlist)
	{
	  if (symlist->addr == addr)
	    {
	      printf("(ff/2 mod0)Call to %s\n", symlist->name);
	      addcall(symlist, node);
	      ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
	      trace_process(pid, symlist_bak, node);
	      return (0);
	    }
	  symlist = symlist->next;
	}
      printf("call not found\n");
    }
  else if (rmb >= 0x50 && rmb <= 0x57)
    {
      char	addb;
      addb = (word & 0xFF0000) >> 16;
      if (!rex.b && rmb == 0x50)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax + addb);
      else if (!rex.b && rmb == 0x51)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx + addb);
      else if (!rex.b && rmb == 0x52)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx + addb);
      else if (!rex.b && rmb == 0x53)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx + addb);
      else if (rmb == 0x54)
	addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rex, 1, pid) + addb);
      else if (!rex.b && rmb == 0x55)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbp + addb);
      else if (!rex.b && rmb == 0x56)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi + addb);
      else if (!rex.b && rmb == 0x57)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi + addb);
      else if (rex.b && rmb == 0x50)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r8 + addb);
      else if (rex.b && rmb == 0x51)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r9 + addb);
      else if (rex.b && rmb == 0x52)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r10 + addb);
      else if (rex.b && rmb == 0x53)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r11 + addb);
      else if (rex.b && rmb == 0x55)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r13 + addb);
      else if (rex.b && rmb == 0x56)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r14 + addb);
      else if (rex.b && rmb == 0x57)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r15 + addb);
      while (symlist)
	{
	  if (symlist->addr == addr)
	    {
	      printf("(ff/2 mod1)Call to %s\n", symlist->name);
	      addcall(symlist, node);
	      ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
	      trace_process(pid, symlist_bak, node);
	      return (0);
	    }
	  symlist = symlist->next;
	}
    }
  else if (rmb >= 0x90 && rmb <= 0x97)
    {
      unsigned long addb = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 2) & 0xFFFFFFFF;
      if (!rex.b && rmb == 0x90)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax + addb);
      else if (!rex.b && rmb == 0x91)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx + addb);
      else if (!rex.b && rmb == 0x92)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx + addb);
      else if (!rex.b && rmb == 0x93)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx + addb);
      else if (rmb == 0x94)
	addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rex, 2, pid) + addb);
      else if (!rex.b && rmb == 0x95)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbp + addb);
      else if (!rex.b && rmb == 0x96)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi + addb);
      else if (!rex.b && rmb == 0x97)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi + addb);
      else if (rex.b && rmb == 0x90)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r8 + addb);
      else if (rex.b && rmb == 0x91)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r9 + addb);
      else if (rex.b && rmb == 0x92)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r10 + addb);
      else if (rex.b && rmb == 0x93)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r11 + addb);
      else if (rex.b && rmb == 0x95)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r13 + addb);
      else if (rex.b && rmb == 0x96)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r14 + addb);
      else if (rex.b && rmb == 0x97)
	addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.r15 + addb);
      while (symlist)
	{
	  if (symlist->addr == addr)
	    {
	      printf("(ff/2 mod2)Call to %s\n", symlist->name);
	      addcall(symlist, node);
	      ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);		  
	      trace_process(pid, symlist_bak, node);
	      return (0);
	    }
	  symlist = symlist->next;
	}
    }
  return (0);
}

static int	get_call(int pid, sym_strtab * symlist, sym_strtab *node)
{
  struct user	infos;
  unsigned long	word;
  t_rex		rex = {0, 0, 0, 0};

  if (ptrace(PTRACE_GETREGS, pid, NULL, &infos) == -1)
    {      fprintf(stderr, "getregs fail\n");      return 1;    }
  word = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip);
  if ((word & 0xF0) == 0x40)
    {
      rex.w = word & 0x8;
      rex.r = word & 0x4;
      rex.x = word & 0x2;
      rex.b = word & 0x1;
      word = ptrace(PTRACE_PEEKTEXT, pid, ++infos.regs.rip);
    }
  // RELATIVE CALL
  if ((word & 0xFF) == 0xe8)
    return call_relative(word, pid, infos, rex.w, symlist, node, symlist);
  // INDIRECT CALL (r/m)
  else if ((word & 0xFF) == 0xFF && (word & 0x3800) == 0x1000)
    return call_rm(word, pid, infos, rex, symlist, node, symlist);
  // RET
  else if ((word & 0xFF) == 0xC2 || (word & 0xFF) == 0xC3 ||
	   (word & 0xFF) == 0xCA || (word & 0xFF) == 0xCB)
    return ret(node);

  return (0);
}

void	trace_process(int pid, sym_strtab * symlist, sym_strtab *node)
{
  int		status;

  while (1)
    {
      if (wait4(pid, &status, WUNTRACED, NULL) == -1)
	{ fprintf(stderr, "wait4 fail\n"); break; }
      if (get_stopsig(pid) || !status)
      	break;
      if (get_call(pid, symlist, node))
	{
	  break;
	}
      if (ptrace(PTRACE_SINGLESTEP, pid, NULL, 0) == -1)
	break;
    }
}

void		print_node(sym_strtab *node, int lvl)
{
  for (int i = 0; i < lvl; ++i)
    printf("   ");
  printf("Node %s, called %d times, called : \n", node->name, node->nb_called);
  for (int i = 0; i < lvl; ++i)
    printf("   ");
  printf("<\n");
  calltree_info *ptr = node->calls;
  while (ptr)
    {
      for (int i = 0; i < lvl; ++i)
	printf("   ");
      printf("%d times : \n", ptr->nb_called);
      print_node(ptr->data, lvl+1);
      ptr = ptr->next;
    }
  for (int i = 0; i < lvl; ++i)
    printf("   ");
  printf(">\n");
}

void		exec_parent(int pid, sym_strtab * symlist, char flag)
{
  sym_strtab	*parent = malloc(sizeof(sym_strtab));

  strcpy(parent->name, "<start>");
  parent->nb_called = 1;
  parent->calls = NULL;
  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
    {
      if (flag)
	kill(pid, SIGKILL);
      exit_error("Cannot attach parent process");
    }
  trace_process(pid, symlist, parent);
  print_node(parent, 0);
}
