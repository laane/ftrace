#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdio.h>
#include "ftrace.h"

static int	big_to_little_endian(int val)
{
  int		ret = 0;
  unsigned char	*oct_val = (unsigned char*)&val;
  unsigned char	*oct_ret = (unsigned char*)&ret;

  oct_ret[0] = oct_val[3];
  oct_ret[1] = oct_val[2];
  oct_ret[2] = oct_val[1];
  oct_ret[3] = oct_val[0];

  return ret;
}

static int	get_stopsig(int pid)
{
  siginfo_t	sig;

  sig.si_signo = 0;
  if (-1 == ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig))
    return fprintf(stderr, "getsiginfo fail\n");
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

static unsigned long	get_sib(unsigned char sib, struct user infos, char rexb, char rexx, char mod, int pid)
{
  char			scale, index, base;
  unsigned long		result = 0;

  scale = sib & 0xC0;
  index = sib & 0x38;
  base = sib & 0x07;
  switch (index)
    {
    case 0:
	if (rexx)
	  result += infos.regs.r8;
	else
	  result += infos.regs.rax;
	printf("Adding Rax\n");
      break;
    case 1:
      if (rexx)
	result += infos.regs.r9;
      else
	result += infos.regs.rcx;
      break;
    case 2:
      if (rexx)
	result += infos.regs.r10;
      else
	result += infos.regs.rdx;
      break;
    case 3:
      if (rexx)
	result += infos.regs.r11;
      else
	result += infos.regs.rbx;
      break;
    case 4:
      if (rexx)
	result += infos.regs.r12;
      break;
    case 5:
      if (rexx)
	result += infos.regs.r13;
      else
	result += infos.regs.rbp;
      break;
    case 6:
      if (rexx)
	result += infos.regs.r14;
      else
	result += infos.regs.rsi;
      break;
    case 7:
      if (rexx)
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
      printf("*8\n");
      break;
    }
  switch (base)
    {
    case 0:
      if (rexb)
	result += infos.regs.r8;
      else
	result += infos.regs.rax;
      break;
    case 1:
      if (rexb)
	result += infos.regs.r9;
      else
	result += infos.regs.rcx;
      break;
    case 2:
      if (rexb)
	result += infos.regs.r10;
      else
	result += infos.regs.rdx;
      break;
    case 3:
      if (rexb)
	result += infos.regs.r11;
      else
	result += infos.regs.rbx;
      break;
    case 4:
      if (rexb)
	result += infos.regs.r12;
      else
	result += infos.regs.rsp;
      break;
    case 5:
      if (rexb && mod)
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
      if (rexb)
	result += infos.regs.r14;
      else
	result += infos.regs.rsi;
      break;
    case 7:
      if (rexb)
	result += infos.regs.r15;
      else
	result += infos.regs.rdi;
      break;
    }
  return (result);
}

static int	get_call(int pid, sym_strtab const* symlist)
{
  struct user	infos;
  unsigned long	word, call_addr;
  int		offset;
  char		rexw = 0;
  char		rexr = 0;
  char		rexx = 0;
  char		rexb = 0;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &infos) == -1)
    {      fprintf(stderr, "getregs fail\n");      return 1;    }
  word = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip);
  if ((word & 0xF0) == 0x40)
    {
      rexw = word & 0x8;
      rexr = word & 0x4;
      rexx = word & 0x2;
      rexb = word & 0x1;
      word = ptrace(PTRACE_PEEKTEXT, pid, ++infos.regs.rip);
    }
  if ((word & 0xFF) == 0xe8)
    {
      offset = (int)((word >> 8));
      if (rexw)
	{
	  offset = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 1);
	  call_addr = infos.regs.rip + offset + 9;
	}
      else
	{
	  int val;
	  val = offset & 0xFFFFFF;
	  call_addr = infos.regs.rip + offset + 5;
	}
      while (symlist)
	{
	  if (symlist->addr == call_addr)
	    {
	      printf("Call to %s\n", symlist->name);
	      return (0);
	    }
	  symlist = symlist->next;
	}
    }
  else if ((word & 0xFF) == 0xFF && (word & 0x3800) == 0x1800)
    {
      printf("Call FF/3 : %#x\n", word);
    }
  else if ((word & 0xFF) == 0xFF && (word & 0x3800) == 0x1000)
    {
      unsigned char	rmb;
      unsigned long	addr;

      rmb = (word & 0xFF00) >> 8;
      if (rmb >= 0xD0 && rmb <= 0xD7)
	{
	  if (!rexb && rmb == 0xD0)
	    addr = infos.regs.rax;
	  if (!rexb && rmb == 0xD1)
	    addr = infos.regs.rcx;
	  if (!rexb && rmb == 0xD2)
	    addr = infos.regs.rdx;
	  if (!rexb && rmb == 0xD3)
	    addr = infos.regs.rbx;
	  if (!rexb && rmb == 0xD4)
	    addr = infos.regs.rsp;
	  if (!rexb && rmb == 0xD5)
	    addr = infos.regs.rbp;
	  if (!rexb && rmb == 0xD6)
	    addr = infos.regs.rsi;
	  if (!rexb && rmb == 0xD7)
	    addr = infos.regs.rdi;
	  while (symlist)
	    {
	      if (symlist->addr == addr)
		{
		  printf("(ff/2 mod3)Call to %s\n", symlist->name);
		  return (0);
		}
	      symlist = symlist->next;
	    }
	}
      if (rmb >= 0x10 && rmb <= 0x17)
	{
	  if (!rexb && rmb == 0x10)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax);
	  if (!rexb && rmb == 0x11)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx);
	  if (!rexb && rmb == 0x12)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx);
	  if (!rexb && rmb == 0x13)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx);
	  if (!rexb && rmb == 0x14)
	      addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rexb, rexx, 0, pid));
	  if (!rexb && rmb == 0x15)
	    {
	      unsigned long addb = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 2) & 0xFFFFFFFF;
	      addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 6 + addb);
	    }
	  if (!rexb && rmb == 0x16)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi);
	  if (!rexb && rmb == 0x17)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi);
	  printf("(ff/2 mod0)Call to %#lx\n", addr);
	  while (symlist)
	    {
	      if (symlist->addr == addr)
		{
		  printf("(ff/2 mod0)Call to %s\n", symlist->name);
		  return (0);
		}
	      symlist = symlist->next;
	    }
	}
      if (rmb >= 0x50 && rmb <= 0x57)
	{
	  char	addb;
	  addb = (word & 0xFF0000) >> 16;
	  if (!rexb && rmb == 0x50)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax + addb);
	  if (!rexb && rmb == 0x51)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx + addb);
	  if (!rexb && rmb == 0x52)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx + addb);
	  if (!rexb && rmb == 0x53)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx + addb);
	  if (!rexb && rmb == 0x54)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rexb, rexx, 1, pid) + addb);
	  if (!rexb && rmb == 0x55)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbp + addb);
	  if (!rexb && rmb == 0x56)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi + addb);
	  if (!rexb && rmb == 0x57)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi + addb);
	  while (symlist)
	    {
	      if (symlist->addr == addr)
		{
		  printf("(ff/2 mod1)Call to %s\n", symlist->name);
		  return (0);
		}
	      symlist = symlist->next;
	    }
	}
      if (rmb >= 0x90 && rmb <= 0x97)
	{
	  unsigned long addb = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip + 2) & 0xFFFFFFFF;
	  if (!rexb && rmb == 0x90)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rax + addb);
	  if (!rexb && rmb == 0x91)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rcx + addb);
	  if (!rexb && rmb == 0x92)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdx + addb);
	  if (!rexb && rmb == 0x93)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbx + addb);
	  if (!rexb && rmb == 0x94)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, get_sib((word & 0xFF0000) >> 16, infos, rexb, rexx, 2, pid) + addb);
	  if (!rexb && rmb == 0x95)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rbp + addb);
	  if (!rexb && rmb == 0x96)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rsi + addb);
	  if (!rexb && rmb == 0x97)
	    addr = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rdi + addb);
	  while (symlist)
	    {
	      if (symlist->addr == addr)
		{
		  printf("(ff/2 mod2)Call to %s\n", symlist->name);
		  return (0);
		}
	      symlist = symlist->next;
	    }
	}
    }
  return (0);
}

static void	trace_process(int pid, sym_strtab const* symlist)
{
  int		status;

  while (1)
    {
      if (wait4(pid, &status, WUNTRACED, NULL) == -1)
	{ fprintf(stderr, "wait4 fail\n"); break; }
      if (get_stopsig(pid) || !status)
      	break;
      if (get_call(pid, symlist))
      	break;
      if (ptrace(PTRACE_SINGLESTEP, pid, NULL, 0) == -1)
	break;
    }
}

void		exec_parent(int pid, sym_strtab const* symlist, char flag)
{
  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
    {
      if (flag)
	kill(pid, SIGKILL);
      exit_error("Cannot attach parent process");
    }
  trace_process(pid, symlist);
}
