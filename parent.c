
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
	  offset &= 0xFFFFFF;
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

      rmb = (word & 0xFF00) >> 8;
      if (rmb >= 0xD0 && rmb <= 0xD7)
	{
	  if (!rexb && rmb == 0xD0)
	    printf("Call to %#x\n", infos.regs.rax);
	  if (!rexb && rmb == 0xD1)
	    printf("Call to %#x\n", infos.regs.rcx);
	  if (!rexb && rmb == 0xD2)
	    printf("Call to %#x\n", infos.regs.rdx);
	  if (!rexb && rmb == 0xD3)
	    printf("Call to %#x\n", infos.regs.rbx);
	  if (!rexb && rmb == 0xD4)
	    printf("Call to %#x\n", infos.regs.rsp);
	  if (!rexb && rmb == 0xD5)
	    printf("Call to %#x\n", infos.regs.rbp);
	  if (!rexb && rmb == 0xD6)
	    printf("Call to %#x\n", infos.regs.rsi);	  
	  if (!rexb && rmb == 0xD7)
	    printf("Call to %#x\n", infos.regs.rdi);
	}
      printf("Call FF/2 : %#x\n", word);
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
