
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

  if (ptrace(PTRACE_GETREGS, pid, NULL, &infos) == -1)
    {      fprintf(stderr, "getregs fail\n");      return 1;    }
  word = ptrace(PTRACE_PEEKTEXT, pid, infos.regs.rip);
  if ((word & 0xFF) != 0xe8)
    return 0;

  offset = big_to_little_endian((int)(word >> 8));

  call_addr = infos.regs.rip + (long)offset;

  /* fprintf(stdout, "\t\toffset = %8.8x\trip = %#lx\taddr = (rip + offset) = %#lx\n", */
  /* 	  offset, infos.regs.rip, call_addr); */
  return 0;
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
