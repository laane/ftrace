
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdio.h>
#include "ftrace.h"

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

static void	trace_process(int pid, sym_strtab const* symlist)
{
  int		status;

  while (1)
    {
      wait4(pid, &status, WUNTRACED, NULL);
      if (get_stopsig(pid) || !status)
      	break;
      /*
      ** >.> Do something <.<
      */
      ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
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
