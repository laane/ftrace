
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <sys/ptrace.h>
#include "ftrace.h"

static int	gl_pid;

static void	handler(int __attribute__((unused))sig)
{
  kill(gl_pid, SIGSTOP);
  wait4(gl_pid, NULL, WUNTRACED, NULL);
  ptrace(PTRACE_DETACH, gl_pid, NULL, NULL);
  kill(gl_pid, SIGCONT);
  exit(1);
}

static char **	get_syscalls(void)
{
  char		**ret;
  size_t	i, j, len, size;
  FILE*		fd;

  if ((fd = fopen("syscall_db", "r")) == NULL)
    return NULL;
  size = 50;
  ret = malloc(size * sizeof(*ret));
  i = 0;
  ret[i] = NULL;
  while (getline(&ret[i], &len, fd) != -1)
    {
      for (j = 0; ret[i][j] && ret[i][j] != '\n'; ++j);
      ret[i][j] = 0;
      if (++i == size)
	{
	  size += 50;
	  if ((ret = realloc(ret, size * sizeof(*ret))) == NULL)
	    perror("realloc fail");
	}
      ret[i] = NULL;
    }
  return ret;
}

static int	usage(void)
{
  fprintf(stderr, "Usage: ./strace [-p pid] | progname\n");
  return 1;
}

static void	free_strtab(char **tab)
{
  size_t	i;

  for (i = 0; tab[i]; ++i)
    free(tab[i]);
}

static char	*getbinary(char *arg)
{
  char		*path = getenv("PATH");
  char		*p;
  char		*bin;

  if (0 == access(arg, X_OK))
    return arg;
  if (!path)
    {
      if (0 != access(arg, X_OK))
	return NULL;
      return arg;
    }
  while ((p = strtok(path, ":")))
    {
      bin = strdup(p);
      bin = realloc(bin, strlen(bin) + strlen(arg) + 10);
      bin = strcat(bin, "/");
      bin = strcat(bin, arg);
      if (0 == access(bin, X_OK))
	return bin;
      free(bin);
      path = NULL;
      p = NULL;
    }
  return NULL;
}

static int	launch_program(char **av)
{
  char		**syscall_strtab;
  char		*bin;
  sym_strtab	*symtab;

  if (!strcmp(av[1], "-p"))
    return usage();
  if (NULL == (bin = getbinary(av[1])))
    {
      fprintf(stderr, "File %s doesnt exist or has not execute permissions\n",
  	      av[1]);
      return 1;
    }
  symtab = get_sym_strtab(bin);
  return 0;
  /* syscall_strtab = get_syscalls(); */
  /* if (syscall_strtab == NULL) */
  /*   exit_error("file syscall_db unreachable"); */
  if ((gl_pid = fork()) == -1)
    exit_error("fork fail");
  if (!gl_pid) /* child */
    exec_child(bin, ++av);
  else /* parent */
    exec_parent(gl_pid, syscall_strtab, 1);
  free_strtab(syscall_strtab);
  return 0;
}

static int	trace_pid(char **av)
{
  char		**syscall_strtab;

  if (strcmp(av[1], "-p"))
    return usage();
  gl_pid = atoi(av[2]);
  if (gl_pid == 0 || gl_pid >= USHRT_MAX)
    {
      fprintf(stderr, "Abort: pid incorrect\n");
      return 1;
    }
  syscall_strtab = get_syscalls();
  if (syscall_strtab == NULL)
    exit_error("file syscall_db unreachable");
  exec_parent(gl_pid, syscall_strtab, 0);
  return 0;
}

int		main(int ac, char **av)
{
  if (signal(SIGINT, &handler) == SIG_ERR)
    {
      fprintf(stderr, "Abort: signal failed\n");
      return 1;
    }
  if (ac == 3 && !strcmp(av[1], "-p"))
    trace_pid(av);
  else if (ac != 1)
    launch_program(av);
  else
    usage();
  return 0;
}
