
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

static int	usage(void)
{
    fprintf(stderr, "Usage: ./strace [-p pid] | progname\n");
    return 1;
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

static int	launch_program(char **av, sym_strtab* symlist)
{
    char		*bin;

    if (!strcmp(av[1], "-p"))
        return usage();
    if (NULL == (bin = getbinary(av[1])))
    {
        fprintf(stderr, "File %s doesnt exist or has not execute permissions\n",
                av[1]);
        return 1;
    }

    //  while (symlist)
    //    {
    //      printf("name = %s\taddr = 0x%08x\n", symlist->name, (unsigned int)symlist->addr);
    //      symlist = symlist->next;
    //    }

    if ((gl_pid = fork()) == -1)
        exit_error("fork fail");
    if (!gl_pid) /* child */
        exec_child(bin, ++av);
    else /* parent */
        exec_parent(gl_pid, syscall_strtab, 1);
    return 0;
}

static int	trace_pid(char **av, sym_strtab* symlist)
{
    if (strcmp(av[1], "-p"))
        return usage();
    gl_pid = atoi(av[2]);
    if (gl_pid == 0 || gl_pid >= USHRT_MAX)
    {
        fprintf(stderr, "Abort: pid incorrect\n");
        return 1;
    }
    if (syscall_strtab == NULL)
        exit_error("file syscall_db unreachable");
    exec_parent(gl_pid, syscall_strtab, 0);
    return 0;
}

int		main(int ac, char **av)
{
    sym_strtab	*symlist = get_sym_strtab(bin);

    if (signal(SIGINT, &handler) == SIG_ERR)
    {
        fprintf(stderr, "Abort: signal failed\n");
        return 1;
    }
    if (ac == 3 && !strcmp(av[1], "-p"))
        trace_pid(av, symlist);
    else if (ac != 1)
        launch_program(av, symlist);
    else
        usage();
    return 0;
}
