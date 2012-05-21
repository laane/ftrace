
#include <unistd.h>
#include <sys/ptrace.h>
#include "ftrace.h"

void		exec_child(char* filename, char **argv)
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execvp(filename, argv);
}
