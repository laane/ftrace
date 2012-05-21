
#include <stdlib.h>
#include <stdio.h>
#include "ftrace.h"

void		exit_error(const char* str)
{
  fprintf(stderr, "Fatal error: %s\n", str);
  exit(1);
}
