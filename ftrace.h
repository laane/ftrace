#ifndef FTRACE_H_
# define FTRACE_H_

#include <bits/types.h>
#include <sys/user.h>

extern	char	*syscalls[350];
#define __SYSCALL(a, b) syscalls[a] = #b + 4;

/*
** Defines
*/
#ifndef NULL
# define NULL	(void*)0
#endif

/*
** Structures
*/

# define MAX_NAME_LEN	512

typedef struct sym_strtab	sym_strtab;
typedef struct	calltree_info	calltree_info;

struct		sym_strtab
{
  unsigned long	addr;
  char		name[MAX_NAME_LEN];
  int		nb_called;
  unsigned long	retaddr;
  calltree_info	*calls;
  sym_strtab	*next;
};

struct		calltree_info
{
  int		nb_called;
  sym_strtab	*data;
  calltree_info	*next;
};

typedef struct	s_rex
{
  char w,
    r,
    x,
    b;
}		t_rex;

/*
** Prototypes
*/
void	trace_process(int, sym_strtab *, sym_strtab *);

void		exit_error(const char*);

void		exec_child(char*, char **);
void		exec_parent(int, sym_strtab*, char);
void		print_args(const char*, char **, struct user, int);
void		int_enum(int, const char*, int);
sym_strtab	*get_sym_strtab(char const*);
sym_strtab	*get_syscall_by_name(sym_strtab *list, char *name);

#endif /* !FTRACE_H_ */
