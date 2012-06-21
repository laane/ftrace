#ifndef FTRACE_H_
# define FTRACE_H_

#include <sys/user.h>

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
  size_t	symtabndx;
  int		nb_called;
  calltree_info	*calls;
  sym_strtab	*next;
};

struct		calltree_info
{
  int		nb_called;
  sym_strtab	*data;
};

/*
** Prototypes
*/
void		exit_error(const char*);

void		exec_child(char*, char **);
void		exec_parent(int, sym_strtab const*, char);
void		print_args(const char*, char **, struct user, int);
void		int_enum(int, const char*, int);
sym_strtab	*get_sym_strtab(char const*);

#endif /* !FTRACE_H_ */
