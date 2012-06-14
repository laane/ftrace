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
struct		sym_strtab
{
  unsigned long	addr;
  char		name[MAX_NAME_LEN];
  sym_strtab	*next;
};


typedef struct	calltree_info	calltree_info;
typedef struct	calltree	calltree;

struct		calltree_info
{
  int		nb_called;
  calltree	*data;
};


struct		calltree
{
  int		nb_called;
  int		total_called;
  char		*name;
  calltree_info	*children;
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
