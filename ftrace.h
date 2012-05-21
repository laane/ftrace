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

/* # define	MAXPARAMS	7 */

/* struct	syscalls */
/* { */
/*   char	*name; */
/*   char	*rtype; */
/*   char	*p[MAXPARAMS];   /\* les parametres *\/ */
/* }; */

# define MAX_NAME_LEN	512

typedef struct sym_strtab	sym_strtab;
struct		sym_strtab
{
  unsigned long	addr;
  char		name[MAX_NAME_LEN];
  sym_strtab	*next;
};

/*
** Prototypes
*/
void		exit_error(const char*);

void		exec_child(char*, char **);
void		exec_parent(int, char **, char);
void		print_args(const char*, char **, struct user, int);
void		int_enum(int, const char*, int);
sym_strtab	*get_sym_strtab(char const*);

#endif /* !FTRACE_H_ */
