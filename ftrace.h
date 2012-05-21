#ifndef FTRACE_H_
# define FTRACE_H_

#include <sys/user.h>

/*
** Defines
*/
#ifndef NULL
# define NULL	(void*)0
#endif

/* # define	MAXPARAMS	7 */

/* struct	syscalls */
/* { */
/*   char	*name; */
/*   char	*rtype; */
/*   char	*p[MAXPARAMS];   /\* les parametres *\/ */
/* }; */

/*
** Prototypes
*/
void		exit_error(const char*);

void		exec_child(char*, char **);
void		exec_parent(int, char **, char);
void		print_args(const char*, char **, struct user, int);
void		int_enum(int, const char*, int);

#endif /* !FTRACE_H_ */
