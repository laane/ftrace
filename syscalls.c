/*
** syscalls.c for  in /home/xaqq/Documents/strace-2015-2014s-erny_a
**
** Made by arnaud kapp
** Login   <kapp_a@epitech.net>
**
** Started on  Wed May  9 14:48:19 2012 arnaud kapp
** Last update Sun Jul  1 21:44:39 2012 arnaud kapp
*/

#include "ftrace.h"
#include <sys/user.h>

char		*syscalls[350];

int set_syscalls()
{
#include	<asm/unistd_64.h>
  return (0);
}

