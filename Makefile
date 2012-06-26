
NAME=		ftrace

SRC=		main.c \
		error.c \
		child.c \
		parent.c \
		symbolnames.c

OBJ=		$(SRC:.c=.o)

CFLAGS+=	-W -Wall -ansi -pedantic $(DEFINES) -std=c99 -g

DEFINES=	-D_BSD_SOURCE -D_XOPEN_SOURCE -D_GNU_SOURCE

LIB=		-lelf

$(NAME):	$(OBJ)
		gcc -o $(NAME) $(OBJ) $(LIB)

all:		$(NAME)

clean:
		rm -rf $(OBJ)

fclean:		clean
		rm -rf $(NAME)

re:		fclean all