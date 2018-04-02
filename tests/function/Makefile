CC ?= gcc
CFLAGS += -O0 -Wall -Wextra -Werror -std=c99 -pedantic
LDFLAGS =
LDLIBS =

SRC = function.c
OBJ = ${SRC:.c=.o}

all: function

function: ${OBJ}

check: CFLAGS += -g3 -DTEST
check: function

.PHONY: clean check
clean:
	${RM} ${OBJ}
	${RM} function
