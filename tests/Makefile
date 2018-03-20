CC ?= gcc
CFLAGS += -Wall -Wextra -Werror -std=c99 -pedantic
LDFLAGS =
LDLIBS =

SRC = test.c
OBJ = ${SRC:.c=.o}

all: test

test: ${OBJ}

check: CFLAGS += -g3 -DTEST
check: test

.PHONY: clean check
clean:
	${RM} ${OBJ}
	${RM} test
