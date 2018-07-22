CC ?= gcc
CFLAGS += -Wall -Wextra -std=c99 -pedantic
LDFLAGS =
LDLIBS =

SRC = main.c a.c b.c
OBJ = ${SRC:.c=.o}

all: main

main: ${OBJ}

check: CFLAGS += -g3 -DTEST
check: main

.PHONY: clean check
clean:
	${RM} ${OBJ}
	${RM} main
