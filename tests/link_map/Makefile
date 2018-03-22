CC ?= gcc
CFLAGS += -Wall -Wextra -Werror -std=c99 -pedantic
LDFLAGS =
LDLIBS =

SRC = link_map.c
OBJ = ${SRC:.c=.o}

all: link_map

link_map: ${OBJ}

check: CFLAGS += -g3 -DTEST
check: link_map

.PHONY: clean check
clean:
	${RM} ${OBJ}
	${RM} link_map
