CC ?= gcc
CFLAGS += -Os -fPIC -shared

SRC = injected-code.c
OUT = injected-code.so

all: injected-code

injected-code:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

.PHONY: clean
clean:
	${RM} ${OUT}
