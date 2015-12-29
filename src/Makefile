
CC=gcc
CFLAGS= -Wall -g
LDFLAGS= -lc

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
INC=$(wildcard *.h)

TARGETS := gen-key encrypt decrypt

all: $(TARGETS)

%.o: %.c $(INC)
	$(CC) $(CFLAGS) $< -c -o $@

.PHONY: clean format

format:
	indent -linux $(SRC)

clean:
	rm -rf $(OBJ) $(TARGETS) *~

