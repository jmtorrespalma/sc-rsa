#   Copyright (C) 2015 Juan Manuel Torres Palma <j.m.torrespalma@gmail.com>
#   This file is part of the SC-RSA program.
#
#   SC-RSA is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   SC-RSA is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SC-RSA.  If not, see <http://www.gnu.org/licenses/>.

# Makefile to build rc-rsa

CC := gcc
CFLAGS := -Wall -g
LDFLAGS := -lm

SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
INC := $(wildcard *.h)

LIBFILE := keyutils.o

TARGETS := gen-key encrypt decrypt

all: $(LIBFILE) $(TARGETS)

#TODO: Unify all these three options.
gen-key: gen-key.c $(LIBFILE)
	$(CC) $(CFLAGS) -I. $^ -o $@

encrypt: encrypt.c $(LIBFILE)
	$(CC) $(CFLAGS) $(LDFLAGS) -I. $^ -o $@

decrypt: decrypt.c $(LIBFILE)
	$(CC) $(CFLAGS) $(LDFLAGS) -I. $^ -o $@

$(LIBFILE): keyutils.c keyutils.h
	$(CC) $(CFLAGS) -I. $< -c -o $@



.PHONY: clean format

format:
	indent -linux $(SRC)

clean:
	rm -rf $(OBJ) $(TARGETS) *~

