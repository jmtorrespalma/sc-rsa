/*  Copyright (C) 2015 Juan Manuel Torres Palma <j.m.torrespalma@gmail.com>
    This file is part of the SC-RSA program.

    SC-RSA is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    SC-RSA is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SC-RSA.  If not, see <http://www.gnu.org/licenses/>.  */

/*  This program encrypts a given plain text file (ASCII only) using a public
 *  key, that if not specified in options, takes key.pub as default. The
 *  algorithm used is RSA-32, a very simple and basic one only for academic
 *  purposes. Do not use this program for other purposes as it is easily
 *  breakable. */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* Includes all tools to open key files and related. */
#include "keyutils.h"

/* Encrypts a message using RSA-32.
 * Stores the encrypted message in enc_msg, using key (n, e).
 * We will encrypt char by char (m=0-255), even if it's not recommended
 * but it's the easiest way to achieve encryption. Returns the number
 * ef encrypted items. */
int encrypt(char *msg, uint32_t * enc_msg, uint32_t n, uint32_t e)
{
	/* No risk of overflow, e = 3. */
	int i;

	for (i = 0; i < SZ - 1 && msg[i] != '\0'; ++i)
		enc_msg[i] = ((uint32_t) pow(msg[i], e)) % n;

	return i;
}

/* Prints the encrypted message to the screen. */
#define print_msg(enc_msg, size)			\
	do {						\
		int ii;					\
							\
		/* FIXME: This printf portable? */	\
		for (ii = 0; ii < size; ++ii)		\
			printf("%08x", enc_msg[ii]);	\
		putchar('\n');				\
	} while (0)

/* Performs RSA-32 encryption from a given file and prints it out to the
 * standard output. */
int main(int argc, char *argv[])
{

	char *keyfile = "key.pub";
	char *message_file = NULL;	/* File to encrypt */
	char msg[SZ];
	uint32_t enc_msg[SZ];	/* Message after encrypting it */

	uint32_t n, e, max;

	parse_args(keyfile, message_file);

	read_key(keyfile, &n, &e);
	read_msg(message_file, msg);

	max = encrypt(msg, enc_msg, n, e);

	print_msg(enc_msg, max);

	return 0;
}
