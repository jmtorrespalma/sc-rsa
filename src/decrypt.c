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

/*  This program decrypts a given encrypted file using a private
 *  key, that if not specified in options, takes key.pri as default. The
 *  algorithm used is RSA-32, a very simple and basic one only for academic
 *  purposes. Do not use this program for other purposes as it is easily
 *  breakable. */

#include <stdio.h>
#include <math.h>

/* Includes all tools to open key files and related. */
#include "keyutils.h"

/* Decrypt a message using RSA-32.
 * Each characted mus be encrypted independently, otherwise it wont work
 * correctly. This process is quite slow as it takes a lot of computation
 * and we aren't using external libraries for big numbers, so we have to
 * make all operations manually. */
void decrypt(uint32_t * crypt_msg, char *msg, int sz, uint32_t n, uint32_t d)
{
	uint32_t i, j, v;
	uint64_t acc;

	for (i = 0; i < sz; ++i) {
		/* We can't do the power using pow(), because with huge
		 * exponents as d it will surely lead to overflow. We have
		 * to control each operation and make a modulo operation on
		 * every iteration to avoid overflow. This is extremely slow,
		 * but it's the simplest solution. */
		acc = v = crypt_msg[i];
		for (j = 1; j < d; ++j) {
			acc = (acc * v);
			if (acc >= n)
				acc %= n;
		}

		msg[i] = acc;
	}
}

int main(int argc, char *argv[])
{

	char *keyfile = "key.pri";
	char *crypt_file = NULL;
	char msg[SZ];
	uint32_t crypt_msg[SZ];

	uint32_t n, d, max;

	parse_args(keyfile, crypt_file);

	read_key(keyfile, &n, &d);
	max = read_crypt_msg(crypt_file, crypt_msg);

	decrypt(crypt_msg, msg, max, n, d);

	printf("%s\n", msg);

	return 0;
}
