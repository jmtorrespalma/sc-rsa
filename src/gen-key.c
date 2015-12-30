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

/*  This program generates public and private keys to encrypt or decrypt
 *  files using asymmetric encryption. Consists on a simple implementation
 *  of the popular RSA algorithm with a key length of only 32 bits.
 *
 *  This implementation has quite a few limitations, as the key lenght and
 *  all data types for integers previously choosen to perfectly match this
 *  application. For security, it's recommended to use libraries to work
 *  with huge integers. */

#include <stdio.h>		/* Read and save files. */
#include <stdlib.h>		/* Strings to ints */
#include <stdint.h>		/* To make it portable to other architectures. */
#include <time.h>		/* Add more entropy to random numbers. */

/* Macro to read a prime number from our prime.txt file. */
#define read_prime_file(f, num)						\
	do {								\
		int n_lines, indx;					\
		char buff[256];						\
									\
		/* First line is the number of primes available. */	\
                fgets(buff, sizeof(buff), f);				\
                n_lines = (int) strtol(buff, NULL, 10);			\
									\
		indx = rand() % n_lines;				\
									\
		for (int i = 0; i <= indx; ++i)				\
	                fgets(buff, sizeof(buff), f);			\
									\
                num = (uint16_t) strtol(buff, NULL, 10);		\
	} while (0)

/* Return a random prime number.
 * This implementation is based in a look-up table created before to simplify
 * computation. The ideal scenario would be generating and testing them.
 * TODO Generate random primes with low overhead. */
uint16_t get_random_prime(void)
{
	FILE *f;
	const char *filename = "primes.txt";

	uint16_t num;

	if (!!(f = fopen(filename, "r"))) {
		read_prime_file(f, num);
		fclose(f);
	} else {
		fprintf(stderr, "Error: file %s not found.\n", filename);
		exit(EXIT_FAILURE);
	}

	return num;
}


/* Computes the modular inverse, required to generate part of the
 * private key. Implementation of Extended Euclidean Algorithm. */
int64_t modular_inverse(int64_t a, int64_t b)
{
	int64_t b0 = b, t, q;
	int64_t x0 = 0, x1 = 1;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

/* Save the generated pair of keys to their respective files. */
int save_keys(uint32_t n, uint32_t d, uint32_t e)
{
	char *pub = "key.pub";
	char *pri = "key.pri";
	FILE *fd = NULL;

	if (!!(fd = fopen(pub,"w+"))) {
		fprintf(fd, "%u, %u\n", n, e);
		fclose(fd);

		if(!!(fd = fopen(pri, "w+"))) {
			fprintf(fd, "%u, %u\n", n, d);
			fclose(fd);

		} else {
			fprintf(stderr, "Error: file %s not found.\n", pri);
			exit(EXIT_FAILURE);
		}

	} else {
		fprintf(stderr, "Error: file %s not found.\n", pub);
		exit(EXIT_FAILURE);
	}


	return 0;
}

/* This performs the classic RSA algorithm.
 * Our key length k = 32 bits and types are a limitation, so in case we want to
 * add support for more, we must use a new library to work with big integers.
 * XXX: Port to use BIGINT from OpenSSL. */

int main(int argc, char *argv[])
{

	uint16_t p, q;		/* Prime numbers */
	uint32_t e, n, phi, d;

	/* Set random number generator seed based on current time. */
	srand(time(NULL));

	/* First we choose an e value. It must be prime.
	 * TODO: Make this value dynamic. */
	e = 3;

	do {
		p = get_random_prime();
	} while (p % e == 1);

	do {
		q = get_random_prime();
	} while (q % e == 1);

	/* Calculate factors */
	n = p * q;
	phi = (p - 1) * (q - 1);
	d = modular_inverse(e, phi);

	printf("n = %u, phi = %u\n", n, phi);
	printf("Mod inverse: %u\n", d);

	save_keys(n, d, e);

	return 0;

}
