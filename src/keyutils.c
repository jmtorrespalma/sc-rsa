/*  Copyright (C) 2016 Juan Manuel Torres Palma <j.m.torrespalma@gmail.com>
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

/*  Implementation file for keyutils. */

#include "keyutils.h"
#include <stdio.h>
#include <stdlib.h>

/* Save the generated pair of keys to their respective files. */
void save_keys(uint32_t n, uint32_t d, uint32_t e)
{
	char *pub = "key.pub";
	char *pri = "key.pri";
	FILE *fd = NULL;

	if (! !(fd = fopen(pub, "w+"))) {
		fprintf(fd, "%u, %u\n", n, e);
		fclose(fd);

		if (! !(fd = fopen(pri, "w+"))) {
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

}

/* Read public or private key, depending on which parameters we pass
 * to the function.
 * Our key files always have the same format so we can use fscanf to
 * read them. */
void read_key(char *const key_file, uint32_t * n, uint32_t * e_or_d)
{
	FILE *fd;

	if (! !(fd = fopen(key_file, "r"))) {
		fscanf(fd, "%u, %u\n", n, e_or_d);
		fclose(fd);
	} else {

		fprintf(stderr, "Error: file %s not found.\n", key_file);
		exit(EXIT_FAILURE);
	}

}

/* Read message in plain text to store it in another array ready to
 * be treated and modified.
 * By reading its chars one by one, we have to manually check everything
 * while creating the msg. Other choice may be reading it line by line.
 * Piping of input is implemented as we can read from stdin too.*/
void read_msg(char *const msg_file, char *const msg)
{
	FILE *fd;
	char file_f;
	char c;
	unsigned cntr = 0;

	/* Is there a file? */
	file_f = (msg_file != NULL);

	/* If no file specified, read from stdin. */
	if (!file_f)
		fd = stdin;

	else {			/* Open file. */
		if (!(fd = fopen(msg_file, "r"))) {
			fprintf(stderr, "Error: file %s not found.\n",
				msg_file);
			exit(EXIT_FAILURE);
		}
	}

	/* Copy char by char. */
	while ((c = fgetc(fd)) != EOF && cntr < SZ - 1)
		msg[cntr++] = c;
	/* Add string terminator. */
	msg[cntr] = '\0';

	if (!file_f)
		fclose(fd);

}

/* Read encrypted message from file "msg_file" and save it to
 * "msg". Returns the number of integers read.*/
int read_crypt_msg(char *const msg_file, uint32_t * const msg)
{
	FILE *fd;
	char file_f;
	char buff[9];		/* Numbers are 8 digit long in hex. */
	unsigned cntr = 0;

	/* Is there a file? */
	file_f = (msg_file != NULL);

	/* If no file specified, read from stdin. */
	if (!file_f)
		fd = stdin;

	else {			/* Open file. */
		if (!(fd = fopen(msg_file, "r"))) {
			fprintf(stderr, "Error: file %s not found.\n",
				msg_file);
			exit(EXIT_FAILURE);
		}
	}

	/* Read values. */
	while ((fgets(buff, sizeof(buff), fd)) != NULL && cntr < SZ)
		msg[cntr++] = strtol(buff, NULL, 16);

	if (!file_f)
		fclose(fd);

	return cntr;

}
