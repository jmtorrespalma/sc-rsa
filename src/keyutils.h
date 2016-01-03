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

/*  Utilities and tools to simplify reading of keys and how to save them. */

#ifndef KEYUTILS_H
#define KEYUTILS_H

#include <unistd.h>
#include <stdint.h>

/* Max size of messages. */
#define SZ 256

/* Parse command line arguments.
 * The -k option is used to specify a key file. Default name of the file
 * is "key.pub" for public, and "key.pri" for private, those are default
 * by the key generator.
 * If no message file is specified, we will read from stdin. */
#define parse_args(keyfile, message_file)			\
	do {							\
		char const *opts = "k:";			\
		int c;						\
								\
		while ((c = getopt (argc, argv, opts)) != -1)	\
			if (c == 'k')				\
				keyfile = optarg;		\
		/* Checks if message argument is added. */	\
		if (optind < argc)				\
			message_file = argv[optind];		\
	} while (0)

/* Save the generated pair of keys to their respective files. */
void save_keys(uint32_t n, uint32_t d, uint32_t e);

/* Read public or private key, depending on which parameters we pass
 * to the function.
 * To read public key, call read_key(key_file, n, e)
 * To read private key, call read_key(key_file, n, d) */
void read_key(char *const key_file, uint32_t *n, uint32_t *e_or_d);

/* Read message in plain text to store it in another array ready to
 * be treated and modified. */
void read_msg(char *const msg_file, char *const msg);

/* Read encrypted message from file "msg_file" and save it to
 * "msg". */
int read_crypt_msg(char *const msg_file, uint32_t *const msg);



#endif /* KEYUTILS_H */
