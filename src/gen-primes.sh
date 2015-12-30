#!/bin/bash

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

# This program generates a list of variable length of several random prime
# numbers. All of those primes are 16 bits length and created by openssl
# command line utility.
# The file primes.txt has the number of primes on the first line, followed by a
# prime number in each line.

rm primes.txt
for i in {1..50}
do
	openssl prime -generate -bits 16 >> primes.txt
done

# Keep only values that can store in 16 bits.
sort primes.txt | uniq | awk '{ if ($1 < 65536) print $1 }' > primes.txt.tmp
wc -l primes.txt.tmp | cut -f1 -d' ' > primes.txt
cat primes.txt.tmp >> primes.txt && rm primes.txt.tmp
