#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1
# Copyright (C) 2022, Google Inc, Steven Rostedt <rostedt@goodmis.org>
#
# This checks if any function is listed in a man page that is not listed
# in the main man page.

if [ $# -lt 1 ]; then
	echo "usage: check-manpages man-page-path"
	exit 1
fi

cd $1

MAIN=libtracefs
MAIN_FILE=${MAIN}.txt

# Ignore man pages that do not contain functions
IGNORE="libtracefs-options.txt"

for man in ${MAIN}-*.txt; do

	sed -ne '/^NAME/,/^SYNOP/{/^[a-z]/{s/, *$//;s/,/\n/g;s/ //g;s/-.*$/-/;/-/{s/-//p;q};p}}' $man | while read a; do
		if [ "${IGNORE/$man/}" != "${IGNORE}" ]; then
			continue
		fi
		if ! grep -q '\*'${a}'\*' $MAIN_FILE; then
			if [ "$last" == "" ]; then
				echo
			fi
			if [ "$last" != "$man" ]; then
				echo "Missing functions from $MAIN_FILE that are in $man"
				last=$man
			fi
			echo "   ${a}"
		fi
	done
done
