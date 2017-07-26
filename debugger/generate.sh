#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters. Expected a path to a C compiler and a name for the debugger object."
	exit -1
fi

OPTIONS="-marm -mfloat-abi=softfp -msoft-float -mfpu=neon -std=gnu99 -Wall -Wextra"

exec 1>Makefile

echo "CC = $1"
echo "CFLAGS := -fPIC $OPTIONS \$(CFLAGS)"
echo $'\r'
echo "default:"
echo $'\t''$(CC) $(CFLAGS)'" -o $2 -c debugger.c"
echo "clean:"
echo $'\t'"-rm -f $2"
