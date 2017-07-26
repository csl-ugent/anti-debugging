#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Get the directory of the repo and go to it
repo_dir=$(dirname $(readlink -f "$0"))
cd $repo_dir

# Set up directory structure
mkdir -p obj-{default,log}/{android,linux}
ln -nsf ./obj-default obj

# Go to the debugger source
cd debugger

# Build the objects (android or linux, logging or not) and put them in the right directory
OBJ=debugger.o

make -f Makefile.android
cp $OBJ $repo_dir/obj-default/android

make -f Makefile.linux
cp $OBJ $repo_dir/obj-default/linux

# From now we enable logging
export CFLAGS=-DENABLE_LOGGING

make -f Makefile.android
cp $OBJ $repo_dir/obj-log/android

make -f Makefile.linux
cp $OBJ $repo_dir/obj-log/linux
