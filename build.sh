#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Get the directory of the repo and go to it
repo_dir=$(dirname $(realpath "$0"))
echo $repo_dir
cd $repo_dir

# Set up directory structure
mkdir -p obj-{default,log}/{android,linux}
ln -s obj-default obj

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
