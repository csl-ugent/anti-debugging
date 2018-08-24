#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Get the repo and build directories, go to the build directory
repo_dir=$(dirname $0)
build_dir=$1
mkdir -p $build_dir
cd $build_dir

# Set up directory structure in the build directory
ln -nsf $repo_dir/debugger
mkdir -p obj-{default,log}/{android,linux}
ln -nsf ./obj-default obj

# Go to the debugger source
cd debugger

# Build the objects (android or linux, logging or not) and put them in the right directory
OBJ=debugger.o

make -f Makefile.linux
mv $OBJ $build_dir/obj-default/linux

# From now we enable logging
export CFLAGS=-DENABLE_LOGGING

make -f Makefile.linux
mv $OBJ $build_dir/obj-log/linux
