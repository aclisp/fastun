#!/bin/bash
set +x  # turn off trace
set -e  # turn on exit immediately

# project related variables
PROJECT_PATH="github.com/aclisp"
PROJECT_NAME="fastun"

# always get PWD of this shell script, even if it is called from any path
THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# construct the golang dirs under .build
GOPATH=$THISDIR/.build
mkdir -p $GOPATH/bin
mkdir -p $GOPATH/pkg
mkdir -p $GOPATH/src
mkdir -p $GOPATH/lib
mkdir -p $GOPATH/tmp
# make project related dirs
mkdir -p $GOPATH/src/$PROJECT_PATH
PROJECT=$PROJECT_PATH/$PROJECT_NAME
WORKDIR=$GOPATH/src/$PROJECT
rm -f $WORKDIR  # workdir is a link
ln -s $THISDIR $WORKDIR  # link to the real src

# setup golang variables, so that go is aware of the new gopath
echo "Build the default (debug) version of tunneld..."
export GOPATH
go build -o $THISDIR/tunneld_debug $PROJECT

echo "Build the optimized (release) version of tunneld..."
# build c libs in a subshell
(
    CFLAGS="-fPIC -Werror -Winline -Wall -Wextra -std=gnu99 -pedantic-errors -Wno-unused-parameter -DNDEBUG -O2"
    cd $GOPATH/lib
    gcc -c $CFLAGS $THISDIR/backend/udp/*.c
    ar rcs liba.a *.o
    gcc -shared $CFLAGS -o libtun.so *.o
)
mv $THISDIR/backend/udp/*.c $GOPATH/tmp
export CGO_LDFLAGS="-L$GOPATH/lib -la"
go build -o $THISDIR/tunneld_release $PROJECT
export CGO_LDFLAGS="-L$GOPATH/lib -ltun"
go build -o $THISDIR/tunneld_shared  $PROJECT
mv $GOPATH/tmp/*.c $THISDIR/backend/udp
echo "Done."
