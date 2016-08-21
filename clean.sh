#!/bin/bash
set +x  # turn off trace
set -e  # turn on exit immediately
THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
rm -rf $THISDIR/.build
rm -f $THISDIR/tunneld_debug
rm -f $THISDIR/tunneld_release
rm -f $THISDIR/tunneld_shared
