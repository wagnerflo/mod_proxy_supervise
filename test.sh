#!/bin/sh
ROOT=$(readlink -f $(dirname $0))
rm -f test.httpd.pid
LD_LIBRARY_PATH=../libs7e \
  httpd -DFOREGROUND -f test.httpd.conf -c "DocumentRoot $ROOT" -d $ROOT
