#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Rotate enough for the last slot to be overwritten"

mkdir -p tmp

rm -f tmp/02_test*
# Create about 2.5k worth of data
print_rows 30 85 | $LOGROTP -k 1 -s 1k -t 32 tmp/02_test

test -e tmp/02_test || fail
test -e tmp/02_test.1 || fail
test -e tmp/02_test.2 && fail

test $(file_size tmp/02_test) -lt 1024 || fail
test $(file_size tmp/02_test.1) -lt 1024 || fail

end
