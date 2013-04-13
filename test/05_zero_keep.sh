#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Test of keeping zero history"

mkdir -p tmp

rm -f tmp/05_test*
# Create about 2.5k worth of data
print_rows 30 85 | $LOGROTP -k 0 -s 1k -t 32 tmp/05_test

test -e tmp/05_test || fail
test -e tmp/05_test.1 && fail

test $(file_size tmp/05_test) -lt 1024 || fail

end
