#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Create a long rotate chain"

mkdir -p tmp

rm -f tmp/03_test*
# Create about 10k worth of data
print_rows 30 341 | $LOGROTP -k 10 -s 1k -t 32 tmp/03_test

test -e tmp/03_test || fail
test $(file_size tmp/03_test) -lt 1024 || fail

for n in 1 2 3 4 5 6 7 8 9 10; do
  test -e tmp/03_test.$n || fail
  test $(file_size tmp/03_test.$n) -lt 1024 || fail
done

end
