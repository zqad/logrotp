#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Check that all files are rotated at \n-point"

mkdir -p tmp

rm -f tmp/06_test*
# Create about 10k worth of data
print_rows 30 341 | $LOGROTP -k 10 -s 1k -t 32 tmp/06_test

test -e tmp/06_test || fail

for n in 1 2 3 4 5 6 7 8 9 10; do
  test -e tmp/06_test.$n || fail

  # It's hard to do a string comparison of \n in bash, so check how many lines
  # the last character consists of. If it's 1, it's a \n.
  test $(tail -c 1 tmp/06_test.$n | wc -l) -eq 1 || fail
done

end
