#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Append to an existing file"

mkdir -p tmp

print_rows 60 20 > tmp/01_correct
print_rows 60 7 > tmp/01_test
print_rows 60 13 | $LOGROTP -s 10k tmp/01_test

cmp tmp/01_correct tmp/01_test || fail

end
