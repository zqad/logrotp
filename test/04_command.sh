#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"
. functions

begin "Test the running of post-rotation commands"

mkdir -p tmp

rm -f tmp/04_test*

# Use a sleep to make sure that logrotp blocks until all children has exited
echo "sleep 1; echo -n x >> tmp/04_testB" > tmp/04_cmd
chmod +x tmp/04_cmd

# Create about 10k worth of data
print_rows 30 341 | $LOGROTP -k 10 -s 1k -t 32 -C tmp/04_cmd tmp/04_test

test -e tmp/04_test || fail
test $(file_size tmp/04_test) -lt 1024 || fail

for n in 1 2 3 4 5 6 7 8 9 10; do
  test -e tmp/04_test.$n || fail
done

# The number of bytes in the file should be equal to the number of rotations
# performed
test "$(file_size tmp/04_testB)" -eq 10 || fail

end
