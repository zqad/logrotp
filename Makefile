CFLAGS+=-pedantic -Wall -std=c99 -g

.PHONY: test test_debug man_view clean

.c.o:
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -o $@ -c $< $(LIBS)

logrotp: src/logrotp.o
	$(CROSS_COMPILE)$(CC) -o $@ $^

test:
	@test/01_append.sh
	@test/02_rotate_and_erase.sh
	@test/03_long_rotate_chain.sh
	@test/04_command.sh
	@test/05_zero_keep.sh
	@test/06_graceful_rotation.sh

test_debug:
	@make test LOGROTP_TEST_DEBUG=1

man_view:
	man -s8 -M man/ logrotp

clean:
	rm -f logrotp src/*.o core
	rm -rf test/tmp/
