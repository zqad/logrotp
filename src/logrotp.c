/*
 * logrotp - pipe-based log rotation daemon
 *
 * Copyright Jonas Eriksson 2013
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _XOPEN_SOURCE
#define _GNU_SOURCE

#include <sys/sendfile.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

/* Options */
static char *opt_file_name = NULL;
static unsigned long opt_file_max_size = 1024*1024*10; /* 10MB */
static char *opt_postrot_cmd = NULL;
static char *opt_postrot_user = NULL;
static uid_t opt_postrot_uid;
static unsigned int opt_keep = 0;
static mode_t opt_file_mode = S_IWUSR | S_IRUSR;
static unsigned long opt_tolerance = 1024;
static int opt_debug = 0;
static int opt_help = 0;
static int opt_file_flags = 0;
static int opt_postrot_cmd_block = 0;

/* Macros */
#define ERR(msg, ...)	fprintf(stderr, msg "\n", __VA_ARGS__)
#define ERR0(msg)	fprintf(stderr, msg "\n")
#define FATAL(msg, ...)	do { \
				ERR(msg, __VA_ARGS__); \
				exit(1); \
			} while (0)
#define FATAL0(msg)	do { \
				ERR0(msg); \
				exit(1); \
			} while (0)
#define DBG(msg, ...)	do { \
				if (opt_debug) \
					fprintf(stdout, msg "\n", __VA_ARGS__); \
			} while (0)
#define DBG0(msg)	do { \
				if (opt_debug) \
					fprintf(stdout, msg "\n"); \
			} while (0)
#define MIN(x, y)	((x) < (y) ? (x) : (y))

/* Parses a text string with a suffix (k, m, g) into a size */
static int parse_size(unsigned long *size_num, const char *__size_text) {
	size_t len;
	char suffix;
	char *size_text;
	unsigned long factor;

	/* Make a copy */
	size_text = strdupa(__size_text);
	if (size_text == NULL)
		FATAL0("Out of memory");

	/* Parse the suffix and update the factor */
	len = strlen(size_text);
	suffix = size_text[len - 1];
	factor = 1;
	switch (suffix) {
	case 'G':
	case 'g':
		factor *= 1024;
		/* Falltrough */
	case 'M':
	case 'm':
		factor *= 1024;
		/* Falltrough */
	case 'K':
	case 'k':
		factor *= 1024;
		size_text[len - 1] = 0;
		break;
	default:
		/* Is it non-numerical? Error. */
		if (suffix < '0' || suffix > '9') {
			ERR("Illegal suffix: %c", suffix);
			return -1;
		}
	}

	/* Parse the numerical part */
	if (sscanf(size_text, "%lu", size_num) != 1) {
		ERR("Unable to parse numeric size '%s'", size_text);
		return -1;
	}

	/* Account for the factor */
	*size_num *= factor;

	return 0;
}

static int uid_from_user(uid_t *uid, const char *user) {
	struct passwd *pwd;

	/* Get passwd entry */
	pwd = getpwnam(user);
	if (pwd == NULL)
		return -1;

	*uid = pwd->pw_uid;

	return 0;
}

static int parse_mode(mode_t *mode_num, const char *mode_text) {
	if (sscanf(mode_text, "%o", mode_num) != 1)
		return -1;
	if (*mode_num > 07777)
		return -1;
	return 0;
}

static void dump_options(void) {
	DBG0("Options:");
	DBG("  File name:                  %s", opt_file_name);
	DBG("  Max file size:              %lu", opt_file_max_size);
	if (opt_postrot_cmd != NULL)
		DBG("  Post-rotation command:      %s", opt_postrot_cmd);
	if (opt_postrot_user != NULL)
		DBG("  Post-rotation command user: %s(%u)",
				opt_postrot_user, opt_postrot_uid);
	DBG("  Keep:                       %u", opt_keep);
	DBG("  Mode:                       0%03o", opt_file_mode);
	DBG("  Tolerance:                  %lu", opt_tolerance);
	DBG("  Debug:                      %d", opt_debug);
	DBG("  Help:                       %d", opt_help);
	DBG("  File flags:                 0x%04x", opt_file_flags);
}

static int parse_options(int argc, char *argv[]) {
	char opt;
	int option_index = 0;
	int errors = 0;

        static struct option long_options[] = {
		{"size",              required_argument, 0,  0 },
		{"post_rotate_cmd",   required_argument, 0,  0 },
		{"post_rotate_user",  required_argument, 0,  0 },
		{"keep",              required_argument, 0,  0 },
		{"mode",              required_argument, 0,  0 },
		{"tolerance",         required_argument, 0,  0 },
		{"debug",             no_argument,       0,  0 },
		{"help",              no_argument,       0,  0 },
		{"direct",            no_argument,       0,  0 },
		{"post_rotate_block", no_argument,       0,  0 },
		{0,                   0,                 0,  0 }
	};
	const char *short_options = "s:C:U:k:m:t:DhdB";

	while (1) {
		opt = getopt_long(argc, argv, short_options,
				long_options, &option_index);

		/* Done? */
		if (opt == -1)
			break;

		/* Longopts, send all to the respective shortops */
		if (opt == 0) {
			switch (option_index) {
			case 0:
				opt = 's';
				break;
			case 1:
				opt = 'C';
				break;
			case 2:
				opt = 'U';
				break;
			case 3:
				opt = 'k';
				break;
			case 4:
				opt = 'm';
				break;
			case 5:
				opt = 't';
				break;
			case 6:
				opt = 'D';
				break;
			case 7:
				opt = 'h';
				break;
			case 8:
				opt = 'd';
				break;
			case 9:
				opt = 'B';
				break;
			}
		}

		/* Shortopts */
		if (opt > 0) {
			switch (opt) {
			case 's':
				/* Size */
				if (parse_size(&opt_file_max_size, optarg)) {
					ERR0("Unable to parse size argument");
					errors++;
				}
				break;
			case 'C':
				/* Post-rotation command */
				opt_postrot_cmd = optarg;
				if (opt_postrot_cmd == NULL) {
					FATAL0("Out of memory");
					exit(1);
				}
				break;
			case 'U':
				/* Post-rotatation command user */
				opt_postrot_user = optarg;
				if (uid_from_user(&opt_postrot_uid,
							opt_postrot_user)) {
					ERR0("No such user");
					errors++;
				}
				break;
			case 'k':
				/* Number of logs to keep */
				if (sscanf(optarg, "%u", &opt_keep) != 1) {
					ERR0("Unable to parse keep-number");
					errors++;
				}
				break;
			case 'm':
				/* File mode on open/create */
				if (parse_mode(&opt_file_mode, optarg)) {
					ERR0("Unable to parse file mode");
					errors++;
				}
				break;
			case 't':
				/* Size of tolerance buffer */
				if (parse_size(&opt_tolerance, optarg)) {
					ERR0("Unable to parse tolerance buffer "
							"size argument");
					errors++;
				}
				break;
			case 'D':
				/* Debug */
				opt_debug = 1;
				break;
			case 'h':
				/* Help */
				opt_help = 1;
				break;
			case 'd':
				/* Direct (minimize cache effects) */
				opt_file_flags |= O_DIRECT;
				break;
			case 'B':
				/* Block until postrotate command has exited */
				opt_postrot_cmd_block = 1;
				break;
			default:
				errors++;
			}
		}
	}

	/* Ignore missing file name argument if --help is supplied */
	if (!opt_help && optind >= argc) {
		ERR0("Missing target file name");
		errors++;
	}
	else {
		opt_file_name = argv[optind];
	}

	if (opt_tolerance >= opt_file_max_size) {
		ERR0("Tolerance must be strictly smaller than max file size");
		errors++;
	}

	if (opt_debug)
		dump_options();

	return errors;
}

static void print_help() {
	/* TODO */
	ERR0("See man logrotp");
}

static int rotate(const char *file_name, int keep) {
	char **rot_file_names;
	const char *from, *to;
	int i;
	int r;
	int errors = 0;
	int max_existing_file = 0;
	struct stat stat_buf;

	DBG0("Running a rotation");

	rot_file_names = calloc(keep + 1, sizeof(char **));
	if (rot_file_names == NULL)
		FATAL0("Out of memory");

	/* Populate rot_file_names with all rotation candidates, that is
	 * file_name, file_name.1, ..., up until the file in question does not
	 * exist on the disk. This is a feature to avoid rotating later logs
	 * until all rotation slots are contignous. */
	rot_file_names[0] = (char *)file_name;
	for (i = 1; i <= keep; i++) {
		r = asprintf(&rot_file_names[i], "%s.%d", file_name, i);
		if (r < 0)
			FATAL0("Out of memory");

		if (stat(rot_file_names[i], &stat_buf))
			break;

		max_existing_file = i;
	}

	/* Now count down, each slot in rot_file_names represents a log that
	 * should be rotated away, except the very last given that all
	 * rotation slots are in use */
	for (i = MIN(max_existing_file, keep - 1); i >= 0; i--) {
		to = rot_file_names[i + 1];
		if (i == 0)
			from = file_name;
		else
			from = rot_file_names[i];

		DBG("  Moving '%s' -> '%s'", from, to);
		r = rename(from, to);
		if (r < 0) {
			ERR("Unable to move '%s' to '%s': %s", from, to,
					strerror(errno));
			errors++;
			goto out;
		}
	}

out:
	/* Be careful to only free the heap-allocated elements in
	 * rot_file_names */
	for (i = 1; i <= max_existing_file; i++)
		free(rot_file_names[i]);
	free(rot_file_names);

	return errors;
}

static int reap(int block) {
	int status;
	pid_t pid;

	pid = waitpid(-1, &status, (block ? 0 : WNOHANG));

	if (pid > 0) {
		DBG("Child %d exited with status %d", pid,
				WEXITSTATUS(status));
		return 1;
	}

	return 0;
}

static int run_postrot_cmd() {
	pid_t pid;
	int children_waiting = 0;

	/* Any command registered? */
	if (opt_postrot_cmd == NULL)
		return 0;

	pid = fork();

	/* Errors? */
	if (pid < 0)
		FATAL0("Unable to fork");

	if (pid == 0) {
		/* In child */

		/* Setuid */
		if (opt_postrot_user != NULL) {
			if (setuid(opt_postrot_uid)) {
				FATAL0("Unable to setuid");
			}
		}

		/* Exec */
		if (execl("/bin/sh", "/bin/sh", "-c", opt_postrot_cmd, NULL)) {
			FATAL("Unable to exec '%s'", opt_postrot_cmd);
		}
	}

	/* In parent */
	DBG("Child %d started with command %s", pid, opt_postrot_cmd);

	/* Block in parent until child has exited? */
	if (opt_postrot_cmd_block)
		reap(1);
	else 
		children_waiting = 1;

	return children_waiting;
}

static ssize_t write_all(int fd, void *buf, size_t count, ssize_t *written) {
	size_t w;

	*written = 0;
	do {
		w = write(fd, buf, count);
		if (w < 0)
			return w;
		count -= w;
		*written += w;
	} while (count > 0);

	return 0;
}

int main(int argc, char *argv[]) {
	int fd;
	int errors = 0;
	int children_waiting = 0;
	int i;
	char *tol_buf;
	char *tol_buf_ptr;
	int tol_buf_ptr_datalen = 0;
	struct stat stat_buf;
	off_t file_size;
	ssize_t num_bytes_read;
	ssize_t num_bytes_read_total;
	ssize_t num_bytes_written;
	ssize_t num_bytes_to_be_written;
	unsigned long file_space_left;
	int rotate_file_flags = 0;

	/* Parse command line argument */
	errors += parse_options(argc, argv);

	/* Print help */
	if (opt_help) {
		print_help();
		exit(1);
	}

	/* Any errors when parsing configuration? */
	if (errors)
		exit(1);


	/* Allocate tolerance buffer */
	tol_buf = malloc(opt_tolerance * 2);
	if (tol_buf == NULL)
		FATAL0("Out of memory");
	tol_buf_ptr = NULL;

	while (1) {
		/* Open target file */
		fd = open(opt_file_name,
				O_WRONLY | O_CREAT | O_CLOEXEC
					| opt_file_flags | rotate_file_flags,
				opt_file_mode);
		if (fd < 0) {
			DBG("Error: %s", strerror(fd));
			FATAL0("Unable to open file for writing");
		}

		/* Write all of tol_buf to the file */
		if (tol_buf_ptr_datalen > 0) {
			if (write_all(fd, tol_buf_ptr, tol_buf_ptr_datalen,
					&num_bytes_written)) {
				FATAL("Unable to write to file, %d "
						"bytes of data lost",
						tol_buf_ptr_datalen);
			}

			/* Reset tol_buf_* */
			tol_buf_ptr_datalen = 0;
			tol_buf_ptr = NULL;
		}

		/* Get current file size */
		if (fstat(fd, &stat_buf)) {
			FATAL0("Unable to stat file");
		}
		file_size = stat_buf.st_size;

		/* Reap eventual children */
		if (children_waiting)
			children_waiting -= reap(0);

		/* Continue filling the file? */
		if (file_size < (opt_file_max_size - opt_tolerance)) {

			/* Let the kernel shuffle data for us until it's time
			 * to look for \n */
			file_space_left = opt_file_max_size - opt_tolerance -
				file_size;
			do {
				/* Shuffle data */
				num_bytes_written = splice(STDIN_FILENO, NULL,
						fd, &file_size, file_space_left,
						SPLICE_F_MOVE | SPLICE_F_MORE);
				if (num_bytes_written <= 0)
					break;

				/* Keep track of file size */
				file_space_left -= num_bytes_written;
			} while (file_space_left > 0);

			if (num_bytes_written < 0) {
				/* The data transfer did not succeed */
				FATAL("Unable to write to file (%s)",
						strerror(num_bytes_written));
			}
			if (num_bytes_written == 0) {
				ERR0("Writer-end of pipe was closed");
				close(fd);
				break;
			}

			/* splice seems unwilling to cooperate without a
			 * offset variable. And when it is in use, the file
			 * position is untouched. Therefore,before we start to
			 * read/write, seek to the end of the file. */
			lseek(fd, 0, SEEK_END);

			/* Search for a \n */
			num_bytes_read_total = 0;
			do {
				/* Read and track how much has been read in
				 * total. Subtract one to be sure to fit the
				 * nul termination. */
				num_bytes_read = read(STDIN_FILENO, tol_buf,
						opt_tolerance * 2 - 1 -
						num_bytes_read_total);
				num_bytes_read_total += num_bytes_read;

				/* Make a string of tol_buf by setting the
				 * position after the read bytes to 0, and
				 * search for the \n */
				tol_buf[num_bytes_read] = 0;
				tol_buf_ptr = strchr(tol_buf, '\n');

				if (tol_buf_ptr != NULL) {
					/* A match. Set up the rest of this
					 * main loop iteration to write
					 * everything before and including the
					 * \n to the current file, and
					 * everything afterwards in the next
					 * main loop iteration. */

					/* Move to the element after \n */
					tol_buf_ptr++;

					/* This iteration, count how many
					 * bytes that should be written */
					num_bytes_to_be_written = (size_t)
						(tol_buf_ptr - tol_buf);

					/* Next main loop teration
					 * (tol_buf_ptr has already ben set) */
					tol_buf_ptr_datalen = num_bytes_read
						- num_bytes_to_be_written;
				}
				else {
					/* No match, write the whole buffer */
					num_bytes_to_be_written = num_bytes_read;
				}

				/* Write everything that is supposed to be
				 * written */
				if (write_all(fd, tol_buf,
							num_bytes_to_be_written,
							&num_bytes_written)) {
					FATAL0("Unable to write to file");
				}

				/* Terminate if we found a \n, or if we give
				 * up finding a \n within the given tolerance */
			} while (tol_buf_ptr == NULL &&
					num_bytes_read_total < (opt_tolerance * 2));
		}

		/* Close target file */
		close(fd);

		/* Reap eventual children */
		if (children_waiting)
			children_waiting -= reap(0);

		/* Rotate the file, either using the step-wise function, or
		 * just by truncating in the next iteration. */
		if (opt_keep > 0) {
			if (rotate(opt_file_name, opt_keep)) {
				FATAL0("Rotate failed");
			}
		}
		else {
			DBG0("No rotation, just overwrite");
			rotate_file_flags = O_TRUNC;
		}

		/* Run post-rotate command */
		children_waiting += run_postrot_cmd();

	}

	/* Reap all remaining children */
	for (i = 0; i < children_waiting; i++)
		reap(1);

	free(tol_buf);
	return errors;
}
