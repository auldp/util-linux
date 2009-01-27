/*
 * blkid.c - User command-line interface for libblkid
 *
 * Copyright (C) 2001 Andreas Dilger
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 * %End-Header%
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_TERMIO_H
#include <termio.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
extern int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind;
#endif

#define OUTPUT_VALUE_ONLY	0x0001
#define OUTPUT_DEVICE_ONLY	0x0002
#define OUTPUT_PRETTY_LIST	0x0004
#define OUTPUT_UDEV_LIST	0x0008

#include <blkid.h>

const char *progname = "blkid";

static void print_version(FILE *out)
{
	fprintf(out, "%s %s (%s)\n", progname, BLKID_VERSION, BLKID_DATE);
}

static void usage(int error)
{
	FILE *out = error ? stderr : stdout;

	print_version(out);
	fprintf(out,
		"Usage:\n"
		"  %1$s [-c <file>] [-ghlLv] [-o format] [-s <tag>] \n"
		"         [-t <token>] [-w <file>] [dev ...]\n\n"
		"  %1$s -p [-O <offset>] [-S <size>] <dev> [dev ...]\n\n"
		"Options:\n"
		"  -c <file>   cache file (default: /etc/blkid.tab, /dev/null = none)\n"
		"  -h          print this usage message and exit\n"
		"  -g          garbage collect the blkid cache\n"
		"  -o <format> output format; can be one of:\n"
		"              value, device, list, udev or full; (default: full)\n"
		"  -p          switch to low-probe mode (bypass cache)\n"
		"  -s <tag>    show specified tag(s) (default show all tags)\n"
		"  -t <token>  find device with a specific token (NAME=value pair)\n"
		"  -l          lookup the the first device with arguments specified by -t\n"
		"  -v          print version and exit\n"
		"  -w <file>   write cache to different file (/dev/null = no write)\n"
		"  <dev>       specify device(s) to probe (default: all devices)\n\n",
				progname);

	exit(error);
}

/*
 * This function does "safe" printing.  It will convert non-printable
 * ASCII characters using '^' and M- notation.
 */
static void safe_print(const char *cp, int len)
{
	unsigned char	ch;

	if (len < 0)
		len = strlen(cp);

	while (len--) {
		ch = *cp++;
		if (ch > 128) {
			fputs("M-", stdout);
			ch -= 128;
		}
		if ((ch < 32) || (ch == 0x7f)) {
			fputc('^', stdout);
			ch ^= 0x40; /* ^@, ^A, ^B; ^? for DEL */
		}
		fputc(ch, stdout);
	}
}

static int get_terminal_width(void)
{
#ifdef TIOCGSIZE
	struct ttysize	t_win;
#endif
#ifdef TIOCGWINSZ
	struct winsize	w_win;
#endif
        const char	*cp;

#ifdef TIOCGSIZE
	if (ioctl (0, TIOCGSIZE, &t_win) == 0)
		return (t_win.ts_cols);
#endif
#ifdef TIOCGWINSZ
	if (ioctl (0, TIOCGWINSZ, &w_win) == 0)
		return (w_win.ws_col);
#endif
        cp = getenv("COLUMNS");
	if (cp)
		return strtol(cp, NULL, 10);
	return 80;
}

static int pretty_print_word(const char *str, int max_len,
			     int left_len, int overflow_nl)
{
	int len = strlen(str) + left_len;
	int ret = 0;

	fputs(str, stdout);
	if (overflow_nl && len > max_len) {
		fputc('\n', stdout);
		len = 0;
	} else if (len > max_len)
		ret = len - max_len;
	do
		fputc(' ', stdout);
	while (len++ < max_len);
	return ret;
}

static void pretty_print_line(const char *device, const char *fs_type,
			      const char *label, const char *mtpt,
			      const char *uuid)
{
	static int device_len = 10, fs_type_len = 7;
	static int label_len = 8, mtpt_len = 14;
	static int term_width = -1;
	int len, w;

	if (term_width < 0)
		term_width = get_terminal_width();

	if (term_width > 80) {
		term_width -= 80;
		w = term_width / 10;
		if (w > 8)
			w = 8;
		term_width -= 2*w;
		label_len += w;
		fs_type_len += w;
		w = term_width/2;
		device_len += w;
		mtpt_len +=w;
	}

	len = pretty_print_word(device, device_len, 0, 1);
	len = pretty_print_word(fs_type, fs_type_len, len, 0);
	len = pretty_print_word(label, label_len, len, 0);
	len = pretty_print_word(mtpt, mtpt_len, len, 0);
	fputs(uuid, stdout);
	fputc('\n', stdout);
}

static void pretty_print_dev(blkid_dev dev)
{
	fprintf(stderr, "pretty print not implemented yet\n");

#ifdef NOT_IMPLEMENTED
	blkid_tag_iterate	iter;
	const char		*type, *value, *devname;
	const char		*uuid = "", *fs_type = "", *label = "";
	char			*cp;
	int			len, mount_flags;
	char			mtpt[80];
	errcode_t		retval;

	if (dev == NULL) {
		pretty_print_line("device", "fs_type", "label",
				  "mount point", "UUID");
		for (len=get_terminal_width()-1; len > 0; len--)
			fputc('-', stdout);
		fputc('\n', stdout);
		return;
	}

	devname = blkid_dev_devname(dev);
	if (access(devname, F_OK))
		return;

	/* Get the uuid, label, type */
	iter = blkid_tag_iterate_begin(dev);
	while (blkid_tag_next(iter, &type, &value) == 0) {
		if (!strcmp(type, "UUID"))
			uuid = value;
		if (!strcmp(type, "TYPE"))
			fs_type = value;
		if (!strcmp(type, "LABEL"))
			label = value;
	}
	blkid_tag_iterate_end(iter);

	/* Get the mount point */
	mtpt[0] = 0;
	retval = ext2fs_check_mount_point(devname, &mount_flags,
					  mtpt, sizeof(mtpt));
	if (retval == 0) {
		if (mount_flags & EXT2_MF_MOUNTED) {
			if (!mtpt[0])
				strcpy(mtpt, "(mounted, mtpt unknown)");
		} else if (mount_flags & EXT2_MF_BUSY)
			strcpy(mtpt, "(in use)");
		else
			strcpy(mtpt, "(not mounted)");
	}

	pretty_print_line(devname, fs_type, label, mtpt, uuid);
#endif
}

static void print_udev_format(const char *name, const char *value, size_t sz)
{
	char enc[265], safe[256];

	*safe = *enc = '\0';

	if (!strcmp(name, "TYPE") || !strcmp(name, "VERSION")) {
		blkid_encode_string(value, enc, sizeof(enc));
		printf("ID_FS_%s=%s\n", name, enc);

	} else if (!strcmp(name, "UUID") ||
		 !strcmp(name, "LABEL") ||
		 !strcmp(name, "UUID_SUB")) {

		blkid_safe_string(value, safe, sizeof(safe));
		printf("ID_FS_%s=%s\n", name, safe);

		blkid_encode_string(value, enc, sizeof(enc));
		printf("ID_FS_%s_ENC=%s\n", name, enc);
	}
	else
		printf("ID_FS_%s=%s\n", name, value);
}

static void print_value(int output, int num, blkid_dev dev,
			const char *value, const char *name, size_t valsz)
{
	if (output & OUTPUT_VALUE_ONLY) {
		fputs(value, stdout);
		fputc('\n', stdout);

	} else if (output & OUTPUT_UDEV_LIST) {
		print_udev_format(name, value, valsz);

	} else {
		if (num == 1 && dev)
			printf("%s: ", blkid_dev_devname(dev));
		fputs(name, stdout);
		fputs("=\"", stdout);
		safe_print(value, valsz);
		fputs("\" ", stdout);
	}
}

static void print_tags(blkid_dev dev, char *show[], int numtag, int output)
{
	blkid_tag_iterate	iter;
	const char		*type, *value;
	int			i, num = 1;

	if (!dev)
		return;

	if (output & OUTPUT_PRETTY_LIST) {
		pretty_print_dev(dev);
		return;
	}

	if (output & OUTPUT_DEVICE_ONLY) {
		printf("%s\n", blkid_dev_devname(dev));
		return;
	}

	iter = blkid_tag_iterate_begin(dev);
	while (blkid_tag_next(iter, &type, &value) == 0) {
		if (numtag && show) {
			for (i=0; i < numtag; i++)
				if (!strcmp(type, show[i]))
					break;
			if (i >= numtag)
				continue;
		}
		print_value(output, num++, dev, value, type, strlen(value));
	}
	blkid_tag_iterate_end(iter);

	if (num > 1 && !(output & OUTPUT_VALUE_ONLY))
		printf("\n");
}

static int lowprobe_device(blkid_probe pr, const char *devname, int output,
		blkid_loff_t offset, blkid_loff_t size)
{
	unsigned char *data;
	const char *name;
	int nvals, n;
	size_t len;
	int fd;
	int rc = 0;

	fd = open(devname, O_RDONLY);
	if (fd < 0) {
		perror(devname);
		return -1;
	}

	if (blkid_probe_set_device(pr, fd, offset, size))
		goto error;
	rc = blkid_do_safeprobe(pr);
	if (rc)
		goto error;

	nvals = blkid_probe_numof_values(pr);

	for (n = 0; n < nvals; n++) {
		if (blkid_probe_get_value(pr, n, &name, &data, &len))
			continue;

		len = strnlen((char *) data, len);
		print_value(output, n + 1, NULL, (char *) data, name, len);
	}

	close(fd);
	return 0;
error:
	if (rc == -2)
		fprintf(stderr, "%s: ambivalent result "
				"(probably more filesystems on the device)\n",
				devname);
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	blkid_cache cache = NULL;
	char *devices[128] = { NULL, };
	char *show[128] = { NULL, };
	char *search_type = NULL, *search_value = NULL;
	char *read = NULL;
	char *write = NULL;
	unsigned int numdev = 0, numtag = 0;
	int version = 0;
	int err = 4;
	unsigned int i;
	int output_format = 0;
	int lookup = 0, gc = 0, lowprobe = 0;
	int c;
	blkid_loff_t offset = 0, size = 0;

	while ((c = getopt (argc, argv, "c:f:ghlo:O:ps:S:t:w:v")) != EOF)
		switch (c) {
		case 'c':
			if (optarg && !*optarg)
				read = NULL;
			else
				read = optarg;
			if (!write)
				write = read;
			break;
		case 'l':
			lookup++;
			break;
		case 'g':
			gc = 1;
			break;
		case 'o':
			if (!strcmp(optarg, "value"))
				output_format = OUTPUT_VALUE_ONLY;
			else if (!strcmp(optarg, "device"))
				output_format = OUTPUT_DEVICE_ONLY;
			else if (!strcmp(optarg, "list"))
				output_format = OUTPUT_PRETTY_LIST;
			else if (!strcmp(optarg, "udev"))
				output_format = OUTPUT_UDEV_LIST;
			else if (!strcmp(optarg, "full"))
				output_format = 0;
			else {
				fprintf(stderr, "Invalid output format %s. "
					"Choose from value,\n\t"
					"device, list, or full\n", optarg);
				exit(1);
			}
			break;
		case 'O':
			offset = strtoll(optarg, NULL, 10);
			break;
		case 'p':
			lowprobe++;
			break;
		case 's':
			if (numtag >= sizeof(show) / sizeof(*show)) {
				fprintf(stderr, "Too many tags specified\n");
				usage(err);
			}
			show[numtag++] = optarg;
			break;
		case 'S':
			size = strtoll(optarg, NULL, 10);
			break;
		case 't':
			if (search_type) {
				fprintf(stderr, "Can only search for "
						"one NAME=value pair\n");
				usage(err);
			}
			if (blkid_parse_tag_string(optarg,
						   &search_type,
						   &search_value)) {
				fprintf(stderr, "-t needs NAME=value pair\n");
				usage(err);
			}
			break;
		case 'v':
			version = 1;
			break;
		case 'w':
			if (optarg && !*optarg)
				write = NULL;
			else
				write = optarg;
			break;
		case 'h':
			err = 0;
		default:
			usage(err);
		}

	while (optind < argc)
		devices[numdev++] = argv[optind++];

	if (version) {
		print_version(stdout);
		goto exit;
	}

	if (!lowprobe && blkid_get_cache(&cache, read) < 0)
		goto exit;

	err = 2;
	if (gc) {
		blkid_gc_cache(cache);
		goto exit;
	}
	if (output_format & OUTPUT_PRETTY_LIST)
		pretty_print_dev(NULL);

	if (lowprobe) {
		blkid_probe pr;

		if (!numdev) {
			fprintf(stderr, "The low-probe option requires a device\n");
			exit(1);
		}
		pr = blkid_new_probe();
		if (!pr)
			goto exit;
		blkid_probe_set_request(pr,
				BLKID_PROBREQ_LABEL | BLKID_PROBREQ_UUID |
				BLKID_PROBREQ_TYPE | BLKID_PROBREQ_SECTYPE |
				BLKID_PROBREQ_USAGE | BLKID_PROBREQ_VERSION);

		for (i = 0; i < numdev; i++)
			err += lowprobe_device(pr, devices[i],
					output_format, offset, size);
		blkid_free_probe(pr);
	} else if (lookup) {
		blkid_dev dev;

		if (!search_type) {
			fprintf(stderr, "The lookup option requires a "
				"search type specified using -t\n");
			exit(1);
		}
		/* Load any additional devices not in the cache */
		for (i = 0; i < numdev; i++)
			blkid_get_dev(cache, devices[i], BLKID_DEV_NORMAL);

		if ((dev = blkid_find_dev_with_tag(cache, search_type,
						   search_value))) {
			print_tags(dev, show, numtag, output_format);
			err = 0;
		}
	/* If we didn't specify a single device, show all available devices */
	} else if (!numdev) {
		blkid_dev_iterate	iter;
		blkid_dev		dev;

		blkid_probe_all(cache);

		iter = blkid_dev_iterate_begin(cache);
		blkid_dev_set_search(iter, search_type, search_value);
		while (blkid_dev_next(iter, &dev) == 0) {
			dev = blkid_verify(cache, dev);
			if (!dev)
				continue;
			print_tags(dev, show, numtag, output_format);
			err = 0;
		}
		blkid_dev_iterate_end(iter);
	/* Add all specified devices to cache (optionally display tags) */
	} else for (i = 0; i < numdev; i++) {
		blkid_dev dev = blkid_get_dev(cache, devices[i],
						  BLKID_DEV_NORMAL);

		if (dev) {
			if (search_type &&
			    !blkid_dev_has_tag(dev, search_type,
					       search_value))
				continue;
			print_tags(dev, show, numtag, output_format);
			err = 0;
		}
	}

exit:
	if (search_type)
		free(search_type);
	if (search_value)
		free(search_value);
	if (!lowprobe)
		blkid_put_cache(cache);
	return err;
}
