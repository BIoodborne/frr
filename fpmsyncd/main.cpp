#include "fpmsyncd.h"
#include "zlog.h"
struct option longopts[] = {{"help", no_argument, NULL, 'h'},
			    {"debug", no_argument, NULL, 'd'},
			    {"file", required_argument, NULL, 'f'},
			    {0}};

void usage(const char *progname, int exit_code)
{
	printf("Usage : %s [OPTION...]\n\
	-f --file <output file path>\n\
	-d --debug\n\
	-h --help\n",
	       progname);
	exit(exit_code);
}
int main(int argc, char **argv)
{
	bool debug_mode = false;
	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "f:dh", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'f':
			// defined in fpmsyncd.h
			output_file_path = optarg;
			break;
		case 'd':
			debug_mode = true;
			break;
		case 'h':
			usage("fpmsyncd", 1);
			break;
		default:
			usage("fpmsyncd", 1);
			break;
		}
	}


	zlog_debug("FPMSYNCD starting");

	if (debug_mode)
		zlog_aux_init("FPMSYNCD", LOG_DEBUG);
	else
		zlog_aux_init("FPMSYNCD", LOG_INFO);

	if (output_file_path == NULL) {
		zlog_err("output file path not specified");
		usage("fpmsyncd", 1);
	} else if (access(output_file_path, F_OK) == -1) {
		zlog_err("output file path does not exist");
		usage("fpmsyncd", 1);
	} else
		zlog_debug("output file path: %s", output_file_path);


	while (1) {
		try {
			fpmsyncd_init();
			fpmsyncd_poll();
		} catch (FpmConnectionClosedException &e) {
			zlog_info("fpm connection closed");
			fpmsyncd_exit();
		} catch (const exception &e) {
			zlog_err("exception: %s had been thrown in daemon",e.what());
			fpmsyncd_exit();
			return 0;
		}
	}
}
