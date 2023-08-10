#ifndef _FPMPBSERVER_H
#define _FPMPBSERVER_H


#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <errno.h>
#include <system_error>
#include <net/if.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include "zlog.h"
#include "libfrr.h"
#include "fpm.h"
#include "lib/json.h"
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

#define FPM_DEFAULT_PORT 2620
#ifndef FPM_DEFAULT_IP
#define FPM_DEFAULT_IP (htonl(INADDR_LOOPBACK))
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001 /* Internet address 127.0.0.1.  */
#endif


using namespace std;
extern char *output_file_path;

struct Fpmpbserver_data {
	unsigned int bufSize;
	char *messageBuffer;
	unsigned int pos;
	int server_socket;
	int connection_socket;
	bool connected;
	bool server_up;
};


class FpmConnectionClosedException : public std::exception
{
};
extern struct Fpmpbserver_data fpmpbserver_data;


int fpmpbserver_init();
int fpmpbserver_exit();
int fpmpbserver_poll(void);
int fpmpbserver_read_data();

#endif