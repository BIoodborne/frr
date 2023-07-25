#ifndef _FPMSYNCD_H
#define _FPMSYNCD_H


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

struct Fpmsyncd_meta_data {
	unsigned int m_bufSize;
	char *m_messageBuffer;
	unsigned int m_pos;
	int m_server_socket;
	int m_connection_socket;
	bool m_connected;
	bool m_server_up;
};


class FpmConnectionClosedException : public std::exception {
};
extern struct Fpmsyncd_meta_data fpmsyncd_meta_data ;


int fpmsyncd_init();
int fpmsyncd_exit();
int fpmsyncd_poll(void);
int fpmsyncd_read_data();

#endif