#ifndef _PROCESS_MSG_H
#define _PROCESS_MSG_H



#include "json.hpp"
#include "time.h"
#include "sys/time.h"
#include "netlink/msg.h"
#include "netlink/cache.h"
#include "fpm.h"
#include "zlog.h"

#include <fstream>
#include <iostream>

#define MAX_ADDR_SIZE 64
#define IPV4_MAX_BYTE       4
#define IPV6_MAX_BYTE      16
#define IPV4_MAX_BITLEN    32
#define IPV6_MAX_BITLEN    128
#define VRF_PREFIX  "Vrf"


using namespace std;

extern char *output_file_path;

nlohmann::json nlmsg_header_to_json(struct nlmsghdr *nl_hdr);
nlohmann::json nlmsg_to_json(nl_msg *msg);
nlohmann::json nlmsg_data_to_json(struct nlmsghdr *nl_hdr);
nlohmann::json nlmsg_err_data_to_json(nl_msg *msg);

bool is_raw_processing(nlmsghdr *h);
void process_fpm_msg(fpm_msg_hdr_t *hdr);
void process_nl_msg(nl_msg *msg);
void process_raw_msg(struct nlmsghdr *h);
void process_evpn_route_msg(struct nlmsghdr *h);

void get_timestamp(char *timestamp);
void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len);

#endif