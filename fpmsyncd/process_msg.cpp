#include "process_msg.h"
void get_timestamp(char *timestamp)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	struct tm *t = gmtime(&time.tv_sec);
	strftime(timestamp, 64, "%Y-%m-%d %H:%M:%S", t); 
}

void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		} else {
			/* FRR 7.5 is sending RTA_ENCAP with NLA_F_NESTED bit
			 * set*/
			if (rta->rta_type & NLA_F_NESTED) {
				int rta_type = rta->rta_type & ~NLA_F_NESTED;
				if (rta_type <= max) {
					tb[rta_type] = rta;
				}
			}
		}
		rta = RTA_NEXT(rta, len);
	}
}


void process_evpn_route_msg(struct nlmsghdr *nl_hdr, int len)
{
    struct rtmsg *rtm;
    struct rtattr *tb[RTA_MAX + 1] = {0};
    void *dest = NULL;
    char anyaddr[16] = {0};
    char dstaddr[16] = {0};
    int  dst_len = 0;
    char buf[MAX_ADDR_SIZE];
    char destipprefix[IFNAMSIZ + MAX_ADDR_SIZE + 2] = {0};
    int nlmsg_type = nl_hdr->nlmsg_type;
    unsigned int vrf_index;

    rtm = (struct rtmsg *)NLMSG_DATA(nl_hdr);

    /* Parse attributes and extract fields of interest. */
    netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

    if (tb[RTA_DST])
    {
        dest = RTA_DATA(tb[RTA_DST]);
    }
    else
    {
        dest = anyaddr;
    }

    if (rtm->rtm_family == AF_INET)
    {
        if (rtm->rtm_dst_len > IPV4_MAX_BITLEN)
        {
            return;
        }
        memcpy(dstaddr, dest, IPV4_MAX_BYTE);
        dst_len = rtm->rtm_dst_len;
    }
    else if (rtm->rtm_family == AF_INET6)
    {
        if (rtm->rtm_dst_len > IPV6_MAX_BITLEN) 
        {
            return;
        }
        memcpy(dstaddr, dest, IPV6_MAX_BYTE);
        dst_len = rtm->rtm_dst_len;
    }

    zlog_debug("Rx MsgType:%d Family:%d Prefix:%s/%d", nl_hdr->nlmsg_type, rtm->rtm_family,
                    inet_ntop(rtm->rtm_family, dstaddr, buf, MAX_ADDR_SIZE), dst_len);

    /* Table corresponding to route. */
    if (tb[RTA_TABLE])
    {
        vrf_index = *(int *)RTA_DATA(tb[RTA_TABLE]);
    }
    else
    {
        vrf_index = rtm->rtm_table;
    }

    // Fpmsyncd will convert vrf_index to vrf_name(interface name)
	// from kernel. In simulation, we just use vrf_index.

	snprintf(destipprefix, sizeof(destipprefix), "%d:", vrf_index);
    
	
	if((rtm->rtm_family == AF_INET && dst_len == IPV4_MAX_BITLEN)
        || (rtm->rtm_family == AF_INET6 && dst_len == IPV6_MAX_BITLEN))
    {
        snprintf(destipprefix + strlen(destipprefix), sizeof(destipprefix) - strlen(destipprefix), "%s",
                inet_ntop(rtm->rtm_family, dstaddr, buf, MAX_ADDR_SIZE));
    }
    else
    {
        snprintf(destipprefix + strlen(destipprefix), sizeof(destipprefix) - strlen(destipprefix), "%s/%u",
                inet_ntop(rtm->rtm_family, dstaddr, buf, MAX_ADDR_SIZE), dst_len);
    }

    zlog_info("Receive route message dest ip prefix: %s Op:%s", 
                    destipprefix,
                    nlmsg_type == RTM_NEWROUTE ? "add":"del");


    /* Get nexthop lists */
    // string nexthops;
    // string vni_list;
    // string mac_list;
    // string intf_list;
    // bool ret;
    // ret = getEvpnNextHop(h, len, tb, nexthops, vni_list, mac_list, intf_list);
    
    
	
	char timestamp[64];
	get_timestamp(timestamp);
	nlohmann::json j;
	j["header"] = nlmsg_header_to_json(nl_hdr);
	j["timestamp"] = timestamp;
	j["payload"] = nlmsg_data_to_json(nl_hdr);
	std::ofstream ofs(output_file_path, std::ofstream::out | std::ofstream::app);
	ofs<<j.dump(4)<<std::endl;
	ofs.close();
	return;

}

void process_raw_msg(struct nlmsghdr *h){
	int len;

    if ((h->nlmsg_type != RTM_NEWROUTE)
        && (h->nlmsg_type != RTM_DELROUTE))
        return;
    /* Length validity. */
    len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg)));
    if (len < 0) 
    {
		zlog_err("%s: Message received from netlink is of a broken size %d %zu",
            __PRETTY_FUNCTION__, h->nlmsg_len,
            (size_t)NLMSG_LENGTH(sizeof(struct ndmsg)));
    }
    process_evpn_route_msg(h, len);
    return;
}
bool is_raw_processing(nlmsghdr *h)
{
	int len;
	short encap_type = 0;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1] = {0};

	rtm = (struct rtmsg *)NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) {
		return false;
	}

	len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
	if (len < 0) {
		return false;
	}

	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (!tb[RTA_MULTIPATH]) {
		if (tb[RTA_ENCAP_TYPE]) {
			encap_type = *(short *)RTA_DATA(tb[RTA_ENCAP_TYPE]);
		}
	} else {
		/* This is a multipath route */
		int len;
		struct rtnexthop *rtnh =
			(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);
		len = (int)RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		struct rtattr *subtb[RTA_MAX + 1];

		for (;;) {
			if (len < (int)sizeof(*rtnh) || rtnh->rtnh_len > len) {
				break;
			}

			if (rtnh->rtnh_len > sizeof(*rtnh)) {
				memset(subtb, 0, sizeof(subtb));
				netlink_parse_rtattr(
					subtb, RTA_MAX, RTNH_DATA(rtnh),
					(int)(rtnh->rtnh_len - sizeof(*rtnh)));
				if (subtb[RTA_ENCAP_TYPE]) {
					encap_type = *(uint16_t *)RTA_DATA(
						subtb[RTA_ENCAP_TYPE]);
					break;
				}
			}

			if (rtnh->rtnh_len == 0) {
				break;
			}

			len -= NLMSG_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	// zlog_debug("Rx MsgType:%d Encap:%d", h->nlmsg_type, encap_type);

	if (encap_type > 0) {
		return true;
	}

	return false;
}

nlohmann::json nlmsg_header_to_json(struct nlmsghdr *nl_hdr)
{
	nlohmann::json j;
	char buf[128];

	j["nlmsg_len"] = nl_hdr->nlmsg_len;
	j["type"]["raw"] = nl_hdr->nlmsg_type;
	j["type"]["value"] = nl_nlmsgtype2str(nl_hdr->nlmsg_type, buf, sizeof(buf));
	j["flags"]["raw"] = nl_hdr->nlmsg_flags;
	j["flags"]["value"] = nl_nlmsg_flags2str(nl_hdr->nlmsg_flags, buf, sizeof(buf));
	j["seq"] = nl_hdr->nlmsg_seq;
	j["port"] = nl_hdr->nlmsg_pid;
	
    return j;
}

   

nlohmann::json nlmsg_data_to_json(struct nlmsghdr *nl_hdr)
{
	nlohmann::json j;
	void *data = nlmsg_data(nl_hdr);
	//TODO: more detailed data parsing
	char hex_str[256];
	for (int i = 0; i < nlmsg_datalen(nl_hdr); i++) {
		int v = *(uint8_t *) ((char*)data + i);
		sprintf(hex_str+i*2 , "%02x ", v);
    }
	// zlog_debug("datalen:%d,data:%s",datalen,hex_str);
	
	j["data"]= hex_str;
	return j;
}

nlohmann::json nlmsg_err_data_to_json(nl_msg *msg)
{
	nlohmann::json j;
	struct nlmsghdr *nl_hdr = nlmsg_hdr(msg);
	struct nlmsgerr *err = (struct nlmsgerr *)nlmsg_data(nl_hdr);
	if (nlmsg_datalen(nl_hdr)> sizeof(*err)) {
		char buf[256];
		struct nl_msg *errmsg;
		errmsg = nlmsg_inherit(&err->msg);
		j["error"]["err_code"] = err->error;
		j["error"]["err_msg"] =
			strerror_r(-err->error, buf, sizeof(buf));
		j["error"]["original_msg"] =
			nlmsg_header_to_json(nlmsg_hdr(errmsg));
		nlmsg_free(errmsg);
	}
	return j;
}

nlohmann::json nlmsg_to_json(nl_msg *msg)
{
    nlohmann::json j;
	struct nlmsghdr *nl_hdr = nlmsg_hdr(msg);
	
    j["header"] = nlmsg_header_to_json(nl_hdr);
	if (nl_hdr->nlmsg_type == NLMSG_ERROR) {
		j["payload"] = nlmsg_err_data_to_json(msg);
	} else if (nlmsg_datalen(nl_hdr) > 0)
		j["payload"] = nlmsg_data_to_json(nl_hdr);

	return j;
}

void process_nl_msg(nl_msg *msg)
{
    char timestamp[64];
    nlohmann::json j;
	struct nlmsghdr *nlmsghdr = nlmsg_hdr(msg);
	
	
	j = nlmsg_to_json(msg);
    get_timestamp(timestamp);
	j["timestamp"] = timestamp;


	std::ofstream ofs(output_file_path, std::ofstream::out | std::ofstream::app);
	ofs<<j.dump(4)<<std::endl;
	ofs.close();
	
}

void process_fpm_msg(fpm_msg_hdr_t *fpm_hdr)
{
	size_t msg_len = fpm_msg_len(fpm_hdr);

	if (fpm_hdr->msg_type != FPM_MSG_TYPE_NETLINK) {
		return;
	}
	// move point to beginning of netlink message
	nlmsghdr *nl_hdr = (nlmsghdr *)fpm_msg_data(fpm_hdr);


	/* Read all netlink messages inside FPM message */
	for (; NLMSG_OK(nl_hdr, msg_len);
	     nl_hdr = NLMSG_NEXT(nl_hdr, msg_len)) {
		/*
		 * EVPN Type5 Add Routes need to be process in Raw mode as they
		 * contain RMAC, VLAN and L3VNI information. Where as all other
		 * route will be using rtnl api to extract information from the
		 * netlink msg.
		 */

		bool isRaw = is_raw_processing(nl_hdr);

		nl_msg *msg = nlmsg_convert(nl_hdr);
		if (msg == NULL) {
			throw system_error(make_error_code(errc::bad_message),
					   "Unable to convert nlmsg");
		}

		nlmsg_set_proto(msg, NETLINK_ROUTE);

		if (isRaw) {
			/* EVPN Type5 Add route processing */
			process_raw_msg(nl_hdr);
		} else {
			process_nl_msg(msg);
		}
		nlmsg_free(msg);
	}
}