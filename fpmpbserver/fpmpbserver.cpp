
#include "fpmpbserver.h"
#include "fpm/fpm.pb-c.h"

#define FPM_HEADER_SIZE 4
struct Fpmpbserver_data fpmpbserver_data = {.bufSize = 2048,
					    .messageBuffer = NULL,
					    .pos = 0,
					    .server_socket = 0,
					    .connection_socket = 0,
					    .connected = false,
					    .server_up = false};
char *output_file_path = NULL;

void process_fpm_msg(fpm_msg_hdr_t *fpm_hdr)
{
	size_t msg_len = fpm_msg_len(fpm_hdr);
	Fpm__Message *msg;
	msg = fpm__message__unpack(NULL, msg_len - FPM_HEADER_SIZE,
				   (uint8_t *)fpm_msg_data(fpm_hdr));
	if (!msg) {
		zlog_info("[process_fpm_msg] unpack error!");
		return;
	} else {
		zlog_info("[process_fpm_msg] msg_type:%d", msg->type);
		if (!msg->add_route) {
			zlog_info("[process_fpm_msg] add_route not exist");
			return;
		}
		zlog_info(
			"[process_fpm_msg] msg add_route data:\nvrf_id:%d\naddress_family:%d\nmetric:%d\nsub_address_family:%d\nhas_route_type:%d\nroute_type:%d\n",
			msg->add_route->vrf_id, msg->add_route->address_family,
			msg->add_route->metric,
			msg->add_route->sub_address_family,
			msg->add_route->has_route_type,
			msg->add_route->route_type);
		if (!msg->add_route->key) {
			zlog_info("[process_fpm_msg] key not exist");
			return;
		} else {
			zlog_info("[process_fpm_msg] key exist");
		}
		char buf[100] = {0};
		inet_ntop(AF_INET, msg->add_route->key->prefix->bytes.data, buf,
			  sizeof(buf));
		zlog_info("[process_fpm_msg] key prefix:%s", buf);
		zlog_info("[process_fpm_msg] key length:%d",
			  msg->add_route->key->prefix->length);

		json_object *json = json_object_new_object();
		json_object_int_add(json, "msg_type", int64_t(msg->type));
		if (msg->add_route) {
			json_object_int_add(json, "vrf_id",
					    int64_t(msg->add_route->vrf_id));
			json_object_int_add(
				json, "address_family",
				int64_t(msg->add_route->address_family));
			json_object_int_add(json, "metric",
					    int64_t(msg->add_route->metric));
			json_object_int_add(
				json, "sub_address_family",
				int64_t(msg->add_route->sub_address_family));
			json_object_int_add(
				json, "has_route_type",
				int64_t(msg->add_route->has_route_type));
			json_object_int_add(
				json, "route_type",
				int64_t(msg->add_route->route_type));
			if (msg->add_route->key) {
				json_object_string_add(json, "prefix", buf);
				json_object_int_add(
					json, "prefix_length",
					int64_t(msg->add_route->key->prefix
							->length));
			}
		}
		if (output_file_path) {
			FILE *fp = fopen(output_file_path, "a+");
			if (!fp) {
				zlog_info(
					"[process_fpm_msg] open file error file path :%s",
					output_file_path);
			} else {
				fprintf(fp, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				fclose(fp);
			}
		}
		json_object_free(json);
	}
}

int fpmpbserver_init()
{
	fpmpbserver_data.server_socket =
		socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fpmpbserver_data.server_socket < 0) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to create socket");
	}

	int opt = 1;
	if (setsockopt(fpmpbserver_data.server_socket, SOL_SOCKET, SO_REUSEADDR,
		       &opt, sizeof(opt)) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to set socket option");
	}

	// bind port
	sockaddr_in server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(FPM_DEFAULT_PORT);
	server_addr.sin_addr.s_addr = FPM_DEFAULT_IP;

	if (bind(fpmpbserver_data.server_socket, (sockaddr *)&server_addr,
		 sizeof(server_addr)) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to bind port");
	}

	if (listen(fpmpbserver_data.server_socket, 10) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to listen on socket");
	}

	fpmpbserver_data.server_up = true;
	fpmpbserver_data.messageBuffer = new char[fpmpbserver_data.bufSize];
	return 0;
}

int fpmpbserver_exit()
{
	delete[] fpmpbserver_data.messageBuffer;
	if (fpmpbserver_data.connected)
		close(fpmpbserver_data.connection_socket);
	if (fpmpbserver_data.server_up)
		close(fpmpbserver_data.server_socket);
	return 0;
}


int fpmpbserver_read_data()
{

	fpm_msg_hdr_t *fpm_hdr;
	size_t msg_len;
	size_t start = 0, left;
	ssize_t read;


	read = ::read(fpmpbserver_data.connection_socket,
		      fpmpbserver_data.messageBuffer + fpmpbserver_data.pos,
		      fpmpbserver_data.bufSize - fpmpbserver_data.pos);
	if (read == 0)
		throw FpmConnectionClosedException();
	if (read < 0)
		throw system_error(make_error_code(errc::bad_message),
				   "read connnected socket error");
	fpmpbserver_data.pos += (uint32_t)read;

	while (true) {
		fpm_hdr = reinterpret_cast<fpm_msg_hdr_t *>(static_cast<void *>(
			fpmpbserver_data.messageBuffer + start));


		left = fpmpbserver_data.pos - start;

		if (left < FPM_MSG_HDR_LEN) {
			break;
		}

		/* fpm_msg_len includes header size */
		msg_len = fpm_msg_len(fpm_hdr);
		if (left < msg_len) {
			break;
		}

		if (!fpm_msg_ok(fpm_hdr, left)) {
			throw system_error(make_error_code(errc::bad_message),
					   "Malformed FPM message received");
		}


		process_fpm_msg(fpm_hdr);

		start += msg_len;
	}

	memmove(fpmpbserver_data.messageBuffer,
		fpmpbserver_data.messageBuffer + start,
		fpmpbserver_data.pos - start);
	fpmpbserver_data.pos = fpmpbserver_data.pos - (uint32_t)start;
	return 0;
}

int fpmpbserver_poll(void)
{
	pollfd poll_fd_set[MAX_CLIENTS + 1];
	memset(poll_fd_set, 0, sizeof(poll_fd_set));
	poll_fd_set[0].fd = fpmpbserver_data.server_socket;
	poll_fd_set[0].events = POLLIN;


	while (true) {

		// poll for events
		int nready = poll(poll_fd_set, MAX_CLIENTS + 1, -1);

		if (nready == -1) {

			throw system_error(make_error_code(errc::bad_message),
					   "Failed to poll socket");

			return -1;
		}
		if (poll_fd_set[0].revents & POLLIN) {
			sockaddr_in client_addr{};
			socklen_t addr_len = sizeof(client_addr);
			int client_fd =
				accept(fpmpbserver_data.server_socket,
				       (sockaddr *)&client_addr, &addr_len);
			if (client_fd == -1) {
				throw system_error(
					make_error_code(errc::bad_message),
					"Failed to accept client connection");
				continue;
			}

			// add new connection to poll fd set
			int i;
			for (i = 1; i <= MAX_CLIENTS; i++) {
				if (poll_fd_set[i].fd == 0) {
					zlog_info("has connected");
					poll_fd_set[i].fd = client_fd;
					poll_fd_set[i].events = POLLIN;
					fpmpbserver_data.connection_socket =
						client_fd;
					fpmpbserver_data.connected = true;
					break;
				}
			}
			if (i > MAX_CLIENTS) {
				throw system_error(
					make_error_code(errc::bad_message),
					"Too many clients");

				close(client_fd);
				continue;
			}

			zlog_info("New client connected: %s",
				  inet_ntoa(client_addr.sin_addr));
		}


		// check for events on client sockets
		for (int i = 1; i <= MAX_CLIENTS; i++) {
			zlog_info("check sockets i:%d", i);

			if (poll_fd_set[i].fd == 0)
				continue;

			if (poll_fd_set[i].revents & POLLIN) {
				fpmpbserver_read_data();
			}

			if (poll_fd_set[i].revents &
			    (POLLERR | POLLHUP | POLLNVAL)) {
				throw system_error(
					make_error_code(errc::bad_message),
					"socket POLLERR | POLLHUP | POLLNVAL event happened");
				close(poll_fd_set[i].fd);
				poll_fd_set[i].fd = 0;
			}
		}
		zlog_info("end of loop");
	}
}
