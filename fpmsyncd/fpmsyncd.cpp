
#include "fpmsyncd.h"


struct Fpmsyncd_meta_data fpmsyncd_meta_data = {.m_bufSize = 2048,
						.m_messageBuffer = NULL,
						.m_pos = 0,
						.m_server_socket = 0,
						.m_connection_socket = 0,
						.m_connected = false,
						.m_server_up = false};
char *output_file_path = NULL;



int fpmsyncd_init()
{
	zlog_info("fpmsyncd_init start");
	fpmsyncd_meta_data.m_server_socket =
		socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fpmsyncd_meta_data.m_server_socket < 0) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to create socket");
	}

	int opt = 1;
	if (setsockopt(fpmsyncd_meta_data.m_server_socket, SOL_SOCKET,
		       SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				"Failed to set socket option");
	}

	// bind port
	sockaddr_in server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(FPM_DEFAULT_PORT);
	server_addr.sin_addr.s_addr = FPM_DEFAULT_IP;

	if (bind(fpmsyncd_meta_data.m_server_socket, (sockaddr *)&server_addr,
		 sizeof(server_addr)) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to bind port");
	}

	if (listen(fpmsyncd_meta_data.m_server_socket, 10) == -1) {
		throw system_error(make_error_code(errc::bad_message),
				   "Failed to listen on socket");
	}

	fpmsyncd_meta_data.m_server_up = true;
	fpmsyncd_meta_data.m_messageBuffer =
		new char[fpmsyncd_meta_data.m_bufSize];
	return 0;
}

int fpmsyncd_exit()
{
	delete[] fpmsyncd_meta_data.m_messageBuffer;
	if (fpmsyncd_meta_data.m_connected)
		close(fpmsyncd_meta_data.m_connection_socket);
	if (fpmsyncd_meta_data.m_server_up)
		close(fpmsyncd_meta_data.m_server_socket);
	return 0;
}





int fpmsyncd_read_data()
{

	fpm_msg_hdr_t *fpm_hdr;
	size_t msg_len;
	size_t start = 0, left;
	ssize_t read;


	read = ::read(fpmsyncd_meta_data.m_connection_socket,
		      fpmsyncd_meta_data.m_messageBuffer +
			      fpmsyncd_meta_data.m_pos,
		      fpmsyncd_meta_data.m_bufSize - fpmsyncd_meta_data.m_pos);
	if (read == 0)
		throw FpmConnectionClosedException();
	if (read < 0)
		throw system_error(make_error_code(errc::bad_message),
				   "read connnected socket error");
	fpmsyncd_meta_data.m_pos += (uint32_t)read;

	while (true) {
		fpm_hdr = reinterpret_cast<fpm_msg_hdr_t *>(static_cast<void *>(
			fpmsyncd_meta_data.m_messageBuffer + start));


		left = fpmsyncd_meta_data.m_pos - start;

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


		// process_fpm_msg(fpm_hdr);

		start += msg_len;
	}

	memmove(fpmsyncd_meta_data.m_messageBuffer,
		fpmsyncd_meta_data.m_messageBuffer + start,
		fpmsyncd_meta_data.m_pos - start);
	fpmsyncd_meta_data.m_pos = fpmsyncd_meta_data.m_pos - (uint32_t)start;
	return 0;
}

int fpmsyncd_poll(void)
{
	zlog_info("fpmsyncd_poll start");
	pollfd poll_fd_set[MAX_CLIENTS + 1];
	memset(poll_fd_set, 0, sizeof(poll_fd_set));
	poll_fd_set[0].fd = fpmsyncd_meta_data.m_server_socket;
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
				accept(fpmsyncd_meta_data.m_server_socket,
				       (sockaddr *)&client_addr, &addr_len);
			zlog_info("client_fd:%d",client_fd);
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
					fpmsyncd_meta_data.m_connection_socket =
						client_fd;
					fpmsyncd_meta_data.m_connected = true;
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
			zlog_info("check sockets i:%d",i);

			if (poll_fd_set[i].fd == 0)
				continue;

			if (poll_fd_set[i].revents & POLLIN) {
				fpmsyncd_read_data();
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
