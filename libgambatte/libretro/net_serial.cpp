#include "net_serial.h"
#include "libretro.h"
#include "gambatte_log.h"

#ifdef GBLINK_POSIX_SOCKETS
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

NetSerial::NetSerial()
: is_stopped_(true)
, is_server_(false)
, port_(12345)
, hostname_()
, server_fd_(-1)
, sockfd_(-1)
, lastConnectAttempt_(0)
{
}

NetSerial::~NetSerial()
{
	stop();
}

bool NetSerial::start(bool is_server, int port, const std::string& hostname)
{
	stop();

	gambatte_log(RETRO_LOG_INFO, "Starting GameLink network %s on %s:%d\n",
			is_server ? "server" : "client", hostname.c_str(), port);
	is_server_ = is_server;
	port_ = port;
	hostname_ = hostname;
	is_stopped_ = false;

	return checkAndRestoreConnection(false);
}
void NetSerial::stop()
{
	if (!is_stopped_) {
		gambatte_log(RETRO_LOG_INFO, "Stopping GameLink network\n");
		is_stopped_ = true;
		if (sockfd_ >= 0) {
			close(sockfd_);
			sockfd_ = -1;
		}
		if (server_fd_ >= 0) {
			close(server_fd_);
			server_fd_ = -1;
		}
	}
}

bool NetSerial::checkAndRestoreConnection(bool throttle)
{
	if (is_stopped_) {
		return false;
	}
	if (sockfd_ < 0 && throttle) {
		clock_t now = clock();
		// Only attempt to establish the connection every 5 seconds
		if (((now - lastConnectAttempt_) / CLOCKS_PER_SEC) < 5) {
			return false;
		}
	}
	lastConnectAttempt_ = clock();
	if (is_server_) {
		if (!startServerSocket()) {
			return false;
		}
		if (!acceptClient()) {
			return false;
		}
	} else {
		if (!startClientSocket()) {
			return false;
		}
	}
	return true;
}
bool NetSerial::startServerSocket()
{
	int fd;
	struct sockaddr_in server_addr;

	if (server_fd_ < 0) {
		memset((char *)&server_addr, '\0', sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port_);
		server_addr.sin_addr.s_addr = INADDR_ANY;

		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error opening socket: %s\n", strerror(errno));
			return false;
		}

		if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error on binding: %s\n", strerror(errno));
			close(fd);
			return false;
		}

		if (listen(fd, 1) < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error listening: %s\n", strerror(errno));
			close(fd);
			return false;
		}
		server_fd_ = fd;
		gambatte_log(RETRO_LOG_INFO, "GameLink network server started!\n");
	}

	return true;
}
bool NetSerial::acceptClient()
{
	struct sockaddr_in client_addr;
	struct timeval tv;
	fd_set rfds;

	if (server_fd_ < 0) {
		return false;
	}
	if (sockfd_ < 0) {
		int retval;

		FD_ZERO(&rfds);
		FD_SET(server_fd_, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		if (select(server_fd_ + 1, &rfds, NULL, NULL, &tv) <= 0) {
			return false;
		}

		socklen_t client_len = sizeof(client_addr);
		sockfd_ = accept(server_fd_, (struct sockaddr*)&client_addr, &client_len);
		if (sockfd_ < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error on accept: %s\n", strerror(errno));
			return false;
		}
		gambatte_log(RETRO_LOG_INFO, "GameLink network server connected to client!\n");
	}
	return true;
}
bool NetSerial::startClientSocket()
{
	int fd;
	struct sockaddr_in server_addr;

	if (sockfd_ < 0) {
		memset((char *)&server_addr, '\0', sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port_);

		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error opening socket: %s\n", strerror(errno));
			return false;
		}

		struct hostent* server_hostname = gethostbyname(hostname_.c_str());
		if (server_hostname == NULL) {
			gambatte_log(RETRO_LOG_ERROR, "Error, no such host: %s\n", hostname_.c_str());
			close(fd);
			return false;
		}

		memmove((char*)&server_addr.sin_addr.s_addr, (char*)server_hostname->h_addr, server_hostname->h_length);
		if (connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
			gambatte_log(RETRO_LOG_ERROR, "Error connecting to server: %s\n", strerror(errno));
			close(fd);
			return false;
		}
		sockfd_ = fd;
		gambatte_log(RETRO_LOG_INFO, "GameLink network client connected to server!\n");
	}
	return true;
}

unsigned char NetSerial::send(unsigned char data, bool fastCgb)
{
	unsigned char buffer[2];

	if (is_stopped_) {
		return 0xFF;
	}
	if (sockfd_ < 0) {
		if (!checkAndRestoreConnection(true)) {
			return 0xFF;
		}
	}

	buffer[0] = data;
	buffer[1] = fastCgb;
#ifdef _WIN32
   if (::send(sockfd_, (char*) buffer, 2, 0) <= 0)
#else
	if (write(sockfd_, buffer, 2) <= 0)
#endif
   {
		gambatte_log(RETRO_LOG_ERROR, "Error writing to socket: %s\n", strerror(errno));
		close(sockfd_);
		sockfd_ = -1;
		return 0xFF;
	}

#ifdef _WIN32
	if (recv(sockfd_, (char*) buffer, 2, 0) <= 0) 
#else
   if (read(sockfd_, buffer, 2) <= 0) 
#endif
   {
		gambatte_log(RETRO_LOG_ERROR, "Error reading from socket: %s\n", strerror(errno));
		close(sockfd_);
		sockfd_ = -1;
		return 0xFF;
	}

	return buffer[0];
}

bool NetSerial::check(unsigned char out, unsigned char& in, bool& fastCgb)
{
	unsigned char buffer[2];
#ifdef _WIN32
	u_long bytes_avail = 0;
#else
	int bytes_avail = 0;
#endif
	if (is_stopped_) {
		return false;
	}
	if (sockfd_ < 0) {
		if (!checkAndRestoreConnection(true)) {
			return false;
		}
	}
#ifdef _WIN32
   if (ioctlsocket(sockfd_, FIONREAD, &bytes_avail) < 0)
#else
	if (ioctl(sockfd_, FIONREAD, &bytes_avail) < 0)
#endif
   {
		gambatte_log(RETRO_LOG_ERROR, "IOCTL Failed: %s\n", strerror(errno));
		return false;
	}

	// No data available yet
	if (bytes_avail < 2) {
		return false;
	}

#ifdef _WIN32
	if (recv(sockfd_, (char*) buffer, 2, 0) <= 0) 
#else
   if (read(sockfd_, buffer, 2) <= 0) 
#endif
   {
		gambatte_log(RETRO_LOG_ERROR, "Error reading from socket: %s\n", strerror(errno));
		close(sockfd_);
		sockfd_ = -1;
		return false;
	}

//	slave_txn_cnt++;

	in = buffer[0];
	fastCgb = buffer[1];

	buffer[0] = out;
	buffer[1] = 128;
   #ifdef _WIN32
      if (::send(sockfd_, (char*) buffer, 2, 0) <= 0)
   #else
   	if (write(sockfd_, buffer, 2) <= 0)
   #endif
   {
		gambatte_log(RETRO_LOG_ERROR, "Error writing to socket: %s\n", strerror(errno));
		close(sockfd_);
		sockfd_ = -1;
		return false;
	}

	return true;
}
#else //!GBLINK_LIBRETRO_NET

#include "libretro.h"

struct NetCallBacks
{
	static bool is_connected;
	static unsigned char recv_buffer[32], recv_len;
	static retro_netpacket_send_t send_fn;
	static retro_netpacket_poll_receive_t poll_receive_fn;
	static uint16_t target_client_id;

	static void RETRO_CALLCONV start(uint16_t client_id, retro_netpacket_send_t _send_fn, retro_netpacket_poll_receive_t _poll_receive_fn)
	{
		send_fn = _send_fn;
		poll_receive_fn = _poll_receive_fn;
		if (client_id != 0)
		{
			// I am a client connected to the host
			is_connected = true;
			target_client_id = 0;
		}
	}

	static void RETRO_CALLCONV receive(const void* pkt, size_t pktlen, uint16_t client_id)
	{
		if (pktlen != 2 || recv_len == sizeof(recv_buffer)) return;
		memcpy(recv_buffer + recv_len, pkt, 2);
		recv_len += 2;
		is_connected = true;
		target_client_id = client_id;
	}

	static void RETRO_CALLCONV stop(void)
	{
		is_connected = false;
		recv_len = 0;
		send_fn = NULL;
	}

	static bool RETRO_CALLCONV connected(uint16_t client_id)
	{
		if (is_connected) return false; // refuse additional players joining
		is_connected = true;
		target_client_id = client_id;
		return true;
	}

	static void RETRO_CALLCONV disconnected(uint16_t client_id)
	{
		if (!is_connected || client_id != target_client_id) return; // unknown client disconnects
		is_connected = false;
		recv_len = 0;
	}

	static bool SendPacket(unsigned char buffer[2])
	{
		// send and flush packet immediately
		send_fn(RETRO_NETPACKET_RELIABLE | RETRO_NETPACKET_FLUSH_HINT, buffer, 2, target_client_id);
		poll_receive_fn();
		return is_connected; // if false stop was called
	}

	static bool ReadPacket(unsigned char buffer[2], bool block)
	{
		if (!recv_len)
		{
			// check latest incoming
			poll_receive_fn();

			// give up if we got disconnected or not blocking without data
			if (!is_connected || (!recv_len && !block))
				return false;

			if (!recv_len)
			{
				// block until data arrives
				for (clock_t t_start = clock();;)
				{
					poll_receive_fn();
					if (!is_connected) return false;
					if (recv_len) break;
					if (((clock() - t_start) / CLOCKS_PER_SEC) < 5) continue;
					gambatte_log(RETRO_LOG_ERROR, "Error: Received no data from other player in 5 seconds\n");
					is_connected = false;
					recv_len = 0;
					return false;
				}
			}
		}

		// read incoming data
		buffer[0] = recv_buffer[0];
		buffer[1] = recv_buffer[1];
		memmove(recv_buffer, recv_buffer + 2, recv_len - 2);
		recv_len -= 2;
		return true;
	}
};

bool NetCallBacks::is_connected;
unsigned char NetCallBacks::recv_buffer[32], NetCallBacks::recv_len;
retro_netpacket_send_t NetCallBacks::send_fn;
retro_netpacket_poll_receive_t NetCallBacks::poll_receive_fn;
uint16_t NetCallBacks::target_client_id;

unsigned char NetSerial::send(unsigned char data, bool fastCgb)
{
	// return error if not connected
	if (!NetCallBacks::is_connected)
		return 0xFF;

	// send data then do a blocking read of incoming data
	unsigned char buffer[2] = { data, fastCgb };
	return (NetCallBacks::SendPacket(buffer) && NetCallBacks::ReadPacket(buffer, true) ? buffer[0] : 0xFF);
}

bool NetSerial::check(unsigned char out, unsigned char& in, bool& fastCgb)
{
	// return false if not connected
	if (!NetCallBacks::is_connected)
		return false;

	// check incoming
	unsigned char buffer_in[2];
	if (!NetCallBacks::ReadPacket(buffer_in, false))
		return false;
	in = buffer_in[0];
	fastCgb = !!buffer_in[1];

	// send outgoing
	unsigned char buffer_out[2] = { out, 128 };
	return NetCallBacks::SendPacket(buffer_out);
}

const retro_netpacket_callback* NetSerial::getLibretroPacketInterface()
{
	static const retro_netpacket_callback packet_callback =
	{
		NetCallBacks::start,
		NetCallBacks::receive,
		NetCallBacks::stop,
		NULL, /* poll */
		NetCallBacks::connected,
		NetCallBacks::disconnected,
	};
	return &packet_callback;
}

#endif
