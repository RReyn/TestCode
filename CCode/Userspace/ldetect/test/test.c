#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "ld_config.h"
#include "io_wrapper.h"

int
main(int argc, char *argv[])
{
	struct sockaddr_in serv;
	char buf[1024] = "";
	int sock;
	int ret = 0;
	struct msg_hdr *msg = NULL;
	char *buf1 = "{\"detect_list\":[{\"id\":3,\"protocol\":\"icmp\",\"src_ip\":\"192.168.2.250\",\"dst_ip\":\"10.2.7.77\",\"src_port\":0,\"dst_port\":0,\"interval\":1,\"retry_times\":5}]}";
	char *buf2 = "{\"detect_list\":[{\"id\":3,\"protocol\":\"udp\",\"src_ip\":\"192.168.2.250\",\"dst_ip\":\"10.2.7.77\",\"src_port\":1002,\"dst_port\":1002,\"interval\":1,\"retry_times\":5}]}";
	char *buf3 = "{\"detect_list\":[{\"id\":3,\"protocol\":\"udp\",\"src_ip\":\"192.168.2.250\",\"dst_ip\":\"10.2.7.77\",\"src_port\":1002,\"dst_port\":1002,\"interval\":1,\"retry_times\":5}]}";

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(8001);
	serv.sin_addr.s_addr = inet_addr("192.168.2.250");

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket error:");
		return -1;
	}


	if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
		perror("bind error:");
		close(sock);
		return -1;
	}

	msg = (struct msg_hdr *)malloc(sizeof(struct msg_hdr) + 256 * sizeof(char));
	if (msg == NULL) {
		perror("malloc failed.");
		close(sock);
		return -1;
	}
#if 0
	set_fd_nonblock(sock);
#endif

	msg->msg_type = ADD_DETECT_CONFIG_TYPE;
	msg->len = sizeof(struct msg_hdr) + strlen(buf1);	
	strncpy(msg->msg_data, buf1, 256);
	printf("Send buf1 message to server.\n");
	ret = write(sock, msg, msg->len);
	if (ret < 0) {
		printf("send error.");
	}
	ret = read(sock, buf, 1024);
	printf("recv: %s\n", buf);
	sleep(10);
	printf("Send buf2 message to server.\n");
	msg->msg_type = MOD_DETECT_CONFIG_TYPE;
	msg->len = sizeof(struct msg_hdr) + strlen(buf2);	
	strncpy(msg->msg_data, buf2, 256);
	ret = write(sock, msg, msg->len);
	if (ret < 0) {
		printf("send error.");
	}
	ret = read(sock, buf, 1024);
	printf("recv: %s\n", buf);
	sleep(10);
	printf("Send buf3 message to server.\n");
	msg->msg_type = DEL_DETECT_CONFIG_TYPE;
	msg->len = sizeof(struct msg_hdr) + strlen(buf3);	
	strncpy(msg->msg_data, buf3, 256);
	ret = write(sock, msg, msg->len);
	if (ret < 0) {
		printf("send error.");
	}
	ret = read(sock, buf, 1024);
	printf("recv: %s\n", buf);

	close(sock);
	return 0;
}
