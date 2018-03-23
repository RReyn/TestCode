#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_EVENT_NUM	1024
#define BUF_SIZE	16
#define IP_LEN		16

int
setnonblocking(int fd)
{
	int flags;	


	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		perror("fcntl F_GETFL error:");
		return 1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl F_SETFL error:");
		return 1;
	}

	return 0;
}

void
add_fd_to_epoll(int efd, int fd, int enable_et)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(struct epoll_event));
	event.data.fd = fd;
	event.events = EPOLLIN;

	if (enable_et) {
		event.events |= EPOLLET;
	}

	epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

void
lt_mode(struct epoll_event *events, int num, int epollfd, int listenfd)
{
	char buf[BUF_SIZE];
	int i = 0;
	int sockfd;

	for (i = 0; i < num; i++) {
		sockfd = events[i].data.fd;	
		if (sockfd == listenfd) {
			struct sockaddr_in clientaddr;
			socklen_t cli_len = sizeof(clientaddr);
			int connfd = accept(listenfd,
					(struct sockaddr *)&clientaddr, &cli_len);
			if (connfd < 0) {
				perror("accept error:");
				continue;
			}
			add_fd_to_epoll(epollfd, connfd, 0);	
		} else if (events[i].events & EPOLLIN) {
			printf("Event trigger once.\n");
			memset(buf, 0, BUF_SIZE);
			int ret = recv(sockfd, buf, BUF_SIZE - 1, 0);
			if (ret <= 0) {
				perror("recv error:");
				close(sockfd);
				continue;
			}
			printf("Get %d bytes of content: %s\n", ret, buf);
		} else {
			printf("Something else happened.\n");
		}
	}
}

void
et_mode(struct epoll_event *event, int num, int efd, int listenfd)
{
	char buf[BUF_SIZE];
	int i = 0;
	int sockfd = -1;

	for (; i < num; i++) {
		sockfd = event[i].data.fd;
		if (sockfd == listenfd) {
			struct sockaddr_in clientaddr;
			socklen_t cli_len = sizeof(clientaddr);
			int connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &cli_len);
			if (connfd < 0) {
				perror("accept error:");
				continue;
			}
			add_fd_to_epoll(efd, connfd, 1);
		} else if (event[i].events & EPOLLIN) {
			int ret = -1;

			printf("Event trigger once.\n");
			/* ET模式下事件不会重复触发，所以要保证将数据读取完成 */
			while (1) {
				memset(buf, 0, BUF_SIZE);
				ret = recv(sockfd, buf, BUF_SIZE - 1, 0);	
				if (ret < 0) {
					if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
						printf("Read later.");
						continue;
					}
					close(sockfd);
					break;
				} else if (ret == 0) {
					close(sockfd);
				} else {
					printf("Get %d bytes of content: %s\n", ret, buf);
				}
			}
		} else {
			printf("Something else happened.\n");
		}
	}
}

int
start_server(char *ipaddr, int port)
{
	int sock = -1;
	struct sockaddr_in serv_addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket error:");
		return 1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ipaddr);

	if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("bind error:");
		goto out;
	}
	if (listen(sock, 128) < 0) {
		perror("listen error:");
		goto out;
	}
	return sock;
out:
	close(sock);
	return -1;
}

void
usage(void)
{
	printf("Usage:\n");
	printf("./server [ipaddr] [port] [enable_et]");
}

int
main(int argc, char *argv[])
{
	int enable_et;
	char ip[IP_LEN] = "";
	int port = 0;
	int listenfd = -1;
	struct epoll_event events[MAX_EVENT_NUM];
	int efd;
	int ret = -1;
	
	if (argc < 4 || argc > 4) {
		usage();	
		return 1;
	} else {
		strncpy(ip, argv[1], IP_LEN - 1);		
		port = atoi(argv[2]);
		if (port < 0 || port > 65535) {
			printf("Invalid port number.\n");
			return 1;
		}
		enable_et = atoi(argv[3]);
	}

	listenfd = start_server(ip, port);
	if (listenfd < 0) {
		return -1;
	}

	efd = epoll_create(MAX_EVENT_NUM);
	if (efd < 0) {
		printf("epoll_create error.\n");
		close(listenfd);
		return -1;
	}

	add_fd_to_epoll(efd, listenfd, enable_et);
	while(1) {
		ret = epoll_wait(efd, events, MAX_EVENT_NUM, -1);	
		if (ret < 0) {
			printf("epoll wait failed.\n");
			break;
		}
		if (!enable_et) {
			lt_mode(events, ret, efd, listenfd);
		} else {
			et_mode(events, ret, efd, listenfd);
		}
	}


	close(listenfd);
	close(efd);
	return -1;
}

