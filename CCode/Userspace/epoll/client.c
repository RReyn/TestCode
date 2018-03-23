#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE	1024

int
main(int argc, char *argv[])
{
	int connfd = -1;
	char buf[BUF_SIZE] = "";
	struct sockaddr_in serv_addr;

	connfd = socket(AF_INET, SOCK_STREAM, 0);
	if (connfd < 0) {
		perror("socket error");
		return 1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(argv[2]));
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

	if (connect(connfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("connect error:");
		close(connfd);
		return 1;
	}

	while (fgets(buf, BUF_SIZE, stdin) != NULL) {
		write(connfd, buf, strlen(buf));	
	}

	close(connfd);
	return 0;
}

