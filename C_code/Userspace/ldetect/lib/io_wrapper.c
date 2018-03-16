#include <errno.h>
#include <netinet/in.h>

#include "common.h"
#include "log.h"

ssize_t
readn(int fd, void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nread;
	char *bufp = usrbuf;

	while (nleft > 0) {
		if ((nread = read(fd, bufp, nleft)) < 0) {
			if (errno == EINTR) {
				/* interrupted by sig handler return */
				nread = 0;
			} else {
				/* error */
				return -1;
			}
		} else if (nread == 0) {
			/* EOF */
			break;
		} else {
			/* read content */
			nleft -= nread;
			bufp += nread;
		}
	}
	return (n - nleft);
}

ssize_t
writen(int fd, void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nwritten;
	char *bufp = usrbuf;

	while ((nwritten = write(fd, bufp, nleft)) <= 0) {
		if (errno == EINTR) {
			/* interrupt by signal */
			nwritten = 0;
		} else {
			/* error  */
			return -1;
		}

		nleft -= nwritten;
		bufp += nwritten;
	}
	return n;
}

static int
if_setsockopt_mcast_all(sa_family_t family, int *sd)
{
#ifndef IP_MULTICAST_ALL /* Since Linux 2.6.31 */
	return -1;
#else
	int ret;
	unsigned char no = 0;

	if (*sd < 0) {
		return -1;
	}

	if (family == AF_INET6) {
		return *sd;
	}
	
	/* Don't accept multicast packets we haven't requested */
	ret = setsockopt(*sd, IPPROTO_IP, IP_MULTICAST_ALL, &no, sizeof(no));
	if (ret < 0) {
		log_message(LOG_INFO,
			"cant set IP_MULTICAST_ALL IP option.errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
#endif
}

static int
if_setsockopt_hdrincl(int *sd)
{
	int ret = 0;
	int on = 1;

	if (*sd < 0)
		return -1;

	ret = setsockopt(*sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set HDRINCL IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

static int
if_setsockopt_bindtodevice(int *sd, const char *devname)
{
	int ret;

	if (*sd < 0) {
		return -1;
	}

	ret = setsockopt(*sd, SOL_SOCKET, SO_BINDTODEVICE,
		devname, (socklen_t)strlen(devname) + 1);
	if (ret < 0) {
		log_message(LOG_INFO, 
			"cant bind to device '%s'. errno=%d.(try to run it as root)",
			devname, errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
open_send_socket(sa_family_t family, int proto, const char *devname)
{
	int fd = -1;

	if (family != AF_INET && family != AF_INET6) {
		log_message(LOG_INFO, "Cant open raw socket, unknown family=%d",
			family);
		return -1;
	}

	fd = socket(family, SOCK_RAW, proto);
	if (fd < 0) {
		log_message(LOG_INFO, "can't open raw socket, errno=%d", errno);
		return -1;
	}

	if (family == AF_INET) {
		if_setsockopt_mcast_all(family, &fd);
		if_setsockopt_hdrincl(&fd);
		if (devname != NULL && strcmp(devname, "")) {
			if_setsockopt_bindtodevice(&fd, devname);
		}
	}

	if (fd < 0)
		return -1;
	return fd;
}

int
open_read_socket(sa_family_t family, int proto, const char *devname)
{
	int fd = -1;

	if (family != AF_INET && family != AF_INET6) {
		log_message(LOG_INFO, "Cant open raw socket, unknown family=%d",
			family);
		return -1;
	}

	fd = socket(family, SOCK_RAW, proto);
	if (fd < 0) {
		log_message(LOG_INFO, "can't open raw socket, errno=%d", errno);
		return -1;
	}

	if (family == AF_INET) {
		if_setsockopt_mcast_all(family, &fd);
	}

	if (devname != NULL && strcmp(devname, "")) {
		if_setsockopt_bindtodevice(&fd, devname);
	}

	if (fd < 0)
		return -1;
	
	return fd;
}

