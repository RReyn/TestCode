#ifndef _IO_WRAPPER_H_
#define _IO_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

extern ssize_t readn(int fd, void *usrbuf, size_t n);
extern ssize_t writen(int fd, void *usrbuf, size_t n);
extern int open_send_socket(sa_family_t family,
	int proto, const char *devname);
extern int open_read_socket(sa_family_t family,
	int proto, const char *devname);
extern int set_fd_nonblock(int fd);

#ifdef __cplusplus
}
#endif

#endif /* IO_WRAPPER_H END */
