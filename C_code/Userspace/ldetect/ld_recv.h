#ifndef _LD_RECV_H_
#define _LD_RECV_H_

#ifdef __cplusplus
extern "C" {
#endif

struct msg_handler {
	ld_msg_type_t type;
	int (*handler)(int, ld_msg_type_t, struct msg_hdr *);
	int (*response)(int, int, void *);
};

enum {
	PARSE_MSG_OK = 0,
	PARSE_MSG_ERR,
	INVALID_MSG,
};

extern void recv_thread_init(void);

#ifdef __cplusplus
}
#endif

#endif /* LD_RECV_H END */
