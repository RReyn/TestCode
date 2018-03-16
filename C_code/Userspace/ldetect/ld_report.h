#ifndef _LD_REPORT_H_
#define _LD_REPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <arpa/inet.h>

#define REPORT_MSG_LEN	1400
#define MAX_REPORT_ITEM	64

typedef struct _ld_report_hdr {
	ld_msg_type_t msg_type;
	int32_t version;
	int32_t item_count;
	time_t report_time;
	char data[0];
} ld_report_hdr_t;

typedef struct _ld_report_item {
	uint32_t id;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint32_t status;
} ld_report_item_t;

typedef struct _ld_report_sock {
	int sockfd;
	struct sockaddr_in serv;
	int send_len;
	uint32_t interval;
	char *report_buf;
} ld_report_sock_t;


extern int ldetect_report_reconfig(void);
extern int ldetect_report_status(void);

#ifdef __cplusplus
}
#endif

#endif /* LD_REPORT_H END */
