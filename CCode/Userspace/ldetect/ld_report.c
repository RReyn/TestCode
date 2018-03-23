#include <list.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "common.h"
#include "ld_config.h"
#include "ld_report.h"
#include "log.h"
#include "timer.h"

ld_report_sock_t *report_sock = NULL;

static uint64_t
ntohll(uint64_t val)
{
	if (__BYTE_ORDER == __LITTLE_ENDIAN) {
		return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
	}
	return val;
}

static void inline
build_report_data(ld_report_item_t *item, ld_detect_t *detect)
{
	item->id = detect->cfg.id;
	item->saddr = (uint32_t)inet_addr(detect->cfg.src_ip);
	item->daddr = (uint32_t)inet_addr(detect->cfg.dst_ip);
	item->sport = detect->cfg.src_port;
	item->dport = detect->cfg.dst_port;
	item->status = detect->status;
}

static void inline
send_report_msg(ld_report_hdr_t *header, uint32_t count, int len)
{
	struct timeval report_time;
	int send_len = -1;

	/* get the current time */
	gettimeofday(&report_time, NULL);

	header->msg_type = REPORT_DETECT_STATUS_TYPE;
	header->version = 0;
	header->item_count = ntohl(count);
	header->report_time = ntohll(report_time.tv_sec);

	report_sock->send_len = len + sizeof(ld_report_hdr_t);

	log_message(LOG_DEBUG, "Send '%d' length message.",
			report_sock->send_len);
	send_len = sendto(report_sock->sockfd, (void *)report_sock->report_buf,
			report_sock->send_len, 0,
			(struct sockaddr *)&report_sock->serv,
			sizeof(report_sock->serv));
	if (send_len < 0) {
		log_message(LOG_ERR, "Sendto error: '%d': '%s'.", errno,
			strerror(errno) ? strerror(errno): "unknown error");
	}
	memset(report_sock->report_buf, 0, REPORT_MSG_LEN);
}

static int
_ldetect_report_status(thread_t *thread)
{
	uint32_t detect_count = 0;
	int len = 0;
	ld_report_hdr_t *header = (ld_report_hdr_t *)report_sock->report_buf;
	ld_report_item_t *item = (ld_report_item_t *)header->data;
	ld_detect_t *detect = NULL;

	assert(report_sock != NULL);
	assert(report_sock->report_buf != NULL);

	if (unlikely(report_sock->sockfd <= 0)) {
		report_sock->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (report_sock->sockfd < 0) {
			log_message(LOG_ERR, "Create report status socket failed.");
			goto out;
		}
	}

	list_for_each_entry(detect, &global_cfg.detect_list, node) {
		build_report_data(item, detect);	
		len += sizeof(ld_detect_t);
		item++;
		detect_count++;
		if (detect_count >= MAX_REPORT_ITEM) {
			send_report_msg(header, detect_count, len);
			len = 0;
			detect_count = 0;
			item = (ld_report_item_t *)header->data;
		}
	}
	if (detect_count > 0) {
		send_report_msg(header, detect_count, len);
	}
#if 0
	log_message(LOG_INFO, "Report_sock interval: %d.", report_sock->interval);
#endif

out:
	thread_add_timer(thread->master, _ldetect_report_status,
			NULL, report_sock->interval * TIMER_HZ);
	return 0;
}

static int
ldetect_report_init(void)
{
	/* report_sock should be NULL now*/
	if (report_sock != NULL) {
		log_message(LOG_ERR, "report_sock not NULL.");
		return -1;
	}
	report_sock = (ld_report_sock_t *)malloc(sizeof(ld_report_sock_t));
	if (report_sock == NULL) {
		log_message(LOG_ERR, "Malloc report socket failed.");
		return -1;
	}
	memset(report_sock, 0, sizeof(ld_report_sock_t));
	/* create report status socket */
	report_sock->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (report_sock->sockfd < 0) {
		log_message(LOG_ERR, "Create report socket failed.");	
		goto socket_err;
	}
	/* alloc report message buffer */
	report_sock->report_buf = (char *)malloc(REPORT_MSG_LEN);
	if (report_sock->report_buf == NULL) {
		log_message(LOG_ERR, "Alloc report message buffer failed.");
		goto msg_err;
	}
	memset(report_sock->report_buf, 0, REPORT_MSG_LEN);
	/* initial report socket server */
	report_sock->serv.sin_family = AF_INET;
	report_sock->serv.sin_port = htons(global_cfg.report.udp_port);
	report_sock->serv.sin_addr.s_addr =
		inet_addr(global_cfg.report.serv_addr);
	report_sock->interval = global_cfg.report.interval;
#if 0
	log_message(LOG_INFO, "report_sock->interval: %d.", report_sock->interval);
#endif

	return 0;
msg_err:
	close(report_sock->sockfd);
socket_err:
	FREE(report_sock);
	return -1;
}

static void
ldetect_report_uninit(void)
{
	if (unlikely(report_sock == NULL)) {
		log_message(LOG_INFO, "report_sock is NULL.");
		return;
	}
	if (likely(report_sock->sockfd > 0)) {
		close(report_sock->sockfd);
	}
	FREE(report_sock->report_buf);
	FREE(report_sock);
}

/*
 * reconfig ldetect report config after modify the configure by user
 */
int
ldetect_report_reconfig(void)
{
	/* release old configure memory */
	ldetect_report_uninit();
	/* reinit the report configure */
	if (ldetect_report_init() < 0) {
		log_message(LOG_ERR, "ldetect_report_init failed.");
		return -1;
	}
	return 0;
}

int
ldetect_report_status(void)
{
	if (ldetect_report_init() < 0) {
		log_message(LOG_ERR, "ldetect_report_init failed.");
		return -1;
	}
	thread_add_timer(master, _ldetect_report_status,
			NULL, report_sock->interval * TIMER_HZ);
	return 0;
}

