#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <list.h>
#include <assert.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "common.h"
#include "ld_config.h"
#include "ld_send.h"
#include "ld_recv.h"
#include "log.h"
#include "io_wrapper.h"

char *send_buffer = NULL;

void
detect_node_thread_cancle(ld_detect_t *node)
{
	thread_cancel(node->detect_node.read);
	thread_cancel(node->detect_node.write);
	thread_cancel(node->detect_node.timeout);
	if (node->detect_node.fd_in != -1) {
		close(node->detect_node.fd_in);
		node->detect_node.fd_in = -1;
	}
	if (node->detect_node.fd_out != -1) {
		close(node->detect_node.fd_out);
		node->detect_node.fd_out = -1;
	}
}

uint16_t
in_csum(const uint16_t *addr, size_t len, uint32_t csum, uint32_t *acc)
{
	register size_t nleft = len;
	const uint16_t *w = addr;
	register uint16_t answer;
	register uint32_t sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *) w << 8);

	if (acc)
		*acc = sum;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = (~sum & 0xffff);		/* truncate to 16 bits */
	return (answer);
}

static void
detect_build_ip4(ld_detect_t *detect, char *buffer, int proto, size_t len)
{
	static int ip_id = 1;
	struct iphdr *ip = (struct iphdr *)buffer;

	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->version = 4;
	/* set tos to internet network control */
	ip->tos = 0x0;
	ip->tot_len = (uint16_t)(sizeof(struct iphdr) + len);
	ip->tot_len = htons(ip->tot_len);
	ip->id = htons(++ip_id);
	if (ip->id == htons(65535)) {
		ip->id = htons(1);
		ip_id = 1;
	}
	ip->frag_off = 0;
	ip->ttl = DETECT_TTL;
	ip->protocol = proto;
	ip->saddr = (uint32_t)inet_addr(detect->cfg.src_ip);
	ip->daddr = (uint32_t)inet_addr(detect->cfg.dst_ip);
	ip->check = in_csum((uint16_t *)ip, ip->ihl >> 2, 0, NULL);
}

static void
detect_build_icmp(ld_detect_t *detect, char *buffer)
{
	static uint16_t sequence = 0;
	struct icmphdr *icmp = (struct icmphdr *)buffer;

	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = ++sequence;
	if (icmp->un.echo.sequence == 65535) {
		icmp->un.echo.sequence = 1;
		sequence = 0;
	}
	icmp->un.echo.id = getpid();

	icmp->checksum = in_csum((uint16_t *)icmp, sizeof(struct icmphdr), 0, NULL);
}

static int
icmp_send_func(thread_t *thread)
{
	int ret = -1;
	ld_detect_t *detect = THREAD_ARG(thread);
	struct sockaddr_in dst_addr;
	ssize_t send_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
	struct iphdr *iph = (struct iphdr *)(send_buffer);
	char *icmphdr = send_buffer + sizeof(struct iphdr);

	log_message(LOG_INFO, ">>>> Begin of [%s:%d]<<<<.", __FUNCTION__, __LINE__);	
	memset(send_buffer, 0, MAX_SEND_LEN);

	detect_build_ip4(detect, (char *)iph,
			IPPROTO_ICMP, sizeof(struct icmphdr));
	detect_build_icmp(detect, icmphdr);

	memset(&dst_addr, 0, sizeof(struct sockaddr_in));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(detect->cfg.dst_ip);

	ret = sendto(detect->detect_node.fd_out, send_buffer, send_len, 0,
		(struct sockaddr *)&dst_addr, sizeof(struct sockaddr));
	if (ret != send_len) {
		log_message(LOG_INFO, "Sendto error.");
		goto out;
	}
out:
	log_message(LOG_INFO, ">>>> End of [%s:%d]<<<<.", __FUNCTION__, __LINE__);	
	thread_add_timer(thread->master,
			icmp_send_func, detect, detect->cfg.interval * TIMER_HZ);
	return 0;
}

static int
icmp_timeout_func(thread_t *thread)
{
	ld_detect_t *detect = THREAD_ARG(thread);
	unsigned long timer = detect->cfg.interval * detect->cfg.retry_times * TIMER_HZ;

	detect->status = 1;
	thread_add_timer(thread->master, icmp_timeout_func, detect, timer);
	return 0;
}

static int
icmp_send_thread_init(int *sd, ld_detect_t *node)
{
	unsigned long timer = 0;

	if (*sd < 0)
		return -1;

	node->detect_node.fd_out = *sd;
	node->detect_node.write = thread_add_timer(master,
		icmp_send_func, node, node->cfg.interval * TIMER_HZ);

	timer = node->cfg.interval * node->cfg.retry_times * TIMER_HZ;
	node->detect_node.timeout = thread_add_timer(master,
		icmp_timeout_func, node, timer);
	
	return 0;
}

static int
icmp_detect_node_entry_init(ld_detect_t *node)
{
	int fd_in, fd_out;
	fd_in = open_read_socket(AF_INET, IPPROTO_ICMP, NULL);
	fd_out = open_send_socket(AF_INET, IPPROTO_ICMP, NULL);

	if (fd_in < 0 || fd_out < 0)
		return -1;
	icmp_send_thread_init(&fd_out, node);

	return 0;
}
#if 0
static int
udp_read_func(thread_t *thread)
{
	return 0;
}
#endif

static void
detect_build_udp(ld_detect_t *detect, char *buffer, size_t len)
{
	struct udphdr *udp = (struct udphdr *)buffer;

	udp->source = htons(detect->cfg.src_port);
	udp->dest = htons(detect->cfg.dst_port);
	udp->len = htons(len); /* no data just iphdr + udphdr  */
	udp->check = 0;
#if 0
	udp->check = in_csum((uint16_t *)udp, sizeof(struct udphdr), 0, NULL);
#endif
	udp->check = in_csum((uint16_t *)udp, len, 0, NULL);
}

static int
udp_send_func(thread_t *thread)
{
	int ret = -1;
	ld_detect_t *detect = THREAD_ARG(thread);
	struct sockaddr_in dst_addr;
	ssize_t send_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 16;
	struct iphdr *iph = (struct iphdr *)(send_buffer);
	char *udphdr = send_buffer + sizeof(struct iphdr);
	char *data = send_buffer + sizeof(struct iphdr) + sizeof(struct udphdr);

	log_message(LOG_INFO, ">>>> Begin of [%s:%d]. <<<<", __FUNCTION__, __LINE__);
	memset(send_buffer, 0, MAX_SEND_LEN);

	detect_build_ip4(detect, (char *)iph,
			IPPROTO_UDP, sizeof(struct udphdr));
	detect_build_udp(detect, udphdr, sizeof(struct udphdr) + IP_LEN);
	memset(data, 'a', 16);

	memset(&dst_addr, 0, sizeof(struct sockaddr_in));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(detect->cfg.dst_port);
	dst_addr.sin_addr.s_addr = inet_addr(detect->cfg.dst_ip);

	ret = sendto(detect->detect_node.fd_out, send_buffer, send_len, 0,
		(struct sockaddr *)&dst_addr, sizeof(struct sockaddr));
	if (ret != send_len) {
		log_message(LOG_INFO, "Sendto error.");
		goto out;
	}
out:
	log_message(LOG_INFO, ">>>> End of [%s:%d]. <<<<", __FUNCTION__, __LINE__);
	thread_add_timer(thread->master,
			udp_send_func, detect, detect->cfg.interval * TIMER_HZ);
	return 0;
}

static int
udp_timeout_func(thread_t *thread)
{
	ld_detect_t *detect = THREAD_ARG(thread);
	unsigned long timer = detect->cfg.interval * detect->cfg.retry_times * TIMER_HZ;

	log_message(LOG_INFO, ">>>> Begin of [%s:%d]<<<<.", __FUNCTION__, __LINE__);	
	detect->status = 1;
	log_message(LOG_INFO, ">>>> End of [%s:%d]<<<<.", __FUNCTION__, __LINE__);	

	thread_add_timer(thread->master, udp_timeout_func, detect, timer);
	return 0;
}

static int
udp_read_thread_init(int *sd, ld_detect_t *node)
{
	struct sockaddr_in serv_addr;

	if (*sd < 0)
		return -1;

	node->detect_node.fd_in = *sd;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(node->cfg.src_port);
	serv_addr.sin_addr.s_addr = inet_addr(node->cfg.src_ip);

	if (bind(*sd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		log_message(LOG_INFO, "Init '%d' udp list error.",
				node->cfg.id);
		return -1;
	}
	node->detect_node.read = thread_add_read(master,
			udp_read_func, node, *sd, TIMER_NEVER);
	return 0;
}

static int
udp_send_thread_init(int *sd, ld_detect_t *node)
{
	unsigned long timer = 0;

	if (*sd < 0)
		return -1;

	node->detect_node.fd_out = *sd;
	node->detect_node.write = thread_add_timer(master, udp_send_func,
			node, node->cfg.interval * TIMER_HZ);

	timer = node->cfg.interval * node->cfg.retry_times * TIMER_HZ;
	node->detect_node.timeout = thread_add_timer(master, udp_timeout_func,
			node, timer);
	return 0;
}

static int
udp_detect_node_entry_init(ld_detect_t *node)
{
	int fd_in, fd_out;

	fd_in = open_read_socket(AF_INET, IPPROTO_UDP, NULL);
	fd_out = open_send_socket(AF_INET, IPPROTO_UDP, NULL);

	if (fd_in < 0 || fd_out < 0)
		return -1;

	udp_read_thread_init(&fd_in, node);
	udp_send_thread_init(&fd_out, node);

	return 0;
}

static int
tcp_detect_node_entry_init(ld_detect_t *node)
{
	return 0;
}

int
detect_node_entry_init(ld_detect_t *node)
{
	int ret;
	assert(node != NULL);

	switch (node->cfg.protocol) {
	case LD_PROTO_ICMP:
		ret = icmp_detect_node_entry_init(node);
		break;
	case LD_PROTO_TCP:
		ret = tcp_detect_node_entry_init(node);
		break;
	case LD_PROTO_UDP:
		ret = udp_detect_node_entry_init(node);
		break;
	case LD_PROTO_MAX:
		ret = -1;
		break;
	}
	return ret;
}

void
detect_list_init(void)
{
	ld_detect_t *detect_node = NULL;

	send_buffer = (char *)malloc(MAX_SEND_LEN);
	if (!send_buffer) {
		log_message(LOG_ERR, "alloc send buffer failed.");
		return;
	}
	memset(send_buffer, 0, MAX_SEND_LEN);
	list_for_each_entry(detect_node, &global_cfg.detect_list, node) {
		detect_node_entry_init(detect_node);
	}
}
