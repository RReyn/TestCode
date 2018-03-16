#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "io_wrapper.h"
#include "ld_config.h"
#include "json.h"
#include "thread.h"
#include "ld_recv.h"

static char *recv_buffer = NULL;
#if 0
static rte_json_t * 
parse_json_wrapper(const char *buf)
{
	rte_json_t *json = NULL;

	json = rte_parse_json(buf);	
	if (json == NULL) {
		log_message(LOG_ERR, "Failed to parse add if config msg.");
		return NULL;
	}
	if (json->type != JSON_OBJECT) {
		log_message(LOG_ERR, "Error json format.");
		return NULL;
	}
	return json;
}

static rte_json_t *
parse_json2item_wrapper(const char *buf, rte_json_t **json,  const char *arg)
{
	rte_json_t *item = NULL;

	*json = parse_json_wrapper(buf);
	if (*json == NULL)
		return NULL;

	item = rte_object_get_item(*json, arg);
	if (item == NULL) {
		log_message(LOG_ERR, "Failed to get if_cfg item.");
		rte_destroy_json(*json);
		return NULL;
	}
	return item;
}

static int
parse_mgt_cfg_msg(int sock, int type, struct msg_hdr *msg)
{
	return 0;
}

static int
parse_global_cfg_msg(int sock, int type,  struct msg_hdr *msg)
{
	return 0;
}

static ld_if_t *
parse_json2ld_if(rte_json_t *entry)
{
	ld_if_t *if_cfg = NULL;	

	if_cfg = (ld_if_t *)malloc(sizeof(ld_if_t));
	if (if_cfg == NULL) {
		log_message(LOG_ERR, "Malloc interface config error.");
		return NULL;
	}
	memset(if_cfg, 0, sizeof(ld_if_t));
	INIT_LIST_HEAD(&if_cfg->node);

	if (rte_handle_json(entry, if_cfg_item,
		ARRAY_SIZE(if_cfg_item), (void *)if_cfg) != 0) {
		log_message(LOG_ERR, "parse interface config error.");
		FREE(if_cfg);
		return NULL;
	}
	return if_cfg;
}

static int
parse_if_cfg_msg(int sock, int type, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL, *entry = NULL;
	int if_cfg_num = 0, i = 0;
	ld_if_t *if_cfg = NULL, *if_cfg_tmp = NULL, *tmp = NULL;
	int ret = 1;

	item = parse_json2item_wrapper(msg->data, &json, "if_cfg");
	if (item == NULL) {
		return ret;
	}
	if (item->type != JSON_ARRAY) {
		log_message(LOG_ERR, "Invalid json type of if_cfg.");
		goto out;
	}

	if_cfg_num = rte_array_get_size(item);
	for (i = 0; i < if_cfg_num; i++) {
		entry = rte_array_get_item(item, i);
		if (entry == NULL) {
			log_message(LOG_ERR, "Failed to get item '%d'", i);
			goto out;
		}

		if_cfg = parse_json2ld_if(entry);
		if (if_cfg == NULL) {
			goto out;
		}
		switch (type) {
		case DEL_IF_CONFIG_TYPE:
			list_for_each_entry_safe(if_cfg_tmp,
					tmp, &global_cfg.ld_if_list, node) {
				if (strncmp(if_cfg->eth_name,
					if_cfg_tmp->eth_name, IF_NAME_LEN) == 0) {
					list_del(&if_cfg_tmp->node);
					FREE(if_cfg_tmp);
				}
			}
			break;
		case ADD_IF_CONFIG_TYPE:
			list_add(&if_cfg->node, &global_cfg.ld_if_list);
			break;
		case MOD_IF_CONFIG_TYPE:
			list_for_each_entry_safe(if_cfg_tmp,
					tmp, &global_cfg.ld_if_list, node) {
				if (strncmp(if_cfg->eth_name,
					if_cfg_tmp->eth_name, IF_NAME_LEN) == 0) {
					list_del(&if_cfg_tmp->node);
					FREE(if_cfg_tmp);
				}
			}
			list_add(&if_cfg->node, &global_cfg.ld_if_list);
			break;
		}
	}
	ret = 0;
out:
	rte_destroy_json(json);
	return ret;
}

static int
parse_del_all_if_cfg_msg(int sock, int type UNUSED, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL;
	int ret = 1, options = 0;
	ld_if_t *if_cfg = NULL, *tmp = NULL;

	item = parse_json2item_wrapper(msg->data, &json, "options");
	if (item == NULL) {
		return ret;
	}

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of options");
		goto out;
	}

	options = item->u.val_int;
	if (options == 0) {
		ret = 0;
		goto out;
	}

	list_for_each_entry_safe(if_cfg, tmp, &global_cfg.ld_if_list, node) {
		list_del(&if_cfg->node);
		FREE(if_cfg);
	}
	ret = 0;

out:
	rte_destroy_json(json);
	return ret;
}
#endif
#if 0
static int
parse_mod_report_serv_cfg_msg(int sock,
		int type UNUSED, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL;
	int ret = 1;
	ld_report_cfg_t *report = NULL;

	item = parse_json2item_wrapper(msg->data, &json, "report_cfg");
	if (item == NULL) 
		return ret;

	if (item->type != JSON_OBJECT) {
		log_message(LOG_ERR, "Invalid json type of report_cfg");
		goto out;
	}

	report = (ld_report_cfg_t *)malloc(sizeof(ld_report_cfg_t));
	if (report == NULL) {
		log_message(LOG_ERR, "Alloc report struct failed.");
		goto out;
	}

	ret = rte_handle_json(item, report_cfg_item,
			ARRAY_SIZE(report_cfg_item), report);
	if (ret < 0) {
		ret = 1;
		log_message(LOG_ERR, "handle report json failed.");
		goto err;
	}

	strncpy(global_cfg.report.serv_addr, report.serv_addr, IP_LEN);
	global_cfg.report.interval = report.interval;
	global_cfg.report.udp_port = report.udp_port;
	global_cfg.report.is_report = report.is_report;

	ret = 0;
err:
	FREE(report);
out:
	rte_destroy_json(json);
	return ret;
}

static int
parse_able_report_cfg_msg(int sock,
		int type UNUSED, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL;
	int ret =1;
	int options = 0;

	item = parse_json2item_wrapper(msg->data, &json, "options");
	if (item == NULL) {
		return ret;
	}
	if (item->type != JSON_INTEGER) {
		log_message("Invlaid json type of options.");
		goto out;
	}

	options = item->u.val_int;
	global_cfg.report.is_report = options;

	ret = 0;
out:
	rte_destroy_json(json);
	return ret;
}

static ld_detect_t *
parse_json2ld_detect(rte_json_t *entry)
{
	ld_detect_t *detect = NULL;	

	detect = (ld_detect_t *)malloc(sizeof(ld_detect_t));
	if (detect == NULL) {
		log_message(LOG_ERR, "Alloc detect config error.");
		return NULL;
	}
	memset(detect, 0, sizeof(ld_detect_t));
	INIT_LIST_HEAD(&detect->node);

	if (rte_handle_json(entry, detect_list_item,
		ARRAY_SIZE(detect_list_item), (void *)detect) != 0) {
		log_message(LOG_INFO, "parse detect config error.");
		FREE(detect);
		return NULL;
	}
	return detect;
}

static int
parse_detect_cfg_msg(int sock, int type, struct msg_hdr *msg)
{
	int ret = 1;
	rte_json_t *json = NULL, *item = NULL, *entry = NULL;
	int detect_num = 0, i = 0;
	ld_detect_t *detect = NULL, *detect_node = NULL, *tmp = NULL;

	item = parse_json2item_wrapper(msg->data, &json, "detect_list");
	if (item == NULL)
		return ret;

	if (item->type != JSON_ARRAY) {
		log_message(LOG_INFO, "Invalid json type of detect_list.");
		goto out;
	}

	detect_num = rte_array_get_size(item);

	for (i = 0; i < detect_num; i++) {
		entry = rte_array_get_item(item, i);			
		if (entry == NULL) {
			log_message(LOG_INFO, "Failed to get item '%d'", i);
			goto out;
		}
		detect = parse_json2ld_detect(entry);
		if (detect == NULL) {
			goto out;
		}
		switch (type) {
		case ADD_DETECT_CONFIG_TYPE:	
			list_for_each_entry(detect_node,
					&global_cfg.detect_list, node) {
				if (detect->cfg.id == detect_node->cfg.id) {
					log_message(LOG_INFO,
						"detect id '%d' exist.", detect->cfg.id);
					FREE(detect);
					break;
				}
			}
			list_add(&detect->node, &global_cfg.detect_list);
			/* init the detect node and create the thread */
			detect_node_entry_init(detect);
			break;
		case MOD_DETECT_CONFIG_TYPE:			
			list_for_each_entry_safe(detect_node, tmp,
					&global_cfg.detect_list, node) {
				if (detect->cfg.id == detect_node->cfg.id) {
					/* cancle all the old detect thread */
					detect_node_thread_cancle(detect_node);
					list_del(&detect_node->node);
					FREE(detect_node);
				}
			}
			list_add(&detect->node, &global_cfg.detect_list);
			/* init the detect node and create the thread */
			detect_node_entry_init(detect);
			break;
		case DEL_DETECT_CONFIG_TYPE:
			list_for_each_entry_safe(detect_node, tmp,
					&global_cfg.detect_list, node) {
				if (detect->cfg.id == detect_node->cfg.id) {
					list_del(&detect_node->node);
					FREE(detect_node);
				}
			}
			FREE(detect);
			break;
		}
	}
	ret = 0;
out:
	rte_destroy_json(json);
	return ret;
}
#endif

static int
response_config_msg(int sock, int ret_value, void *arg UNUSED)
{
	int len = 0;
	char buf[MAX_RECV_LEN] = "";
	struct msg_hdr *msg = (struct msg_hdr *)buf;
	rte_json_t *root = NULL, *item = NULL;
	int ret = -1;

	root = new_json_item();
	if (root == NULL) {
		log_message(LOG_ERR, "Alloc new json item failed.");
		return -1;
	}
	root->type = JSON_OBJECT;

	item = new_json_item();
	if (item == NULL) {
		log_message(LOG_ERR, "Alloc new json item failed.");
		goto out;
	}
	item->type = JSON_INTEGER;
	item->u.val_int = ret_value;
	rte_object_add_item(root, "result", item);

	len = rte_persist_json(msg->msg_data, root, JSON_WITHOUT_FORMAT);
	if (len <= 0) {
		log_message(LOG_ERR, "Failed to persist json to buffer.");	
		goto out;
	}
	msg->len = len + sizeof(struct msg_hdr);
	msg->msg_type = ACK_CONFIG_TYPE;

	ret = writen(sock, msg, msg->len);
	if (ret < 0) {
		log_message(LOG_ERR, "Failed to send response msg.");
		goto out;
	}
	ret = 0;
out:
	rte_destroy_json(root);
	return ret;
}

static struct msg_handler msg_handler[] = {
	{MOD_MGT_CONFIG_TYPE, parse_mgt_cfg_msg, response_config_msg},
	{ADD_GLOBAL_CONFIG_TYPE, parse_global_cfg_msg, response_config_msg},
	{DEL_GLOBAL_CONFIG_TYPE, parse_global_cfg_msg, response_config_msg},
#if 0	
	{ADD_IF_CONFIG_TYPE, parse_if_cfg_msg, response_config_msg},
	{MOD_IF_CONFIG_TYPE, parse_if_cfg_msg, response_config_msg},
	{DEL_IF_CONFIG_TYPE, parse_if_cfg_msg, response_config_msg},
	{DEL_ALL_IF_CONFIG_TYPE, parse_del_all_if_cfg_msg, response_config_msg},
#endif	
	{MOD_REPORT_SERV_CONFIG_TYPE, parse_mod_report_serv_cfg_msg, response_config_msg},
	{ENABLE_REPORT_CONFIG_TYPE, parse_able_report_cfg_msg, response_config_msg},
	{DISABLE_REPORT_CONFIG_TYPE, parse_able_report_cfg_msg, response_config_msg},
	{ADD_DETECT_CONFIG_TYPE, parse_detect_cfg_msg, response_config_msg},
	{MOD_DETECT_CONFIG_TYPE, parse_detect_cfg_msg, response_config_msg},
	{DEL_DETECT_CONFIG_TYPE, parse_detect_cfg_msg, response_config_msg},
};

static void
ldetect_store_config(void)
{
	FILE *fp = NULL;
	ld_detect_t *detect_node = NULL;
	int flag = 1;

	fp = fopen(LDETECT_CONFIG_TMP_FILE, "w");
	if (fp == NULL) {
		log_message(LOG_ERR, "Open file '%s' failed.");
		return;
	}
	fprintf(fp, "{");
	/* store mgt config begin */
	fprintf(fp, "\"mgt_cfg\":{");
	fprintf(fp, "\"eth_name\":\"%s\",", global_cfg.mgt.mgt_if.eth_name);
	fprintf(fp, "\"ipaddr\":\"%s\",", global_cfg.mgt.mgt_if.ipaddr);
	fprintf(fp, "\"prefix\":%u,", global_cfg.mgt.mgt_if.prefix);
	fprintf(fp, "\"gateway\":\"%s\",", global_cfg.mgt.mgt_if.static_route);
	fprintf(fp, "\"tcp_port\": %u},", global_cfg.mgt.port);
	/* store mgt config end */
	/* store report_cfg config begin */
	fprintf(fp, "\"report_cfg\":{");
	fprintf(fp, "\"server_ip\":\"%s\",", global_cfg.report.serv_addr);
	fprintf(fp, "\"udp_port\":%u,", global_cfg.report.udp_port);
	fprintf(fp, "\"interval\":%u,", global_cfg.report.interval);
	fprintf(fp, "\"is_report\":%u},", global_cfg.report.is_report);
	/* store report_cfg config end */
	/* store detect_list config begin */
	fprintf(fp, "\"detect_list\":[");
	list_for_each_entry(detect_node, &global_cfg.detect_list, node) {
		if (flag == 1) {
			fprintf(fp, "{");
			flag = 0;
		} else {
			fprintf(fp, ",{");
		}
		fprintf(fp, "\"id\":%u,", detect_node->cfg.id);
		fprintf(fp, "\"protocol\":\"%s\",",
			(detect_node->cfg.protocol == LD_PROTO_ICMP) ? "icmp": 
			((detect_node->cfg.protocol == LD_PROTO_TCP) ? "tcp" : "udp"));
		fprintf(fp, "\"src_ip\":\"%s\",", detect_node->cfg.src_ip);
		fprintf(fp, "\"dst_ip\":\"%s\",", detect_node->cfg.dst_ip);
		fprintf(fp, "\"src_port\":%u,", detect_node->cfg.src_port);
		fprintf(fp, "\"dst_port\":%u,", detect_node->cfg.dst_port);
		fprintf(fp, "\"interval\":%u,", detect_node->cfg.interval);
		fprintf(fp, "\"retry_times\":%u}", detect_node->cfg.retry_times);
	}
	fprintf(fp, "]");
	/* store detect_list config end */
	fprintf(fp, "}");
	fclose(fp);
	/* just for debug */
	rename(LDETECT_CONFIG_FILE, LDETECT_CONFIG_DBG_FILE);
	/* replace the filename */
	rename(LDETECT_CONFIG_TMP_FILE, LDETECT_CONFIG_FILE);
	return;
}

static int
ldetect_parse_msg(thread_t *thread)
{
	int sock = THREAD_FD(thread);
	int read_len = 0;
	struct msg_hdr *msg = NULL;
	int ret = 0, i = 0;
#if 0
	unsigned long timeout = 1;
#endif

	log_message(LOG_INFO, "In function '%', socket=%d.",
			__FUNCTION__, sock);

	read_len = readn(sock, recv_buffer, MAX_RECV_LEN);
	if (read_len < 0) {
		log_message(LOG_ERR, "Receive error.");
		close(sock);
		memset(recv_buffer, 0, MAX_RECV_LEN);
		return -1;
	}

	msg = (struct msg_hdr *)recv_buffer;
	if (read_len < msg->len) {
		log_message(LOG_DEBUG,
			"Receive not compelete: msg.len = %d, read.len = %d",
			msg->len, read_len);
		goto out;
	}

	if (msg->msg_type < ACK_CONFIG_TYPE 
			|| msg->msg_type >= MAX_CONFIG_TYPE) {
		response_config_msg(sock, INVALID_MSG, NULL);
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(msg_handler); i++) {
		if (msg->msg_type == msg_handler[i].type) {
			ret = msg_handler[i].handler(sock, msg->msg_type, msg);
			msg_handler[i].response(sock, ret, NULL);
		}
	}

	if (!ret) {
		ldetect_store_config();
	}
out:
	memset(recv_buffer, 0, MAX_RECV_LEN);
	thread_add_read(thread->master, ldetect_parse_msg, NULL, sock, TIMER_NEVER);
	return 0;
}

static int
ldetect_listen_func(thread_t *thread)
{
	int sock = THREAD_FD(thread);
	int accept_sock;
	int client_len;
	struct sockaddr_in client;
#if 0
	unsigned long time_out = 1;
#endif

	memset(&client, 0, sizeof(client));
	client_len = sizeof(client);

	accept_sock = accept(sock,
			(struct sockaddr *)&client, (socklen_t *)&client_len);
	if (accept_sock < 0) {
		log_message(LOG_ERR, "Accept error.");
		goto listen_end;
	}

	thread_add_read(thread->master, ldetect_parse_msg, NULL, accept_sock, TIMER_NEVER);
listen_end:
	thread_add_read(thread->master, ldetect_listen_func, NULL, sock, TIMER_NEVER);
	return 0;
}

static int
cfg_recv_init(void)
{
	int sock = -1;
	struct sockaddr_in serv;
#if 0
	unsigned long timeout = 1;
#endif

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		log_message(LOG_INFO, "Failed to create socket.");
		return -1;
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(global_cfg.mgt.port);

	if (bind(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
		log_message(LOG_INFO, "Failed to bind socket.");
		goto out;
	}
	if (listen(sock, 5) < 0) {
		log_message(LOG_INFO, "Failed to listen socket.");
		goto out;
	}
	
	thread_add_read(master, ldetect_listen_func, NULL, sock, TIMER_NEVER);
	return 0;
out:
	close(sock);
	return -1;
}

static int
icmp_recv_parse_func(thread_t *thread)
{
	int sock = THREAD_FD(thread);
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	struct iphdr *iph = NULL;
	struct icmphdr *icmp = NULL;
	char src_ip[IP_LEN];
	struct in_addr recv_ip;
	unsigned long timer = 0;

	memset(recv_buffer, 0, MAX_RECV_LEN);

	if (recvfrom(sock, recv_buffer, MAX_RECV_LEN, 0,
			(struct sockaddr *)&from, &from_len) < 0) {
//		log_message(LOG_INFO, "icmp recv failed.");
		goto out;
	}
	iph = (struct iphdr *)recv_buffer;
	if (iph->protocol != IPPROTO_ICMP) {
		log_message(LOG_INFO, "no icmp message, receive protocol=%d",
			iph->protocol);
		goto out;
	}
	icmp = (struct icmphdr *)(recv_buffer + sizeof(struct iphdr));
	if (icmp->type == ICMP_ECHOREPLY) {
		ld_detect_t *detect = NULL;
		
		memcpy(&recv_ip, &iph->saddr, sizeof(recv_ip));
		memcpy(src_ip, inet_ntoa(recv_ip), sizeof(src_ip));

		list_for_each_entry(detect, &global_cfg.detect_list, node) {
			if (!strcmp(detect->cfg.dst_ip, src_ip)) {
				log_message(LOG_INFO, "Recv the icmp reply from '%s'.", src_ip);
				timer = detect->cfg.interval * detect->cfg.retry_times;
				detect->status = 0;
				thread_mod_timer(detect->detect_node.timeout, timer);
				break;
			}
		}
	} else {
		log_message(LOG_INFO, "Not ICMP_ECHOREPLY message, type=%d.",
			icmp->type);
	}
out:
	thread_add_read(thread->master, icmp_recv_parse_func, NULL,
			sock, TIMER_NEVER);
	return 0;
}

static int
icmp_recv_init(void)
{
	int sock = -1;
	int flags = 0;

	sock = open_read_socket(AF_INET, IPPROTO_ICMP, NULL);
	if (sock < 0) {
		log_message(LOG_INFO, "cant create icmp receive socket.");
		return -1;
	}
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	thread_add_read(master, icmp_recv_parse_func, NULL, sock, TIMER_NEVER);
	return 0;
}

void
recv_thread_init(void)
{
	recv_buffer = (char *)malloc(MAX_RECV_LEN);
	if (!recv_buffer) {
		log_message(LOG_INFO, "Alloc receieve buffer failed.");
		return;
	}
	memset(recv_buffer, 0, MAX_RECV_LEN);

	cfg_recv_init();
	icmp_recv_init();

}

