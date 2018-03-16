#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include "common.h"
#include "ld_config.h"
#include "json.h"
#include "io_wrapper.h"
#include "list.h"
#include "ld_send.h"

ld_global_cfg_t global_cfg;
#if 0
static int
get_os_interface(void)
{
	FILE *fp = NULL;
	char buffer[BUF_LEN] = ""; 	
	char *cmd = "grep ':' /proc/net/dev | awk -F':' '{print $1}'";
	struct os_interface *os_if, *n;
	char *tmp = NULL;
	struct ifreq ifr;

	fp = popen(cmd, "r");
	if (fp == NULL)
		return -1;
	while (fgets(buffer, BUF_LEN, fp) != NULL) {
		buffer[strlen(buffer) - 1] = '\0';
		tmp = buffer;	
		while (*tmp) {
			if (isspace(*tmp)) {
				tmp++;
			} else {
				break;
			}
		}
		os_if = (struct os_interface *)malloc(sizeof(struct os_interface));
		if (os_if == NULL) {
			log_message(LOG_ERR, "Malloc os interface failed.");
			goto out;
		}
		memset(os_if, 0, sizeof(struct os_interface));
		INIT_LIST_HEAD(&os_if->node);
		memcpy(os_if->eth_name, tmp, IF_NAME_LEN);
		list_add(&os_if->node, &global_cfg.os_if_list);
	}

	return 0;
out:
	if (!list_empty(&global_cfg.os_if_list)) {
		list_for_each_entry_safe(os_if, n,
				&global_cfg.os_if_list, node) {
			FREE(of_if);
		}
	}
	return -1;
}

static int
check_interface(const char *dev)
{
	struct os_interface *os_if = NULL;

	list_for_each_entry(os_if, &global_cfg.os_if_list, node) {
		if (!strcmp(os_if->eth_name, dev)) {
			return 0;
		}
	}
	return -1;
}
#endif

static int
check_ipaddr(const char *ipaddr)
{
	char *tmp, *s;
	struct in_addr in;
	int count = 0;
	int ret = -EINVAL;

	tmp = strdup(ipaddr);
	if (tmp == NULL) {
		return ret;
	}

	s = strtok(tmp, ".");
	while (s != NULL ) {
		if (strlen(s) > 3) {
			goto out;
		}
		if (s[0] == '0' && strlen(s) != 1) {
			goto out;
		}
		count++;
		if (count > 4) {
			goto out;
		}
		s = strtok(NULL, ".");
	}

	if (inet_aton(ipaddr, &in) == 0 || in.s_addr == -1)
		goto out;
	ret = 0;
out:
	FREE(tmp);
	return ret;
}

static int
check_prefix(const uint32_t prefix)
{
	if (prefix > 32 || prefix <= 0) {
		return -EINVAL;
	}
	return 0;
}

static int
check_port(const uint16_t port)
{
	return port > 65535 ? -1 : 0;
}

static char *
read_config_file(const char *file)
{
	int fd;
	struct stat stat;
	unsigned int file_length = 0;
	char *file_buf = NULL;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		log_message(LOG_ERR, "Failed to open file '%s'.", file);
		return NULL;
	}

	memset(&stat, 0, sizeof(struct stat));
	if (fstat(fd, &stat) < 0) {
		log_message(LOG_ERR, "Failed to get file '%s' stat.", file);
		goto out;
	}

	file_length = stat.st_size;
	file_buf = (char *)malloc(file_length);
	if (file_buf == NULL) {
		log_message(LOG_ERR, "Malloc file buffer failed.\n");
		goto out;
	}
	memset(file_buf, 0, file_length);
	read(fd, file_buf, file_length);
out:
	close(fd);
	return file_buf;
}

static int
handle_mgt_eth_name(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of mgt_eth_name.");
		return -EINVAL;
	}

	strncpy(global_cfg.mgt.mgt_if.eth_name, item->u.val_str, IF_NAME_LEN);

	return 0;
}

static int
handle_mgt_ipaddr(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of mgt_ipaddr.");
		return -EINVAL;
	}
	strncpy(global_cfg.mgt.mgt_if.ipaddr, item->u.val_str, IP_LEN);

	return 0;
}

static int
handle_mgt_prefix(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of mgt prefix.");
		return -EINVAL;
	}

	global_cfg.mgt.mgt_if.prefix = item->u.val_int;

	return 0;
}

static int
handle_mgt_gateway(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of mgt_gateway.");
		return -EINVAL;
	}
	strncpy(global_cfg.mgt.mgt_if.static_route, item->u.val_str, IP_LEN);

	return 0;
}

static int
handle_mgt_tcp_port(rte_json_t *item, void *arg)
{
	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of mgt_tcp_port.");
		return -EINVAL;
	}
	global_cfg.mgt.port = item->u.val_int;

	return 0;
}

static struct rte_handle_json_item mgt_cfg_item[] = {
	{"eth_name", handle_mgt_eth_name},
	{"ipaddr", handle_mgt_ipaddr},
	{"prefix", handle_mgt_prefix},
	{"gateway", handle_mgt_gateway},
	{"tcp_port", handle_mgt_tcp_port}
};


static int
handle_mgt_cfg(rte_json_t *item, void *arg)
{
	if (item->type != JSON_OBJECT) {
		log_message(LOG_ERR, "Invalid json type of mgt_cfg.");
		return -EINVAL;
	}
	return rte_handle_json(item, mgt_cfg_item,
			ARRAY_SIZE(mgt_cfg_item), arg);
}
#if 0
static int
handle_if_eth_name(rte_json_t *item, void *arg)
{
	ld_if_t *if_cfg = (ld_if_t *)arg;

	assert(if_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of if_eth_name.");
		return -1;
	}

	strncpy(if_cfg->eth_name, item->u.val_str, IF_NAME_LEN);

	if (check_interface(if_cfg->eth_name) != 0) {
		log_message(LOG_ERR,
				"Invalid interface '%s'.", if_cfg->eth_name);
		return -1;
	}

	return 0;
}

static int
handle_if_ipaddr(rte_json_t *item, void *arg)
{
	ld_if_t *if_cfg = (ld_if_t *)arg;

	assert(if_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of if_ipaddr.");
		return -1;
	}

	strncpy(if_cfg->ipaddr, item->u.val_str, IP_LEN);
	if (check_ipaddr(if_cfg->ipaddr) != 0) {
		log_message(LOG_ERR,
				"Invalid ip address '%s'.", if_cfg->ipaddr);
		return -1;
	}
	
	return 0;
}

static int
handle_if_prefix(rte_json_t *item, void *arg)
{
	ld_if_t *if_cfg = (ld_if_t *)arg;

	assert(arg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of if_prefix.");
		return -1;
	}
	if_cfg->prefix = item->u.val_int;
	if (check_prefix(if_cfg->prefix) != 0) {
		log_message(LOG_ERR, "Invalid prefix '%d'.", if_cfg->prefix);
		return -1;
	}
	return 0;
}

static int
handle_if_static_route(rte_json_t *item, void *arg)
{
	ld_if_t *if_cfg = (ld_if_t *)arg;

	assert(if_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of if_route.");
		return -1;
	}
	strncpy(if_cfg->static_route, item->u.val_str, IP_LEN);
	if (check_ipaddr(if_cfg->static_route) != 0) {
		log_message(LOG_ERR, "Invalid ip address '%s'.",
				if_cfg->static_route);
		return -1;
	}
	return 0;
}

struct rte_handle_json_item if_cfg_item[] = {
	{"eth_name", handle_if_eth_name},
	{"ip_addr", handle_if_ipaddr},
	{"prefix", handle_if_prefix},
	{"static_route", handle_if_static_route}
};

static int
handle_if_cfg(rte_json_t *item, void *arg)
{
	int if_cfg_num = 0;
	int i = 0;
	rte_json_t *entry = NULL;
	ld_if_t *if_cfg = NULL;

	if (item->type != JSON_ARRAY) {
		log_message(LOG_ERR, "Invalid json type of if_cfg.");
		return -1;
	}

	if_cfg_num = rte_array_get_size(item);

	for (i = 0; i < if_cfg_num; i++) {
		entry = rte_array_get_item(item, i);	
		if (entry == NULL) {
			log_message(LOG_ERR, "Failed to get item '%d'.", i);
			return -1;
		}
		if_cfg = (ld_if_t *)malloc(sizeof(ld_if_t));
		if (if_cfg == NULL) {
			log_message(LOG_ERR, "Malloc interface config type error.");
			return -1;
		}
		memset(if_cfg, 0, sizeof(ld_if_t));
		INIT_LIST_HEAD(&if_cfg->node);
		if (rte_handle_json(entry, if_cfg_item,
				ARRAY_SIZE(if_cfg_item), (void *)if_cfg) != 0) {
			log_message(LOG_ERR, "Parse interface config json error.");
			FREE(if_cfg);
			return -1;
		}
		list_add(&if_cfg->node, &global_cfg.ld_if_list);
	}
	return 0;
}
#endif
static int
handle_report_server_ip(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of report serverip.");
		return -EINVAL;
	}

	strncpy(global_cfg.report.serv_addr, item->u.val_str, IP_LEN);
	if (check_ipaddr(global_cfg.report.serv_addr) != 0) {
		log_message(LOG_ERR, "Invalid report server ip address.");
		return -EINVAL;
	}

	return 0;	
}

static int
handle_report_udp_port(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of report udp port.");
		return -EINVAL;
	}

	global_cfg.report.udp_port = item->u.val_int;
	if (check_port(global_cfg.report.udp_port) != 0) {
		log_message(LOG_ERR, "Invalid report udp port.");
		return -EINVAL;
	}
	return 0;
}

static int
handle_report_interval(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of report interval.");
		return -EINVAL;
	}

	global_cfg.report.interval = item->u.val_int;

	return 0;
}

static int
handle_report_is_report(rte_json_t *item, void *arg UNUSED)
{
	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of report is_report.");
		return -EINVAL;
	}

	global_cfg.report.is_report = item->u.val_int;
	return 0;
}

struct rte_handle_json_item report_cfg_item[] = {
	{"server_ip", handle_report_server_ip},
	{"udp_port", handle_report_udp_port},
	{"interval", handle_report_interval},
	{"is_report", handle_report_is_report}
};

static int
handle_report_cfg(rte_json_t *item, void *arg)
{
	if (item->type != JSON_OBJECT) {
		log_message(LOG_ERR, "Invalid json type of report_cfg.");
		return -EINVAL;
	}

	return rte_handle_json(item, report_cfg_item,
			ARRAY_SIZE(report_cfg_item), arg);
}

static int
handle_detect_id(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of detect id.");
		return -EINVAL;
	}

	detect_cfg->cfg.id = item->u.val_int;
	return 0;
}

static int
handle_detect_protocol(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of detect id.");
		return -EINVAL;
	}

	if (!strncmp(item->u.val_str, "icmp", 4)) {
		detect_cfg->cfg.protocol = LD_PROTO_ICMP;
	} else if (!strncmp(item->u.val_str, "tcp", 3)) {
		detect_cfg->cfg.protocol = LD_PROTO_TCP;
	} else if (!strncmp(item->u.val_str, "udp", 3)) {
		detect_cfg->cfg.protocol = LD_PROTO_UDP;
	} else {
		log_message(LOG_ERR, "Invalid detect protocol.");
		return -EINVAL;
	}
	return 0;
}

static int
handle_detect_src_ip(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of detect srcip.");
		return -EINVAL;
	}

	strncpy(detect_cfg->cfg.src_ip, item->u.val_str, IP_LEN);
	if (check_ipaddr(detect_cfg->cfg.src_ip) != 0) {
		log_message(LOG_ERR, "Invalid detect src ip address.");
		return -EINVAL;
	}

	return 0;
}

static int
handle_detect_dst_ip(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of detect dstip.");
		return -EINVAL;
	}

	strncpy(detect_cfg->cfg.dst_ip, item->u.val_str, IP_LEN);
	if (check_ipaddr(detect_cfg->cfg.dst_ip) != 0) {
		log_message(LOG_ERR, "Invalid detect dst ip address.");
		return -EINVAL;
	}

	return 0;
}

static int
handle_detect_src_port(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of detect srcport.");
		return -EINVAL;
	}

	detect_cfg->cfg.src_port = item->u.val_int;
	if (check_port(detect_cfg->cfg.src_port) != 0) {
		log_message(LOG_ERR, "Invalid detect source port.");
		return -EINVAL;
	}

	return 0;
}

static int
handle_detect_dst_port(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of detect dstport.");
		return -EINVAL;
	}

	detect_cfg->cfg.dst_port = item->u.val_int;
	if (check_port(detect_cfg->cfg.dst_port) != 0) {
		log_message(LOG_ERR, "Invalid detect destination port.");
		return -EINVAL;
	}

	return 0;
}
#if 0
static int
handle_detect_dev_out(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_STRING) {
		log_message(LOG_ERR, "Invalid json type of detect dev out.");
		return -1;
	}

	strncpy(detect_cfg->dev_out, item->u.val_str, IF_NAME_LEN);;
	if (check_interface(detect_cfg->dev_out) != 0) {
		log_message(LOG_ERR, "Invalid detect out device .");
		return -1;
	}

	return 0;
}
#endif
static int
handle_detect_interval(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of detect interval.");
		return -EINVAL;
	}

	detect_cfg->cfg.interval= item->u.val_int;

	return 0;
}

static int
handle_detect_retry_times(rte_json_t *item, void *arg)
{
	ld_detect_t *detect_cfg = (ld_detect_t *)arg;

	assert(detect_cfg != NULL);

	if (item->type != JSON_INTEGER) {
		log_message(LOG_ERR, "Invalid json type of detect interval.");
		return -EINVAL;
	}

	detect_cfg->cfg.retry_times = item->u.val_int;

	return 0;
}

struct rte_handle_json_item detect_list_item[] = {
	{"id", handle_detect_id},
	{"protocol", handle_detect_protocol},
	{"src_ip", handle_detect_src_ip},
	{"dst_ip", handle_detect_dst_ip},
	{"src_port", handle_detect_src_port},
	{"dst_port", handle_detect_dst_port},
#if 0	
	{"dev_out", handle_detect_dev_out},
#endif	
	{"interval", handle_detect_interval},
	{"retry_times", handle_detect_retry_times}
};

static int
handle_detect_list(rte_json_t *item, void *arg UNUSED)
{
	int detect_list_num = 0;
	int i = 0;
	rte_json_t *entry = NULL;
	ld_detect_t *detect_cfg = NULL;

	if (item->type != JSON_ARRAY) {
		log_message(LOG_ERR, "Invalid json type of detect_list.");
		return -EINVAL;
	}

	detect_list_num = rte_array_get_size(item);

	for (i = 0; i < detect_list_num; i++) {
		entry = rte_array_get_item(item, i);	
		if (entry == NULL) {
			log_message(LOG_ERR, "Failed to get item '%d'.", i);
			return -EINVAL;
		}
		detect_cfg = (ld_detect_t *)malloc(sizeof(ld_detect_t));
		if (detect_cfg == NULL) {
			log_message(LOG_ERR, "Malloc detect config type error.");
			return -ENOMEM;
		}
		memset(detect_cfg, 0, sizeof(ld_detect_t));
		INIT_LIST_HEAD(&detect_cfg->node);
		if (rte_handle_json(entry, detect_list_item,
				ARRAY_SIZE(detect_list_item),
				(void *)detect_cfg) != 0) {
			log_message(LOG_ERR, "Parse detect list json error.");
			FREE(detect_cfg);
			return -EINVAL;
		}
		list_add(&detect_cfg->node, &global_cfg.detect_list);
		global_cfg.detect_num++;
	}
	return 0;
}

struct rte_handle_json_item ldetect_config_item[] = {
	{"mgt_cfg", handle_mgt_cfg},
#if 0		
	{"if_cfg", handle_if_cfg},
#endif
	{"report_cfg", handle_report_cfg},
	{"detect_list", handle_detect_list},
};

static int
parse_config_json(const char *json_buf)
{
	int ret = 0;
	rte_json_t *json = NULL;

	assert(json_buf);

	json = rte_parse_json(json_buf);
	if (json == NULL) {
		log_message(LOG_ERR, "Failed to get json object from json string.");
		return -EINVAL;
	}

	ret = rte_handle_json(json, ldetect_config_item,
			ARRAY_SIZE(ldetect_config_item), NULL);
	rte_destroy_json(json);
	return ret;
}

#if 1 /* Move function from ld_recv.c */
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

int
parse_mgt_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg)
{
	return 0;
}

int
parse_global_cfg_msg(int sock, ld_msg_type_t type,  struct msg_hdr *msg)
{
	return 0;
}
int
parse_mod_report_serv_cfg_msg(int sock,
		ld_msg_type_t type UNUSED, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL;
	int ret = 1;
	ld_report_cfg_t *report = NULL;

	item = parse_json2item_wrapper(msg->msg_data, &json, "report_cfg");
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

	strncpy(global_cfg.report.serv_addr, report->serv_addr, IP_LEN);
	global_cfg.report.interval = report->interval;
	global_cfg.report.udp_port = report->udp_port;
	global_cfg.report.is_report = report->is_report;

	ret = 0;
err:
	FREE(report);
out:
	rte_destroy_json(json);
	return ret;
}

int
parse_able_report_cfg_msg(int sock,
		ld_msg_type_t type UNUSED, struct msg_hdr *msg)
{
	rte_json_t *json = NULL, *item = NULL;
	int ret =1;
	int options = 0;

	item = parse_json2item_wrapper(msg->msg_data, &json, "options");
	if (item == NULL) {
		return ret;
	}
	if (item->type != JSON_INTEGER) {
		log_message(LOG_INFO, "Invlaid json type of options.");
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
int
parse_detect_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg)
{
	int ret = 1;
	rte_json_t *json = NULL, *item = NULL, *entry = NULL;
	int detect_num = 0, i = 0;
	ld_detect_t *detect = NULL, *detect_node = NULL, *tmp = NULL;

	item = parse_json2item_wrapper(msg->msg_data, &json, "detect_list");
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
		case MOD_MGT_CONFIG_TYPE:
			break;
		case ADD_GLOBAL_CONFIG_TYPE:
			break;
		case DEL_GLOBAL_CONFIG_TYPE:
			break;
		case MOD_REPORT_SERV_CONFIG_TYPE:
			break;
		case ENABLE_REPORT_CONFIG_TYPE:
			break;
		case DISABLE_REPORT_CONFIG_TYPE:
			break;
		case REPORT_DETECT_STATUS_TYPE:
		case ACK_CONFIG_TYPE:
		case MAX_CONFIG_TYPE:
		default:
			goto out;
		}
	}
	ret = 0;
out:
	rte_destroy_json(json);
	return ret;
}
#endif

static int
parse_config_file(const char *file)
{
	int ret = 0;
	char *json_buf = NULL;

	assert(file);

	json_buf  = read_config_file(file);
	if (json_buf == NULL) {
		return -1;
	}
	
	ret = parse_config_json(json_buf);
	if (ret != 0) {
		goto parse_json_error;
	}

parse_json_error:
	free(json_buf);
	return ret;
}

static int
ld_parse_config(void)
{
	if (likely(!access(LDETECT_CONFIG_FILE, F_OK))) {
		return parse_config_file(LDETECT_CONFIG_FILE);			
	}
	/* File non-existent */
	return -ENOENT;
}

static void
ldetect_config_init(void)
{
	global_cfg.mgt.port = DEFAULT_LISTEN_PORT;
#if 0	
	INIT_LIST_HEAD(&global_cfg.os_if_list);	
	INIT_LIST_HEAD(&global_cfg.ld_if_list);
#endif
	INIT_LIST_HEAD(&global_cfg.detect_list);
	global_cfg.report.is_report = REPORT_IS_DISABLE;
	global_cfg.detect_num = 0;
}

int
ldetect_init(void)
{
	int ret = 0;

	ldetect_config_init();
#if 0	
	get_os_interface();
#endif
	/* parse the json config file, and update the global_cfg */
	ret = ld_parse_config();
	if (ret != 0) {
		return ret;
	}
	return 0;
}
