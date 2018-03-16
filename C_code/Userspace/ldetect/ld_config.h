#ifndef _LD_CONFIG_H_
#define _LD_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "thread.h"
#include "list.h"

#define LDETECT_CONFIG_FILE	"/etc/ldetect/config.json"
#define LDETECT_CONFIG_TMP_FILE	"/etc/ldetect/config_tmp.json"
/* Just for debug */
#define LDETECT_CONFIG_DBG_FILE	"/etc/ldetect/config_dbg.json"


/* default listen tcp port to receive configure  */
#define DEFAULT_LISTEN_PORT	8002

#define IF_NAME_LEN	16
#define IP_LEN		16
#define MAC_ADDR_LEN	18
#define BUF_LEN		1024
#define MAX_RECV_LEN	4096
#define MAX_SEND_LEN	4096

typedef enum ld_msg_type {
	/* report stats */
	REPORT_DETECT_STATUS_TYPE = 0,
	/* Ack config msg */
	ACK_CONFIG_TYPE,
	/* modify management config*/
	MOD_MGT_CONFIG_TYPE,
	/* add global config */
	ADD_GLOBAL_CONFIG_TYPE,
	DEL_GLOBAL_CONFIG_TYPE,
	MOD_REPORT_SERV_CONFIG_TYPE,
	ENABLE_REPORT_CONFIG_TYPE,
	DISABLE_REPORT_CONFIG_TYPE,
	ADD_DETECT_CONFIG_TYPE,
	MOD_DETECT_CONFIG_TYPE,
	DEL_DETECT_CONFIG_TYPE,

	MAX_CONFIG_TYPE
} ld_msg_type_t;

enum {
	REPORT_IS_DISABLE = 0,
	REPORT_IS_ENABLE
};

typedef enum _ld_proto_type {
	LD_PROTO_ICMP = 0,
	LD_PROTO_TCP,
	LD_PROTO_UDP,

	LD_PROTO_MAX
} ld_proto_type_t;

struct os_interface {
	struct list_head node;
	char eth_name[IF_NAME_LEN];
};

struct msg_hdr {
	ld_msg_type_t msg_type;
	uint32_t len;
	char msg_data[0];
};

typedef struct _ld_if {
	struct list_head node;
	char eth_name[IF_NAME_LEN];
	char ipaddr[IP_LEN];
	uint32_t prefix;
	char static_route[IP_LEN];
} ld_if_t;

typedef struct _ld_mgt {
	ld_if_t mgt_if;
	uint16_t port;
} ld_mgt_t;

typedef struct _ld_report_cfg {
	char serv_addr[IP_LEN];
	uint32_t interval;
	uint16_t udp_port;
	uint16_t is_report;
} ld_report_cfg_t;

typedef struct _ld_detect_cfg {
	uint32_t id;
	ld_proto_type_t protocol;
	char src_ip[IP_LEN];
	char dst_ip[IP_LEN];
	uint16_t src_port;
	uint16_t dst_port;
	int interval;
	int retry_times;	
} ld_detect_cfg_t;

typedef struct _ld_detect_node {
	int fd_in;
	int fd_out;
	thread_t *read;
	thread_t *write;
	thread_t *timeout;
} ld_detect_node_t;

typedef struct _ld_detect {
	struct list_head node;
	ld_detect_cfg_t cfg;
	ld_detect_node_t detect_node;
	uint32_t status;
} ld_detect_t;

typedef struct _ld_global_cfg {
	ld_mgt_t mgt;
#if 0	
	struct list_head os_if_list;
	struct list_head ld_if_list;
#endif	
	ld_report_cfg_t report;
	struct list_head detect_list;
	uint32_t detect_num;
} ld_global_cfg_t;

/* global config variable*/
extern ld_global_cfg_t global_cfg;
#if 0
extern struct rte_handle_json_item if_cfg_item[];
#endif
#if 0
extern struct rte_handle_json_item ldetect_config_item[];
extern struct rte_handle_json_item report_cfg_item[]; 
#endif
extern int parse_mgt_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg);
extern int parse_global_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg);
extern int parse_mod_report_serv_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg);
extern int parse_able_report_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg);
extern int parse_detect_cfg_msg(int sock, ld_msg_type_t type, struct msg_hdr *msg);
extern int ldetect_init(void);

#ifdef __cplusplus
}
#endif

#endif /* LD_CONFIG_H END */
