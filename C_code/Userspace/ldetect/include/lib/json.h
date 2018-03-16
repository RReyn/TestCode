#ifndef _JSON_H_
#define _JSON_H_

#include "common.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

enum json_type {
	JSON_NULL,
	JSON_FALSE,
	JSON_TRUE,
	JSON_INTEGER,
	JSON_FLOAT,
	JSON_STRING,
	JSON_OBJECT,
	JSON_ARRAY,
};

typedef struct rte_json {
	struct rte_json *next, *prev;
	struct rte_json *member;
	enum json_type type;
	char *name;
	union {
		char *val_str;	
		long val_int;
		float val_flt;
	} u;
} rte_json_t;

enum {
	JSON_WITHOUT_FORMAT,
	JSON_WITH_FORMAT,
};

struct rte_handle_json_item {
	char *item_name;
	int (*handle)(rte_json_t *, void *);
};

extern rte_json_t *new_json_item(void);
extern rte_json_t *rte_parse_json(const char *str);
extern int rte_destroy_json(rte_json_t *json);
extern int rte_traverse_json(rte_json_t *json);
extern char *rte_serialize_json(rte_json_t *json, int fmt);
extern int rte_persist_json(char *buf, rte_json_t *json, int fmt);
extern int rte_array_get_size(rte_json_t *array);
extern rte_json_t *rte_array_get_item(rte_json_t *array, int idx);
extern int rte_array_add_item(rte_json_t *array, rte_json_t *item);
extern int rte_array_del_item(rte_json_t *array, int idx);
extern rte_json_t *rte_object_get_item(rte_json_t *object, const char *name);
extern int rte_object_add_item(rte_json_t *object,
		const char *name, rte_json_t *item);
extern int rte_object_del_item(rte_json_t *object, const char *name);

static inline int
rte_handle_json(rte_json_t *object, struct rte_handle_json_item *array,
		unsigned int array_len, void *arg)
{
	unsigned int i;
	rte_json_t *item;
	int ret = 0;

	if (array == NULL || object == NULL)
		return -1;

	for (i = 0; i < array_len; i++) {
		if (array[i].item_name == NULL ||
			!strcmp(array[i].item_name, "")) {
			continue;
		}
		item = rte_object_get_item(object, array[i].item_name);
		if (item == NULL) {
			log_message(LOG_ERR, "Failed to parse '%s'",
					array[i].item_name);
			continue;
		}
		if (array[i].handle) {
			ret = array[i].handle(item, arg);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* JSON_H END */
