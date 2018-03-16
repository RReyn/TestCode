#include <math.h>

#include "json.h"

static const char *err_point=NULL;
static const char *json_parse_value(rte_json_t *json, const char *value);

/*
 * skip useless space and CR/LF character
 */
static inline const char *
json_skip(const char *in)
{
	while (in && *in && (unsigned char)*(in) <= 32) {
		in++;
	}
	return in;
}

rte_json_t *
new_json_item(void)
{
	rte_json_t *item = (rte_json_t *)malloc(sizeof(rte_json_t));
	if (item == NULL) {
		return NULL;
	}
	memset(item, 0, sizeof(rte_json_t));
	return item;
}

static unsigned int
parse_hex4(const char *str)
{
	unsigned int h = 0;
	unsigned int count = 0;

#define HEX_LEN	4
	while (count < HEX_LEN) {
		h = h << 4;
		if (*str >= '0' && *str <= '9') {
			h += (*str) - '0';
		} else if (*str >= 'A' && *str <= 'F') {
			h += 10 + (*str) - 'A'; 
		} else if (*str >= 'a' && *str <= 'f') {
			h += 10 + (*str) - 'a'; 
		} else {
			/* invalid */
			return 0;
		}
		str++;
		count++;

	}
	return h;
}

static const unsigned char firstByteMark[7] = 
		{ 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const char *
json_parse_string(rte_json_t *json, const char *value)
{
	const char *ptr = value + 1;
	char *ptr2 = NULL;
	char *out = NULL;
	int len = 0;
	unsigned int uc, uc2;

	if (*value != '\"') { 
		err_point = value;
		return NULL;
	}
	
	/* get the length of string */
	while (*ptr != '\"' && *ptr && ++len){
		/* Skip escaped quotes. */
		if (*ptr++ == '\\') {
			ptr++;
		}
	}
	
	out= (char *)malloc(len + 1);
	if (NULL == out) {
		return NULL;
	}
		
	ptr = value + 1;
	ptr2 = out;
	while (*ptr != '\"' && *ptr) {
		if (*ptr != '\\') {
			*ptr2++ = *ptr++;
		} else {
			ptr++;
			switch (*ptr) {
			case 'b': *ptr2++ = '\b'; break;
			case 'f': *ptr2++ = '\f'; break;
			case 'n': *ptr2++ = '\n'; break;
			case 'r': *ptr2++ = '\r'; break;
			case 't': *ptr2++ = '\t'; break;
			case 'u': /* transcode utf16 to utf8. */
				/* get the unicode char */
				uc = parse_hex4(ptr + 1);
				ptr += 4;
				/* check for invalid */
				if ((uc >= 0xDC00 && uc <= 0xDFFF)
						|| uc == 0) {
					break;	
				}
				/* UTF16 surrogate pairs */
				if (uc >= 0xD800 && uc <= 0xDBFF) {
					/* missing second-half of surrogate */
					if (ptr[1] != '\\' 
						|| ptr[2] != 'u') {
						break;	
					}
					uc2 = parse_hex4(ptr + 3);
					ptr += 6;
					/* invalid second-half of surrogate*/
					if (uc2 < 0xDC00 || uc2 > 0xDFFF) {
						break;	
					}
					uc = 0x10000 + (((uc & 0x3FF) << 10) 
							| (uc2 & 0x3FF));
				}

				len = 4;
				if (uc < 0x80) {
					len = 1;
				} else if (uc < 0x800) {
					len = 2;
				} else if (uc < 0x10000) {
					len = 3; 
				}
				ptr2 += len;
				
				switch (len) {
				case 4: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
				case 3: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
				case 2: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
				case 1: *--ptr2 =(uc | firstByteMark[len]);
				}
				ptr2 += len;
				break;
			default: 
				*ptr2++ = *ptr; 
				break;
			}
			ptr++;
		}
	}
	*ptr2 = '\0';
	if (*ptr == '\"'){
		ptr++;
	}
	json->u.val_str = out;
	json->type = JSON_STRING;
	return ptr;
}

static const char *
json_parse_number(rte_json_t *json, const char *value)
{
	float n = 0.0, sign = 1.0, scale = 0.0;
	int subscale = 0, signsubscale = 1;
	int flt_flag = 0; 
	/* negative */
	if (*value == '-') {
		sign = -1.0;
		value++;
	}
	if (*value == '0') {
		value++;
	}
	if (*value >= '1' && *value <= '9') {
		do{
			n = (n * 10.0) + (*value++ - '0');
		} while (*value >= '0' && *value <= '9'); /* Number? */
	}
	if (*value == '.' && value[1] >= '0' && value[1] <= '9') {
		flt_flag = 1;
		value++;
		do {
			n = (n * 10.0) + (*value++ - '0');
			scale--;
		} while (*value >= '0' && *value <= '9');
	}	/* Fractional part? */

	if (*value == 'e' || *value == 'E') {	/* Exponent? */
		flt_flag = 1;
		value++;
		if (*value == '+') {
			value++;
		} else if (*value == '-') {
			signsubscale = -1;
			value++;	/* With sign? */
		}
		/* Number? */
		while (*value >= '0' && *value <= '9') {
			subscale = (subscale * 10) + (*value++ - '0');
		}
	}

	/* number = +/- number.fraction * 10^+/- exponent */
	n = sign * n * pow(10.0, (scale + subscale * signsubscale));
	
	if (flt_flag) {
		json->type = JSON_FLOAT;
		json->u.val_flt = n;
	} else {
		json->type = JSON_INTEGER;
		json->u.val_int = (int)n;
	}
	return value;
}

static const char *
json_parse_array(rte_json_t *json, const char *value)
{
	rte_json_t *member = NULL;

	if (*value != '[') {
		err_point = value;
		return NULL;
	}
	json->type = JSON_ARRAY;	
	value = json_skip(value + 1);		
	/* empty array */
	if (*value==']') {
		return value + 1;
	}
	member = new_json_item();
	if (NULL == member) {
		return NULL;
	}
	json->member = member;
	value = json_skip(json_parse_value(member, json_skip(value)));
	if (NULL == value) {
		return NULL;
	}
	while (*value == ',') {
		rte_json_t *item = new_json_item();
		if (NULL == item) {
			return NULL;
		}
		member->next = item;
		item->prev = member;
		member = item;
		value = json_skip(json_parse_value(member,
					json_skip(value + 1)));
		if (NULL == value) {
			return NULL;
		}
	}
	if (*value == ']') {
		return value + 1;
	}

	err_point = value;
	return NULL;
}
/* This function has memory leak, I will resolve it later.... */
static const char *
json_parse_object(rte_json_t *json, const char *value)
{
	rte_json_t *member = NULL;	

	if (*value!='{') {
		err_point = value;
		return NULL;
	}
	json->type = JSON_OBJECT;
	value = json_skip(value+1);
	/* empty object */
	if (*value == '}') {
		return value + 1;
	}
	member = new_json_item();
	if(NULL == member) {
		return NULL;
	}
	json->member = member;
	/* get member name */
	value = json_skip(json_parse_string(member, json_skip(value)));
	if (NULL == value) {
		return NULL;
	}
	member->name = member->u.val_str;
	member->u.val_str = NULL;
	if (*value != ':') {
		err_point = value;
		return NULL;
	}
	value = json_skip(json_parse_value(member, json_skip(value + 1)));
	if (NULL == value) {
		return NULL;
	}
	while (*value == ',') {
		rte_json_t *item = new_json_item();
		if(NULL == item) {
			return NULL;
		}
		member->next = item;
		item->prev = member;
		member = item;
		/* get member name */
		value = json_skip(json_parse_string(member,
					json_skip(value + 1)));
		if(NULL == value) {
			return NULL;
		}

		member->name = member->u.val_str;
	   	member->u.val_str = NULL; 	
		if (*value != ':') {
			err_point = value;
			return NULL;
		}
		value = json_skip(json_parse_value(member,
					json_skip(value + 1)));
		if(NULL == value) {
			return NULL;
		}
	}
	if (*value == '}') {
		return value + 1;
	}
	err_point = value;
	return NULL;
}

static const char *
json_parse_value(rte_json_t *json, const char *value)
{
	if (NULL == value) {
		return NULL;
	}
	if (!strncmp(value, "null", 4)) {
		json->type = JSON_NULL;
		return value + 4;
	}
	if (!strncmp(value, "false", 5)) {
		json->type = JSON_FALSE;
		return value + 5;
	}
	if (!strncmp(value, "true", 4)) {
		json->type = JSON_TRUE;
		return value+4;
	}
	switch (*value) {
	case '\"':
		return json_parse_string(json, value);
	case '-': case '0': case '1': case '2':
	case '3': case '4': case '5': case '6':
	case '7': case '8': case '9':
		return json_parse_number(json, value);
	case '[':
		return json_parse_array(json, value);
	case '{':
		return json_parse_object(json, value);
	}

	err_point = value;
	return NULL;
}

rte_json_t *
rte_parse_json(const char *str)
{
	const char *end = NULL;
	rte_json_t *json = NULL;
	
	json = new_json_item();
	if (NULL == json) {
		return NULL;
	}
	
	end = json_parse_value(json, json_skip(str));	
	if (NULL == end) {
		rte_destroy_json(json);
		return NULL;
	}

	return json;
}

int
rte_destroy_json(rte_json_t *json)
{
	rte_json_t *next = NULL;
	while (json) {
		next = json->next;
		if (json->member) {
			rte_destroy_json(json->member);
		}	
		if (json->type == JSON_STRING) {
			free(json->u.val_str);
		}
		if (json->name) {
			free(json->name);
		}
		free(json);
		json = next;
	}
	return 0;
}

int
rte_traverse_json(rte_json_t *json)
{
	rte_json_t *next = NULL;
	while (json) {
		next = json->next;
		if (json->name) {
			printf("%s:", json->name);
		}
		if (json->member) {
			rte_traverse_json(json->member);
		}
		if (json->type == JSON_STRING) {
			printf("%s ", json->u.val_str);
		}
		if (json->type == JSON_INTEGER) {
			printf("%ld ", json->u.val_int);
		}
		if (json->type==JSON_FLOAT) {
			printf("%f ", json->u.val_flt);
		}
		json = next;
	}
	return 0;	
}

static char *
json_strdup(const char *str)
{
	int len;
	char *copy = NULL;

	len = strlen(str) + 1;
	copy = (char *)malloc(len);
	if (NULL == copy) {
		return NULL;
	}
	memset(copy, 0, len * sizeof(char));
	memcpy(copy, str, len);
	return copy;
}

static char *print_value(rte_json_t *json, int depth, int fmt);
static int persist_value(char *buf, rte_json_t *json, int depth, int fmt);

static char *
print_number(rte_json_t *json)
{
	char *str = NULL;
	str = (char *)malloc(21);	
	if (NULL == str) {
		return NULL;
	}
	memset(str, 0, 21 * sizeof(char));

	if (json->type == JSON_INTEGER) {
		sprintf(str, "%ld", json->u.val_int);
	} else if (json->type == JSON_FLOAT) {
		sprintf(str, "%f", json->u.val_flt);
	}

	return str;
}

static char *
print_string_ptr(const char *str)
{
	const char *ptr;
	char *ptr2, *out;
	int len = 0;
	unsigned char token;
	
	if (NULL == str) {
		return json_strdup("");
	}

	ptr = str;
	while ((token = *ptr) && ++len) {
		if (strchr("\"\\\b\f\n\r\t", token)) {
			len++;
		} else if (token < 32) {
			len += 5;
		}
		ptr++;
	}
	
	out = (char*)malloc(len + 3); // 3个字符存放""\0
	if (NULL == out) {
		return NULL;
	}

	ptr2 = out;
	ptr = str;
	*ptr2++ = '\"';
	while (*ptr) {
		if ((unsigned char)*ptr > 31 
				&& (*ptr != '\"') && (*ptr != '\\')) {
		   	*ptr2++ = *ptr++;
		} else {
			*ptr2++ = '\\';
			switch (token = *ptr++) {
			case '\\': *ptr2++='\\'; break;
			case '\"': *ptr2++='\"'; break;
			case '\b': *ptr2++='b';	break;
			case '\f': *ptr2++='f';	break;
			case '\n': *ptr2++='n';	break;
			case '\r': *ptr2++='r';	break;
			case '\t': *ptr2++='t';	break;
			default: 
				sprintf(ptr2, "u%04x", token);
				ptr2 += 5;
				break;	/* escape and print */
			}
		}
	}
	*ptr2++ = '\"';
	*ptr2++ = 0;
	return out;
}

static char *
print_string(rte_json_t *json)
{
	return print_string_ptr(json->u.val_str);
}

static char *
print_array(rte_json_t *json, int depth, int fmt)
{
	char **entries;
	char *out = NULL, *ptr, *value;
	int len = 5;
	int numentries = 0, i = 0, fail = 0;
	rte_json_t *item = json->member;

	/* get the member number in array */
	while (NULL != item) {
		numentries++;
		item = item->next;
	}
	/* empty array */
	if (0 == numentries) {
		out = (char *)malloc(3);
		if (NULL == out) {
			return NULL;
		}
		memset(out, 0, 3);
		strcpy(out, "[]");
		return out;
	}

	entries = (char **)malloc(numentries * sizeof(char *));
	if (NULL == entries) {
		return NULL;
	}
	memset(entries, 0, numentries * sizeof(char *));

	item = json->member;
	while ((NULL != item) && !fail) {
		value = print_value(item, depth + 1, fmt);
		entries[i++] = value;
		if (value) {
			len += strlen(value) + 2 + (fmt ? 1 : 0);
		} else {
			fail = 1;
		}
		item = item->next;
	}

	if (!fail) {
		out = (char *)malloc(len);
	}
	if (NULL == out) {
		fail = 1;
	}
	if (fail) {
		for (i = 0; i < numentries; i++) {
			if (entries[i]) {
				free(entries[i]);
			}
		}
		free(entries);
		return NULL;
	}

	*out = '[';
	ptr = out + 1;
	*ptr = '\0';
	for (i = 0; i < numentries; i++) {
		strcpy(ptr, entries[i]);
		ptr += strlen(entries[i]);
		if (i != (numentries - 1)) {
			*ptr++ = ',';
			if (fmt) {
				*ptr++ = ' ';
			}
			*ptr = '\0';
		}
		free(entries[i]);
	}
	free(entries);
	*ptr++ = ']';
	*ptr++ = '\0';
	return out;
}

static char *
print_object(rte_json_t *json, int depth, int fmt)
{
	char *out = NULL, *ptr, *name, *value;
	char **entries = NULL, **names = NULL;
	int numentries = 0;
	int len = 7; 
	int i = 0, j = 0;
	int fail = 0;
	rte_json_t *item = json->member;

	/* get the member number in object */
	while (item) {
		numentries++;
		item = item->next;
	}
	/* empty object  */
	if (0 == numentries) {
		/* malloc 4 bytes to save '{\n}\0' */
		out = (char *)malloc(fmt ? (depth + 4) : 3);
		if (NULL == out) {
			return NULL;
		}
		ptr = out;
		*ptr++ = '{';
		if (fmt) {
			*ptr++ = '\n';
			for (i = 0; i < depth - 1; i++) {
				*ptr++ = '\t';
			}
		}
		*ptr++ = '}';
		*ptr++ = '\0';
		return out;
	}

	entries = (char **)malloc(numentries * sizeof(char *));	
	if(NULL == entries) {
		return NULL;
	}
	names = (char **)malloc(numentries * sizeof(char *));
	if (NULL == names) {
		free(entries);
		return NULL;
	}
	memset(entries, 0, numentries * sizeof(char *));
	memset(names, 0, numentries * sizeof(char *));

	item = json->member;
	depth++;
	if (fmt) {
		len += depth;
	}
	while (NULL != item) {
		names[i] = name = print_string_ptr(item->name);
		entries[i] = value = print_value(item, depth, fmt);
		i++;	
		if (name && value) {
			len += strlen(name) 
				+ strlen(value) + 2 + (fmt ? (2 + depth): 0); 
		} else {
			fail = 1;
		}
		item = item->next;
	}
	if (0 == fail) {
		out = (char *)malloc(len);
		if (unlikely(NULL == out)) {
			fail = 1;
		}
	}
	if (unlikely(fail)) {
		for (i = 0; i < numentries; i++) {
			if (names[i]) {
				free(names[i]);
			}
			if (entries[i]) {
				free(entries[i]);
			}
		}
		free(names);
		free(entries);
		return NULL;
	}
	
	*out = '{';
	ptr = out + 1;
	if (fmt) {
		*ptr++ = '\n';
	}
	*ptr = '\0';
	for (i = 0; i < numentries; i++) {
		if (fmt) {
			for (j = 0; j < depth; j++) {
				*ptr++ = '\t';
			}
		}
		strcpy(ptr, names[i]);
		ptr += strlen(names[i]);
		*ptr++ = ':';
		if (fmt) {
			*ptr++='\t';
		}
		strcpy(ptr, entries[i]);
		ptr += strlen(entries[i]);
		/* there is no comma after last member */
		if (i != (numentries - 1)) { // 最后一个member后面没有逗号
			*ptr++ = ',';
		}
		if (fmt) {
			*ptr++ = '\n';
		}
		*ptr = '\0';
		free(names[i]);
		free(entries[i]);
	}
	free(names);
	free(entries);

	if (fmt) {
		for (i = 0; i < depth - 1; i++) {
			*ptr++ = '\t';
		}
	}
	*ptr++ = '}';
	*ptr = '\0';

	return out;
}

static char *
print_value(rte_json_t *json, int depth, int fmt)
{
	char *out = 0;
	if (NULL == json) {
		return NULL;
	}

	switch (json->type) {
	case JSON_NULL:
		out = json_strdup("null");
		break;
	case JSON_FALSE:
		out = json_strdup("false");
		break;
	case JSON_TRUE:
		out = json_strdup("true");
		break;
	case JSON_INTEGER:
	case JSON_FLOAT:
		out = print_number(json);
		break;
	case JSON_STRING:
		out = print_string(json);
		break;
	case JSON_OBJECT:
		out = print_object(json, depth, fmt);
		break;
	case JSON_ARRAY:
		out = print_array(json, depth, fmt);
		break;
	}
	return out;
}

/*
 * 根据JSON结构体中的内容，输出JSON文本
 * 
 */
char *
rte_serialize_json(rte_json_t *json, int fmt)
{
	return print_value(json, 0, fmt);
}

int
rte_array_get_size(rte_json_t *array)
{
	int size = 0;
	rte_json_t *item = array->member;
	while (item) {
		size++;
		item = item->next;
	}	
	return size;
}

rte_json_t *
rte_array_get_item(rte_json_t *array, int idx)
{
	rte_json_t *item = array->member;	
	while (item && idx > 0) {
		idx--;
		item = item->next;
	}
	return item;
}

int
rte_array_add_item(rte_json_t *array, rte_json_t *item)
{
	rte_json_t *tmp = NULL;
	if (NULL == item) {
		return 0;
	}
	if (NULL == array->member) {
		array->member = item;
	} else {
		tmp = array->member;
		while (tmp && tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = item;
		item->prev = tmp;
	}
	return 0;
}

int
rte_array_del_item(rte_json_t *array, int idx)
{
	rte_json_t *item = array->member;	

	while (item && idx > 0) {
		item = item->next;
		idx--;
	}
	if (NULL == item) {
		return 0;
	}
	if (item->prev) {
		item->prev->next = item->next;
	}
	if (item->next) {
		item->next->prev = item->prev;
	}
	if (item == array->member) {
		array->member = item->next;
	}
	item->prev = item->next = NULL;

	rte_destroy_json(item);

	return 0;
}

rte_json_t *
rte_object_get_item(rte_json_t *object, const char *name)
{
	rte_json_t *item = object->member;	

	while (item && strcmp(item->name, name)) {
		item = item->next;
	}
	return item;
}

int
rte_object_add_item(rte_json_t *object, const char *name, rte_json_t *item)
{
	int len = 0;

	if (NULL == item) {
		return 0;
	}
	if (NULL != item->name) {
		free(item->name);
	}
	len = strlen(name) + 1;
	item->name = (char *)malloc(len);
	if (NULL == item->name) {
		return -1;
	}
	memset(item->name, 0, len);
	strcpy(item->name, name);

	rte_array_add_item(object, item);	
	return 0;
}

int
rte_object_del_item(rte_json_t *json, const char *name)
{
	int i = 0;
	rte_json_t *item = json->member;	

	while (item && strcmp(item->name, name)) {
		i++;
		item = item->next;
	}
	if (item) {
		rte_array_del_item(json, i);
	}
	return 0;
}

static int
json_persist_str(char *buf, const char *str)
{
	int len;

	len = strlen(str) + 1;
	memcpy(buf, str, len);

	return len;
}

static int
persist_number(char *buf, rte_json_t *json)
{
	int len;
	char str[21];

	memset(str, 0, 21);
	if (json->type == JSON_INTEGER) {
		sprintf(str, "%ld", json->u.val_int);
	} else if (json->type == JSON_FLOAT) {
		sprintf(str, "%f", json->u.val_flt);
	}
	len = strlen(str);
	memcpy(buf, str, len);

	return len;
}

static int
persist_string_ptr(char *buf, const char *str)
{
	const char *ptr;
	char *ptr2;
	unsigned char token;

	if (NULL == str) {
		return json_persist_str(buf, "");
	}

	ptr2 = buf;
	ptr = str;
	*ptr2++ = '\"';
	while (*ptr) {
		if ((unsigned char)*ptr > 31 
				&& (*ptr != '\"') && (*ptr != '\\')) {
			*ptr2++ = *ptr++;
		} else {
			*ptr2++ = '\\';
			switch (token = *ptr++) {
			case '\\': *ptr2++ = '\\'; break;
			case '\"': *ptr2++ = '\"'; break;
			case '\b': *ptr2++ = 'b'; break;
			case '\f': *ptr2++ = 'f'; break;
			case '\n': *ptr2++ = 'n'; break;
			case '\r': *ptr2++ = 'r'; break;
			case '\t': *ptr2++ = 't'; break;
			default:
				sprintf(ptr2, "u%04x", token);
				ptr2 += 5;
				break;	/* escape and print */
			}
		}
	}
	*ptr2++ = '\"';

	return (ptr2 - buf);
}

static int
persist_string(char *buf, rte_json_t *json)
{
	return persist_string_ptr(buf, json->u.val_str);
}

static int
persist_array(char *buf, rte_json_t *json, int depth, int fmt)
{
	char *ptr = NULL;
	int entry_len = 0;
	int numentries = 0, i = 0, fail = 0;
	rte_json_t *item = json->member;

	/* get the member number in the array */
	while (NULL != item) {
		numentries++;
		item = item->next;
	}

	/*empty array */
	if (0 == numentries) {
		strcpy(buf, "[]");
		return 2;
	}

	/* serializing every member */
	item = json->member;
	ptr = buf;
	*ptr++ = '[';
	while ((NULL != item) && !fail) {
		entry_len = persist_value(ptr, item, depth + 1, fmt);
		ptr += entry_len;
		if (entry_len <= 0) {
			fail = 1;
		}
		if (i != (numentries - 1)) {
			*ptr++ = ',';
			if (fmt) {
				*ptr++ = ' ';
			}
		}
		i++;
		item = item->next;
	}
	*ptr++ = ']';

	if (fail) {
		return - 1;
	}

	return (ptr-buf);
}

static int
persist_object(char *buf, rte_json_t *json, int depth, int fmt)
{
	char *ptr;
	int numentries = 0;
	int name_len = 0, entry_len = 0;
	int i = 0, j = 0;
	int fail = 0;
	rte_json_t *item = json->member;

	/* get the member number in object*/
	while (item) {
		numentries++;
		item = item->next;
	}

	ptr = buf;
	/* empty object*/
	if (0 == numentries) { 
		*ptr++ = '{';
		if (fmt) {
			*ptr++ = '\n';
			for (i = 0; i < depth - 1; i++) {
				*ptr++ = '\t';
			}
		}
		*ptr++ = '}';
		*ptr++ = '\0';
		return (ptr-buf);
	}

	item = json->member;
	depth++;

	*ptr++ = '{';
	if (fmt) {
		*ptr++ = '\n';
	}
	while (NULL!= item) {
		if (fmt) {
			for (j = 0; j < depth; j++) {
				*ptr++ = '\t';
			}
		}
		name_len = persist_string_ptr(ptr, item->name);
		if(name_len <= 0) {
			fail = 1;
		}
		ptr += name_len;
		*ptr++ = ':';
		if (fmt) {
			*ptr++ = '\t';
		}

		entry_len = persist_value(ptr, item, depth, fmt);
		ptr += entry_len;

		if (entry_len <= 0) {
			fail = 1;
		}
		if (i != (numentries - 1)) {
			*ptr++ = ',';
		}
		if (fmt) {
			*ptr++ = '\n';
		}
		i++;
		item = item->next;
	}

	if (fail) {
		return -1;
	}

	if (fmt) {
		for (i = 0; i < depth - 1; i++) {
			*ptr++ = '\t';
		}
	}

	*ptr++ = '}';

	return (ptr - buf);
}

static int
persist_value(char *buf, rte_json_t *json, int depth, int fmt)
{
	int len = 0;
	if (NULL == json) {
		return 0;
	}

	switch (json->type) {
	case JSON_NULL:
		len = json_persist_str(buf, "null");
		break;
	case JSON_FALSE:
		len = json_persist_str(buf, "false");
		break;
	case JSON_TRUE:
		len = json_persist_str(buf, "true");
		break;
	case JSON_INTEGER:
	case JSON_FLOAT:
		len = persist_number(buf, json);
		break;
	case JSON_STRING:
		len = persist_string(buf, json);
		break;
	case JSON_OBJECT:
		len = persist_object(buf, json, depth, fmt);
		break;
	case JSON_ARRAY:
		len = persist_array(buf, json, depth, fmt);
		break;
	}
	if (depth == 0) {
		*(buf + len) = '\0';
		len += 1;
	}
	return len;
}

/*
 * 将JSON的序列化结果存放在buf中，省去内存分配的过程。
 * 返回值：
 * <=0 : 失败
 *  >0 : 序列化结果字符串的长度
 * */
int
rte_persist_json(char *buf, rte_json_t *json, int fmt)
{
	return persist_value(buf, json, 0, fmt);
}
