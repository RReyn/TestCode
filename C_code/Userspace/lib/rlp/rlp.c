#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rlp.h"

/* use 'unused' attribute to make gcc happy */
static void
general_data_dump(u8 *data, type_t type) __attribute__((unused));
static void
general_data_dump(u8 *data, type_t type)
{
	int i;
	for (i = 0; i < type.size; ++i) {
		printf("%02x", data[i]);
	}
}

static inline u32
key_idx(rlp_t *rlp, u8 *key)
{
	return ((key - FIRST_KEY(rlp)) / rlp->type.size);
}

static enum RLP_RET
insert_aux(rlp_t **rlp, u8 *key)
{
	u8 *kpos, *fpos;
	type_t type;
	rlp_t *new;
	u32 new_size;
	u32 offset;

	type = (*rlp)->type;
	kpos = (*rlp)->type.locate(key,
			(*rlp)->elem, (*rlp)->size);
	if (type.eq(kpos, key))
		return RLP_OK;
	offset = kpos - (u8 *)(*rlp);
	fpos = FIRST_FLAG(*rlp) + key_idx(*rlp, kpos);
	new_size = sizeof(rlp_t) + \
		   (((*rlp)->size + 1)* \
		    ((sizeof(u8) * type.size) + sizeof(u8)));
	new = calloc(1, new_size);
	if (!new)
		return RLP_ERR;
	memcpy((u8 *)new, (u8 *)(*rlp), offset);
	memcpy((u8 *)new + offset, key, type.size);
	memcpy((u8 *)new + offset + type.size, kpos, fpos - kpos);
	memcpy((u8 *)new + offset + type.size + (fpos - kpos) + sizeof(u8),
			fpos,
			new_size - \
			((sizeof(u8) * type.size) + sizeof(u8)) + \
			(u8 *)(*rlp) - fpos);
	new->size += 1;
	if (!FLAG_IS_ZERO(fpos))
		SET_FLAG((u8 *)new + offset + type.size + (fpos - kpos));
	free(*rlp);
	*rlp = new;
	return RLP_OK;
}

/* the data struct will be like below:
 * --------
 * | data1 |
 * | data2 |
 * | data3 |
 * | ...   |
 * | flag1 |
 * | flag2 |
 * | flag3 |
 * | ...   |
 * we use macro FIRST_KEY to get rlp's first data,
 * and use macro FIRST_FLAG to get rlp's first flag.
 *
 * we use 'type_t' but not 'type_t *' as an argument
 * for convenient, because gcc will make one copy in the stack.
 */
enum RLP_RET
segment_insert(rlp_t **rlp, type_t type,
		u8 *left, u8 *right)
{
	enum RLP_RET ret;
	u8 *lpos, *rpos, *lfpos, *rfpos, *idx;

	if (!rlp || !(*rlp)|| !left || !right ||
			(*rlp)->type.size != type.size ||
			type.gt(left, right))
		return RLP_ERR;

	if (!type.is_zero(left)) {
		ret = insert_aux(rlp, type.dec(left));
		if (ret != RLP_OK)
			return ret;
		type.inc(left);
	}
	ret = insert_aux(rlp, right);
	if (ret != RLP_OK)
		return ret;
	/* set flags */
	lpos = (*rlp)->type.locate(left,
			(*rlp)->elem, (*rlp)->size); 
	rpos = (*rlp)->type.locate(right,
			(*rlp)->elem, (*rlp)->size);
	if (lpos > rpos)
		return RLP_ERR;
	lfpos = FIRST_FLAG((*rlp)) + ((lpos - FIRST_KEY((*rlp))) / type.size);
	rfpos = FIRST_FLAG((*rlp)) + ((rpos - FIRST_KEY((*rlp))) / type.size);
	for (idx = lfpos; idx <= rfpos; ++idx) {
		SET_FLAG(idx);
	}
	return RLP_OK;
}

rlp_t *
rlp_new(type_t type)
{
	rlp_t *rlp;
	
	rlp = calloc(1, sizeof(rlp_t) + type.size * sizeof(u8) + sizeof(u8));
	if (!rlp) {
		printf("oom\n");
		return NULL;
	}
	rlp->type = type;
	rlp->size = 1;
	memset(rlp->elem, 0xff, type.size);
	return rlp;
}

/* 
 * we dump data like below:
 * -----------
 * data1 flag1
 * data2 flag2
 * data3 flag3
 * ...
 */
void
rlp_dump(rlp_t *rlp)
{
	int i;
	type_t type = rlp->type;
	u8 *flags;

	flags = rlp->elem + (rlp->size * type.size);
	for (i = 0; i < rlp->size; i++) {
		type.dump(rlp->elem + (i * type.size));
		printf("\t");
		printf("%u\n", flags[i]);
	}
}

/* test driver, only contents type u8(uint8_t) */
//#ifndef NDEBUG
static bool
u32_is_zero(u8 *data)
{
	return *(u32 *)data == 0;
}
static u8 *
u32_dec(u8 *data)
{
	*(u32 *)data -= 1;
	return data;
}

static u8 *
u32_inc(u8 *data)
{
	*(u32 *)data += 1;
	return data;
}

static bool
u32_gt(u8 *left, u8 *right)
{
	return *(u32 *)left > *(u32 *)right;
}

static bool
u32_eq(u8 *left, u8 *right)
{
	return *(u32 *)left == *(u32 *)right;
}

static void
u32_dump(u8 *data)
{
	printf("%u", *(u32 *)data);
}

/* liner search, not binary, so the complex will be O(n^2)... */
/* use 'unused' attribute to make gcc happy */
static u8 *
u8_llocate(u8 *key, u8 *base, u32 size) __attribute__((unused));
static u8 *
u8_llocate(u8 *key, u8 *base, u32 size)
{
	int i;
	for (i = 0; i < size; ++i) {
		if (*key <= *(base + i))
			return base + i;
	}
	/* should never reach here */
	assert(0);
	return base;
}

/* here comes the binary locate */
static u8 *
u32_locate(u8 *key, u8 *base, u32 size)
{
	u8 tsize = 4;
	u32 left, right, pos;
	left = 0;
	right = size - 1;
	while (left <= right) {
		pos = (left + right) >> 1;
		if (*(u32 *)&base[pos * tsize] < *(u32 *)key) {
			left = pos + 1;
		} else if (pos && *(u32 *)&base[(pos - 1)*tsize] >= *(u32 *)key) {
			right = pos - 1;
		} else {
			return &base[pos*tsize];
		}
	}
	/* should never reach here */
	assert(0);
	return base;
}

type_t type = {
	.size = 4,
	.locate = u32_locate,
	.dec = u32_dec,
	.inc = u32_inc,
	.gt = u32_gt,
	.eq = u32_eq,
	.is_zero = u32_is_zero,
	.dump = u32_dump,
};

enum RLP_RET
trans_rlp2addr_set(type_t type, rlp_t *rlp, addr_set_t **result)
{
	enum RLP_RET ret;
	int i = 0;
	size_t count = 0, ip_count = 0;
	u32 ip = 0;
	u8 *flag = NULL;

	assert(rlp != NULL);
	assert(result != NULL);

	flag = rlp->elem + (rlp->size * type.size);
	for (i = 0; i < rlp->size; i++) {
		if (flag[i] == 0) {
			flag[i] = 1;
			count++;
		} else {
			flag[i] = 0;
		}
	}

	*result = (addr_set_t *)malloc(sizeof(addr_set_t) 
			+ count * sizeof(addr_unit_t));
	if (*result == NULL) {
		ret = RLP_ERR;
		goto _exit;
	}

	(*result)->size = count;
	for (i = 0; i < rlp->size; i++) {
		if (flag[i] == 0) {
			ip = *(u32 *)(rlp->elem + (i * type.size)) + 1;
		} else if (flag[i] == 1) {
			if (ip_count >= count) {
				ret = RLP_ERR;
				goto _exit;
			}
			(*result)->cells[ip_count].left.ip = ip;	
			(*result)->cells[ip_count].right.ip = 
				*(u32 *)(rlp->elem + (i * type.size));
			ip_count++;
		}
	}
#ifdef DEBUG
	int j = 0;
	printf("[%s: %d]: result->size: %zu\n",
			__FUNCTION__, __LINE__, (*result)->size);
	for (j = 0; j < (*result)->size; j++) {
		printf("result[%d]->left: %u, result[%d]->right: %u\n",
			j, (*result)->cells[j].left.ip,
			j, (*result)->cells[j].right.ip);
	}
#endif

	return RLP_OK;
_exit: 
	if (*result) {
		free(*result);
		*result = NULL;
	}
	return ret;
}

enum RLP_RET
addr_set2elem(type_t type, addr_set_t *set, rlp_t **rlp)
{
	enum RLP_RET ret = RLP_OK;
	u32 i = 0, left = 0, right = 0;

	assert(rlp != NULL);
	assert(*rlp != NULL);
	assert(set != NULL);

	while (i < set->size) {
		left = set->cells[i].left.ip;
		right = set->cells[i].right.ip;
		ret = segment_insert(rlp, type, (u8 *)&left, (u8 *)&right);
		if (ret != RLP_OK) {
			goto _exit;
		}
		i++;
	}
_exit:
	return ret;
}

addr_set_t *
get_u32_complementary_set(addr_set_t *set)
{
	enum RLP_RET ret;
	rlp_t *rlp;
	addr_set_t *result = NULL;

	assert(set != NULL);

	rlp = rlp_new(type);
	if (!rlp)
		return NULL;

	ret = addr_set2elem(type, set, &rlp);
	if (ret != RLP_OK) {
		result = NULL;	
		goto _exit;
	}
#ifdef DEBUG
	printf("before rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
	rlp_dump(rlp);
	printf("after rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
#endif
	ret = trans_rlp2addr_set(type, rlp, &result);
	if (ret != RLP_OK) {
		result = NULL;
		goto _exit;
	}
_exit:
	free(rlp);
	return result;
}

addr_set_t *
get_u32_intersection_set(addr_set_t *set1, addr_set_t *set2)
{
	enum RLP_RET ret;
	rlp_t *rlp;
	addr_set_t *result = NULL;

	if (set1 == NULL || set2 == NULL) {
		return NULL;
	}

	rlp = rlp_new(type);
	if (!rlp) {
		goto _exit;
	}

	ret = addr_set2elem(type, set1, &rlp);
	if (ret != RLP_OK) {
		goto _exit;
	}
#ifdef DEBUG
	printf("before rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
	rlp_dump(rlp);
	printf("after rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
#endif
	ret = addr_set2elem(type, set2, &rlp);
	if (ret != RLP_OK) {
		goto _exit;
	}
#ifdef DEBUG
	printf("before rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
	rlp_dump(rlp);
	printf("after rlp_dump [%s: %d] ===========================\n",
			__FUNCTION__, __LINE__);
#endif
	ret = trans_rlp2addr_set(type, rlp, &result);
	if (ret == RLP_OK) {
		/* success */
		goto _exit;
	}
	/* error */
	if (result) {
		free(result);
		result = NULL;
	}
_exit:	
	if (set1) {
		free(set1);
		set1 = NULL;
	}
	if (set2) {
		free(set2);
		set2 = NULL;
	}
	return result;
}

int
check_u32_intersection(addr_set_t *src, addr_set_t *dst)
{
	int ret = 0;
	addr_set_t *result = NULL;

	assert(src != NULL);
	assert(dst != NULL);

	result = get_u32_intersection_set(get_u32_complementary_set(src), 
			get_u32_complementary_set(dst));
	if (result) {
#ifdef DEBUG
		printf("result->size: %zu\n", result->size);
		printf("result->left: %u, result->right: %u\n",
				result->cells[0].left.ip,
				result->cells[0].right.ip);
#endif
		ret = 1;
		free(result);
		result = NULL;
	}
	return ret;
}
#ifdef DEBUG
int
main(int argc, char *argv[])
{
	addr_set_t *set1 = NULL, *set2 = NULL; 
	int ret = 0;

	set1 = (addr_set_t *)malloc(sizeof(addr_set_t) + sizeof(addr_unit_t));
	if (set1 == NULL) {
		printf("set1 is NULL\n");
		ret = -1;
		goto _exit;
	}
	set1->size = 1;
	set1->cells[0].left.ip = 5;
	set1->cells[0].right.ip = 10;

	set2 = (addr_set_t *)malloc(sizeof(addr_set_t) + sizeof(addr_unit_t));
	if (set2 == NULL) {
		printf("set1 is NULL\n");
		ret = -1;
		goto _exit;
	}
	set2->size = 1;
	set2->cells[0].left.ip = 8;
	set2->cells[0].right.ip = 20;

	ret = check_u32_intersection(set1, set2);
	if (ret) {
		printf("set1 and set2 has intersection.\n");
		ret = 0;
	}
_exit:
	if (set1) {
		free(set1);
		set1 = NULL;
	}
	if (set2) {
		free(set2);
		set2 = NULL;
	}
	return ret;
}
#endif
//#endif

