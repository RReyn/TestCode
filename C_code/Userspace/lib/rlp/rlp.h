#ifndef _RLP_H_
#define _RLP_H_

#pragma pack(1)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef u32
#define u32 uint32_t
#endif

#ifndef u8
#define u8 uint8_t
#endif

enum RLP_RET {
	RLP_OK  = 0,
	RLP_ERR = 1
};

typedef struct _type {
	u8 size; /* how many bytes */
	u8 *(*locate)(u8 *key, u8 *base, u32 size);
	u8 *(*dec)(u8 *data);
	u8 *(*inc)(u8 *data);
	bool (*gt)(u8 *l, u8 *r);
	bool (*eq)(u8 *l, u8 *r);
	bool (*is_zero)(u8 *data);
	void (*dump)(u8 *data);
} type_t;

typedef struct _rlp {
	type_t  type;
	u32 size;
	/* the data, then the flags */
	u8  elem[0];
} rlp_t;

typedef struct inet_addr_ipv4 {
	__be32 ip;
} inet_addr_t;

typedef struct addr_unit {
	inet_addr_t left;
	inet_addr_t right;
} addr_unit_t;

typedef struct addr_set {
	size_t size;
	addr_unit_t cells[0];
} addr_set_t;

#define FIRST_KEY(rlp) ((u8 *)(rlp) + sizeof(rlp_t))
#define FIRST_FLAG(rlp) ((u8 *)(rlp) + sizeof(rlp_t) + \
		(((rlp)->type.size * sizeof(u8)) * (rlp)->size))

#define SET_FLAG(flag)  (*(flag) = 1)
#define ZERO_FLAG(flag) (*(flag) = 0)
#define FLAG_IS_ZERO(flag) (*(flag) == 0)

/* interfaces */
extern enum RLP_RET
segment_insert(rlp_t **rlp, type_t type,
		u8 *left, u8 *right);

extern rlp_t *
rlp_new(type_t type);

/* debug dump */
extern void
rlp_dump(rlp_t *rlp);

extern int check_u32_intersection(addr_set_t *, addr_set_t *);

#ifdef __cplusplus
}
#endif

#endif

