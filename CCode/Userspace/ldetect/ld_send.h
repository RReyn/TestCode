#ifndef _LD_SEND_H_
#define _LD_SEND_H_

#ifdef __cplusplus
extern "C" {
#endif

#define DETECT_TTL		255

extern void detect_node_thread_cancle(ld_detect_t *node);
extern int detect_node_entry_init(ld_detect_t *node);
extern void detect_list_init(void);

#ifdef __cplusplus
}
#endif

#endif /* LD_SEND_H END */
