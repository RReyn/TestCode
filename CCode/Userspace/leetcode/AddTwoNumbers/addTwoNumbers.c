#include <stdio.h>

#define add_unit_to_list(list, unit, flag) do {                            \
	struct ListNode *tmp = NULL;                                       \
	while (unit) {                                                     \
		tmp = (struct ListNode *)malloc(sizeof(struct ListNode));  \
		if (!tmp) {                                                \
			goto out;                                          \
		}                                                          \
		tmp->val = (unit)->val + (flag);                           \
		if (tmp->val >= 10) {                                      \
			tmp->val = tmp->val % 10;                          \
			(flag) = 1;                                        \
		} else {                                                   \
			(flag) = 0;                                        \
		}                                                          \
		tmp->next = NULL;                                          \
		pos->next = tmp;                                           \
		pos = tmp;                                                 \
		l1 = l1->next;                                             \
	}                                                                  \
} while (0)

/**
 * Definition for singly-linked list.
 * struct ListNode {
 *     int val;
 *     struct ListNode *next;
 * };
 */
struct ListNode* addTwoNumbers(struct ListNode* l1, struct ListNode* l2) {
	struct ListNode *head = NULL, *pos = NULL, *tmp = NULL;
	int flag = 0;

	while (l1) {
		if (l2) {
			if (!head) {
				head = (struct ListNode *)malloc(sizeof(struct ListNode));
				if (!head)
					return NULL;
				head->next = NULL;
				head->val = l1->val + l2->val;
				if (head->val >= 10) {
					head->val = head->val % 10;
					flag = 1;
				}
				pos = head;
			} else {
				tmp = (struct ListNode *)malloc(sizeof(struct ListNode));
				if (!tmp) {
					goto out;
				} 
				tmp->val = l1->val + l2->val + flag;
				if (tmp->val >= 10) {
					tmp->val = tmp->val % 10;
					flag = 1;
				} else {
					flag = 0;
				}
				tmp->next = NULL;
				pos->next = tmp;
				pos = tmp;
			}
		} else {
			break;
		}
		l1 = l1->next;
		l2 = l2->next;
	}

	add_unit_to_list(pos, l1, flag);
	add_unit_to_list(pos, l2, flag);

	if (flag) {
		tmp = (struct ListNode *)malloc(sizeof(struct ListNode));
		if (!tmp) {
			goto out;
		} 
		tmp->val =  flag;
		tmp->next = NULL;
		pos->next = tmp;
		pos = tmp;
	}
	return head;
out:
	while (head) {
		pos = head->next;
		free(head);
		head = pos;
	}
	return NULL;
}

