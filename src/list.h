#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

#define prefetch(exp)       ((void)(exp))

#ifndef container_of
#define container_of(ptr, type, member) ({          \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define LIST_POISON1  ((void *) (0x00100100))
#define LIST_POISON2  ((void *) (0x00200200))

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *nodenew,
                              struct list_head *prev,
                              struct list_head *next)
{
	next->prev = nodenew;
	nodenew->next = next;
	nodenew->prev = prev;
	prev->next = nodenew;
}

static inline void list_add(struct list_head *nodenew, struct list_head *head)
{
	__list_add(nodenew, head, head->next);
}

static inline void list_add_tail(struct list_head *nodenew, struct list_head *head)
{
	__list_add(nodenew, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head *)LIST_POISON1;
	entry->prev = (struct list_head *)LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
	     pos = pos->next)

#define list_for_each_entry(pos, head, member)              \
	for (pos = list_entry((head)->next, typeof(*pos), member);  \
	     prefetch(pos->member.next), &pos->member != (head);    \
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)          \
	for (pos = list_entry((head)->next, typeof(*pos), member),  \
	     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);                    \
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry_safe2(tpos, n, head, type, member)  \
	for (tpos = list_entry((head)->next, type, member),         \
	     n = list_entry(tpos->member.next, type, member);            \
	     &tpos->member != (head);                               \
	     tpos = n, n = list_entry(n->member.next, type, member))

#endif
