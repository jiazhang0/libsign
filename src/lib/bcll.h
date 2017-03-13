/*
 * BSD 2-clause "Simplified" License
 *
 * Copyright (c) 2017, Lans Zhang <jia.zhang@windriver.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __BCLL_H__
#define __BCLL_H__

struct __bcll;
typedef struct __bcll {
	struct __bcll *next;
	struct __bcll *prev;
} bcll_t;

#define BCLL_INIT(head)		{ .prev = head, .next = head }

#define BCLL_DECLARE(name)	\
	bcll_t name = BCLL_INIT(&name)

static inline void
bcll_init(bcll_t *head)
{
	head->next = head->prev = head;
}

static inline void
__bcll_add(bcll_t *head, bcll_t *entry)
{
	bcll_t *next = head->next;

	next->prev = entry;
	entry->next = next;
	head->next = entry;
	entry->prev = head;
}

static inline void
bcll_add(bcll_t *head, bcll_t *entry)
{
	__bcll_add(head, entry);
}

static inline void
bcll_add_tail(bcll_t *head, bcll_t *entry)
{
	__bcll_add(head->prev, entry);
}

static inline void
bcll_del(bcll_t *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
}

static inline void
bcll_del_init(bcll_t *entry)
{
	bcll_del(entry);
	bcll_init(entry);
}

#define bcll_for_each_link(p, head, member)	\
	for (p = container_of((head)->next, typeof(*p), member);	\
		&p->member != (head);	\
		p = container_of(p->member.next, typeof(*p), member))

#define bcll_for_each_link_safe(p, tmp, head, member)	\
	for (p = container_of((head)->next, typeof(*p), member),	\
		tmp = container_of(p->member.next, typeof(*p), member);	\
		&p->member != (head);	\
		p = tmp, tmp = container_of(tmp->member.next, typeof(*tmp), \
					    member))

#endif	/* __BCLL_H__ */
