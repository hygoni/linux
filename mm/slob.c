// SPDX-License-Identifier: GPL-2.0
/*
 * SLOB Allocator: Simple List Of Blocks
 *
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * NUMA support by Paul Mundt, 2007.
 *
 * How SLOB works:
 *
 * The core of SLOB is a traditional K&R style heap allocator, with
 * support for returning aligned objects. The granularity of this
 * allocator is as little as 2 bytes, however typically most architectures
 * will require 4 bytes on 32-bit and 8 bytes on 64-bit.
 *
 * The slob heap is a set of linked list of pages from alloc_pages(),
 * and within each page, there is a singly-linked list of free blocks
 * (slob_t). The heap is grown on demand. To reduce fragmentation,
 * heap pages are segregated into three lists, with objects less than
 * 256 bytes, objects less than 1024 bytes, and all other objects.
 *
 * Allocation from heap involves first searching for a page with
 * sufficient free blocks (using a next-fit-like approach) followed by
 * a first-fit scan of the page. Deallocation inserts objects back
 * into the free list in address order, so this is effectively an
 * address-ordered first fit.
 *
 * Above this is an implementation of kmalloc/kfree. Blocks returned
 * from kmalloc are prepended with a 4-byte header with the kmalloc size.
 * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
 * alloc_pages() directly, allocating compound pages so the page order
 * does not have to be separately tracked.
 * These objects are detected in kfree() because PageSlab()
 * is false for them.
 *
 * SLAB is emulated on top of SLOB by simply calling constructors and
 * destructors for every SLAB allocation. Objects are returned with the
 * 4-byte alignment unless the SLAB_HWCACHE_ALIGN flag is set, in which
 * case the low-level allocator will fragment blocks to create the proper
 * alignment. Again, objects of page-size or greater are allocated by
 * calling alloc_pages(). As SLAB objects know their size, no separate
 * size bookkeeping is necessary and there is essentially no allocation
 * space overhead, and compound pages aren't needed for multi-page
 * allocations.
 *
 * NUMA support in SLOB is fairly simplistic, pushing most of the real
 * logic down to the page allocator, and simply doing the node accounting
 * on the upper levels. In the event that a node id is explicitly
 * provided, __alloc_pages_node() with the specified node id is used
 * instead. The common case (or when the node id isn't explicitly provided)
 * will default to the current node, as per numa_node_id().
 *
 * Node aware pages are still inserted in to the global freelist, and
 * these are scanned for by matching against the node id encoded in the
 * page flags. As a result, block allocations that can be satisfied from
 * the freelist will only be done so on pages residing on the same node,
 * in order to prevent random node placement.
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

#include <linux/atomic.h>

#include "slab.h"


struct slob slob_list[PAGE_SHIFT + 1];

#define for_each_object(__p, __size, __addr, __objects) \
        for(__p = __addr; \
                __p < __addr + __objects * __size; \
                __p += __size)

/*
 * slob_page_free: true for pages on free_slob_pages list.
 */
static inline int slob_page_free(struct page *sp)
{
	return PageSlobFree(sp);
}

static void set_slob_page_free(struct page *sp, struct list_head *list)
{
	list_add(&sp->slab_list, list);
	__SetPageSlobFree(sp);
}

static inline void clear_slob_page_free(struct page *sp)
{
	list_del(&sp->slab_list);
	__ClearPageSlobFree(sp);
}

static noinline unsigned int slob_size(size_t size, int order)
{
	return (PAGE_SIZE << order) / size;
}

static void *get_freepointer(void *objp)
{
	return (void*)(*(unsigned long *)objp);
}

static noinline void set_freepointer(void *objp, void *fp)
{
	*(unsigned long*)(objp) = (unsigned long)fp;
}

/*
 * struct slob_rcu is inserted at the tail of allocated slob blocks, which
 * were created with a SLAB_TYPESAFE_BY_RCU slab. slob_rcu is used to free
 * the block using call_rcu.
 */
struct slob_rcu {
	struct rcu_head head;
	unsigned int size;
};


static struct page *slob_new_pages(gfp_t gfp, int order, int node)
{
	struct page *page;

#ifdef CONFIG_NUMA
	if (node != NUMA_NO_NODE)
		page = __alloc_pages_node(node, gfp, order);
	else
#endif
		page = alloc_pages(gfp, order);

	if (!page)
		return NULL;

	mod_node_page_state(page_pgdat(page), NR_SLAB_UNRECLAIMABLE_B,
			    PAGE_SIZE << order);
	return page;
}

static void slob_free_pages(const void *b, int order)
{
	struct page *sp = virt_to_page(b);

	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;

	mod_node_page_state(page_pgdat(sp), NR_SLAB_UNRECLAIMABLE_B,
			    -(PAGE_SIZE << order));
	page_mapcount_reset(sp);
	__free_pages(sp, order);
}

static noinline unsigned int slob_get_order(size_t size)
{
	int i = PAGE_SHIFT;

	/* TODO: faster way to do this? */
	while (i >= 0)
	{
		if (size > slob_list[i].size)
			break;
		i--;
	}
	return i + 1;
}

/*
 * slob_page_alloc() - Allocate a slob block within a given slob_page sp.
 * @sp: Page to look in.
 *
 * Tries to find a chunk of memory at least @size bytes big within @page.
 *
 * Caller must manage slob->lock.
 *
 * Return: Pointer to memory if allocated, %NULL otherwise.  If the
 *         allocation fills up @page then the page is removed from the
 *         freelist, in this case @page_removed_from_list will be set to
 *         true (set to false otherwise).
 */
static void *slob_page_alloc(struct page *sp)
{
	void *cur;

	cur = sp->freelist;
	VM_BUG_ON(!cur);
	sp->freelist = get_freepointer(cur);
	sp->inuse++;

	return cur;
}

static void slob_init_page(struct page *sp, int order, size_t size)
{
	void *cur, *prev, *addr = page_address(sp);
	struct slob *slob = &slob_list[slob_get_order(size)];
	int node = page_to_nid(sp);
	struct list_head *head = &slob->head[node];

	__SetPageSlab(sp);
	sp->objects = slob_size(size, order);
	sp->inuse = 0;
	sp->object_size = size;
	sp->freelist = addr;
	INIT_LIST_HEAD(&sp->slab_list);

	prev = NULL;
	for_each_object(cur, size, addr, sp->objects) {
		if (prev)
			set_freepointer(prev, cur);
		set_freepointer(cur, NULL);
		prev = cur;
	}

	set_slob_page_free(sp, head);
}

/*
 * slob_alloc: entry point into the slob allocator.
 * size must be 2^n
 */
static void *slob_alloc(size_t size, gfp_t gfp, int node)
{
	struct slob *slob;
	struct page *sp;
	struct list_head *head;
	void *objp = NULL;
	unsigned long flags;

	if (node == NUMA_NO_NODE)
		node = numa_mem_id();

	slob = &slob_list[slob_get_order(size)];
	head = &slob->head[node];

	spin_lock_irqsave(&slob->lock, flags);

	if (list_empty(head)) {
		spin_unlock_irqrestore(&slob->lock, flags);
		sp = slob_new_pages(gfp & ~__GFP_ZERO, 0, node);

		if (!sp)
			return NULL;

		spin_lock_irqsave(&slob->lock, flags);
		slob_init_page(sp, 0, size);
	} else
		sp = list_first_entry(head, struct page, slab_list);

	objp = slob_page_alloc(sp);

	/* free pointer corrupted */
	VM_BUG_ON(((unsigned long)objp & PAGE_MASK) !=
			((unsigned long)page_address(sp) & PAGE_MASK));

	/* became full slab */
	if (sp->inuse == sp->objects)
		clear_slob_page_free(sp);

	spin_unlock_irqrestore(&slob->lock, flags);

	if (unlikely(gfp & __GFP_ZERO))
		memset(objp, 0, size);
	return objp;
}

/*
 * slob_free: entry point into the slob allocator.
 */
static void slob_free(void *block)
{
	struct page *sp;
	struct slob *slob;
	unsigned long flags;
	int node;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;

	sp = virt_to_page(block);
	slob = &slob_list[slob_get_order(sp->object_size)];
	node = page_to_nid(sp);

	spin_lock_irqsave(&slob->lock, flags);

	set_freepointer(block, sp->freelist);
	sp->freelist = block;
	sp->inuse--;

	/* invalid free */
	VM_BUG_ON(((unsigned long)block & PAGE_MASK) !=
			((unsigned long)page_address(sp) & PAGE_MASK));

	/* page became full */
	if (!sp->inuse) {
		/* Go directly to page allocator. Do not pass slob allocator */
		if (slob_page_free(sp))
			clear_slob_page_free(sp);
		spin_unlock_irqrestore(&slob->lock, flags);

		__ClearPageSlab(sp);
		slob_free_pages(block, 0);
		return;
	}

	/* empty page becoming partial */
	if (!slob_page_free(sp)) {
		set_slob_page_free(sp, &slob->head[node]);
	}

	spin_unlock_irqrestore(&slob->lock, flags);
}

#ifdef CONFIG_PRINTK
void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct page *page)
{
	kpp->kp_ptr = object;
	kpp->kp_page = page;
}
#endif

/*
 * End of slob allocator proper. Begin kmem_cache_alloc and kmalloc frontend.
 */

static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
{
	void *ret;
	struct page *sp;

	gfp &= gfp_allowed_mask;

	might_alloc(gfp);

	if (unlikely(!size))
		return ZERO_SIZE_PTR;

	if (size < PAGE_SIZE) {
		size = ALIGN(size, sizeof(void *));
		size = ALIGN(size, ARCH_KMALLOC_MINALIGN);

		size = 1 << slob_get_order(size);
		ret = slob_alloc(size, gfp, node);
	} else {
		unsigned int order = get_order(size);

		if (likely(order))
			gfp |= __GFP_COMP;

		sp = slob_new_pages(gfp, order, node);
		if (!sp)
			return NULL;

		ret = page_address(sp);
	}

	return ret;
}

void *__kmalloc(size_t size, gfp_t gfp)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t gfp, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, caller);
}
EXPORT_SYMBOL(__kmalloc_track_caller);

#ifdef CONFIG_NUMA
void *__kmalloc_node_track_caller(size_t size, gfp_t gfp,
					int node, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, node, caller);
}
EXPORT_SYMBOL(__kmalloc_node_track_caller);
#endif

void kfree(const void *block)
{
	struct page *sp;


	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;

	sp = virt_to_page(block);

	if (PageSlab(sp))
		slob_free((void*)block);
	else {
		unsigned int order = compound_order(sp);
		slob_free_pages(block, order);
	}
}
EXPORT_SYMBOL(kfree);

size_t __ksize(const void *block)
{
	struct page *sp;

	BUG_ON(!block);

	if (unlikely(block == ZERO_SIZE_PTR))
		return 0;

	sp = virt_to_page(block);
	if (!PageSlab(sp))
		return page_size(sp);

	return sp->object_size;
}
EXPORT_SYMBOL(__ksize);

int __kmem_cache_create(struct kmem_cache *c, slab_flags_t flags)
{
	if (flags & SLAB_TYPESAFE_BY_RCU) {
		/* leave room for rcu footer at the end of object */
		c->size += sizeof(struct slob_rcu);
	}

	c->flags = flags;
	return 0;
}

static void *slob_alloc_node(struct kmem_cache *c, gfp_t flags, int node)
{
	void *b;
	struct page *sp;
	size_t size;

	flags &= gfp_allowed_mask;

	might_alloc(flags);

	if (unlikely(!c->size))
			return ZERO_SIZE_PTR;

	size = ALIGN(c->size, sizeof(void *));
	size = ALIGN(size, c->align);

	if (size < PAGE_SIZE) {
		size = 1 << slob_get_order(size);
		b = slob_alloc(size, flags, node);
	} else {
		unsigned int order = get_order(size);

		sp = slob_new_pages(flags, order, node);
		if (!sp)
			return NULL;
		b = page_address(sp); 
	}

	if (b && c->ctor) {
		WARN_ON_ONCE(flags & __GFP_ZERO);
		c->ctor(b);
	}

	return b;
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return slob_alloc_node(cachep, flags, NUMA_NO_NODE);
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_NUMA
void *__kmalloc_node(size_t size, gfp_t gfp, int node)
{
	return __do_kmalloc_node(size, gfp, node, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc_node);

void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t gfp, int node)
{
	return slob_alloc_node(cachep, gfp, node);
}
EXPORT_SYMBOL(kmem_cache_alloc_node);
#endif

static void __kmem_cache_free(void *b)
{
	struct page *sp = virt_to_page(b);

	if (PageSlab(sp))
		slob_free(b);
	else
		slob_free_pages(b, compound_order(sp));
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slob_rcu *slob_rcu = (struct slob_rcu *)head;
	void *b = (void *)slob_rcu - (slob_rcu->size - sizeof(struct slob_rcu));

	__kmem_cache_free(b);
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	if (unlikely(c->flags & SLAB_TYPESAFE_BY_RCU)) {
		struct slob_rcu *slob_rcu;
		slob_rcu = b + (c->size - sizeof(struct slob_rcu));
		slob_rcu->size = c->size;
		call_rcu(&slob_rcu->head, kmem_rcu_free);
	} else
		__kmem_cache_free(b);
}
EXPORT_SYMBOL(kmem_cache_free);

void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
{
	__kmem_cache_free_bulk(s, size, p);
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
								void **p)
{
	return __kmem_cache_alloc_bulk(s, flags, size, p);
}
EXPORT_SYMBOL(kmem_cache_alloc_bulk);

int __kmem_cache_shutdown(struct kmem_cache *c)
{
	/* No way to check for remaining objects */
	return 0;
}

void __kmem_cache_release(struct kmem_cache *c)
{
}

int __kmem_cache_shrink(struct kmem_cache *d)
{
	return 0;
}

struct kmem_cache kmem_cache_boot = {
	.name = "kmem_cache",
	.size = sizeof(struct kmem_cache),
	.flags = SLAB_PANIC,
	.align = ARCH_KMALLOC_MINALIGN,
};

void __init kmem_cache_init(void)
{
	int shift, node;
	struct slob *slob;

	kmem_cache = &kmem_cache_boot;
	kmem_cache->size = ALIGN(kmem_cache->size, kmem_cache->align);

	for (shift = 0; shift <= PAGE_SHIFT; shift++) {
		slob = &slob_list[shift];
		slob->size = 1 << shift;
		for_each_node(node) {
			INIT_LIST_HEAD(&slob->head[node]);
		}
	}
	slab_state = UP;
}

void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}
