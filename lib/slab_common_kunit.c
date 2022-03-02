// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "../mm/slab.h"

static struct kunit_resource resource;
static int slab_errors;

static void test_zero_size_ptr(struct kunit *test)
{
	void *p = kmalloc(0, GFP_KERNEL);

	if (!p)
		return;

	KUNIT_EXPECT_TRUE(test, p == ZERO_SIZE_PTR);
	kfree(p);
}

static void test_ksize_zero_size(struct kunit *test)
{
	void *p = kmalloc(0, GFP_KERNEL);

	if (!p)
		return;

	KUNIT_EXPECT_EQ(test, 0, ksize(p));
	kfree(p);
}

static void test_ksize_small_size(struct kunit *test)
{
	void *p = kmalloc(123, GFP_KERNEL);
	
	if (!p)
		return;

	KUNIT_EXPECT_GE(test, ksize(p), 123);
	kfree(p);
}

static void test_ksize_big_size(struct kunit *test)
{
	const int size = PAGE_SIZE << 3;
	void *p = kmalloc(size, GFP_KERNEL);

	if (!p)
		return;
	
	KUNIT_EXPECT_EQ(test, size, ksize(p));
	kfree(p);
}

static void test_kmalloc_small_object_slab_folio(struct kunit *test)
{
	void *p = kmalloc(32, GFP_KERNEL);
	struct folio *folio;
	
	if (!p)
		return;

	folio = virt_to_folio(p);
	KUNIT_EXPECT_TRUE(test, folio_test_slab(folio));
	kfree(p);
}

static void test_kmalloc_big_object_normal_folio(struct kunit *test)
{
	const int size = PAGE_SIZE << 3;
	void *p = kmalloc(size, GFP_KERNEL);
	struct folio *folio;

	if (!p)
		return;

	folio = virt_to_folio(p);
	KUNIT_EXPECT_FALSE(test, folio_test_slab(folio));
	kfree(p);
}


static void test_kfree_bulk_small(struct kunit *test)
{
	int i;
	const int len = 10;
	void *array[len];

	for (i = 0; i < len; i++)
		array[i] = kmalloc(32, GFP_KERNEL);

	kfree_bulk(len, array);
}

static void test_kfree_bulk_big(struct kunit *test)
{
	int i;
	const int len = 10;
	void *array[len];

	for (i = 0; i < len; i++)
		array[i] = kmalloc(PAGE_SIZE << 3, GFP_KERNEL);

	kfree_bulk(len, array);
}

static void test_bulk_alloc_free_small(struct kunit *test)
{
	const int len = 10;
	int ret, i;
	void *array[len];
	struct kmem_cache *s = kmem_cache_create("slab_test_bulk", 64, 0,
						 0, NULL);

	if (!s)
		return;

	ret = kmem_cache_alloc_bulk(s, GFP_KERNEL, len, array);
	for (i = 0; i < ret; i++)
		KUNIT_EXPECT_TRUE(test, array[i] != NULL);

	kmem_cache_free_bulk(s, len, array);
	kmem_cache_destroy(s);
}

static void test_bulk_alloc_free_big(struct kunit *test)
{
	const int len = 10;
	int ret, i;
	void *array[len];
	struct kmem_cache *s = kmem_cache_create("slab_test_bulk", PAGE_SIZE << 3,
						 0, 0, NULL);

	if (!s)
		return;

	ret = kmem_cache_alloc_bulk(s, GFP_KERNEL, len, array);
	for (i = 0; i < ret; i++)
		KUNIT_EXPECT_TRUE(test, array[i] != NULL);

	kmem_cache_free_bulk(s, len, array);
	kmem_cache_destroy(s);
}

static int test_init(struct kunit *test)
{
	slab_errors = 0;

	kunit_add_named_resource(test, NULL, NULL, &resource,
					"slab_errors", &slab_errors);
	return 0;
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_zero_size_ptr),
	KUNIT_CASE(test_ksize_zero_size),
	KUNIT_CASE(test_ksize_small_size),
	KUNIT_CASE(test_ksize_big_size),
	KUNIT_CASE(test_kmalloc_small_object_slab_folio),
	KUNIT_CASE(test_kmalloc_big_object_normal_folio),
	KUNIT_CASE(test_kfree_bulk_small),
	KUNIT_CASE(test_kfree_bulk_big),
	KUNIT_CASE(test_bulk_alloc_free_small),
	KUNIT_CASE(test_bulk_alloc_free_big),
	{}
};

static struct kunit_suite test_suite = {
	.name = "slab_common_test",
	.init = test_init,
	.test_cases = test_cases,
};
kunit_test_suite(test_suite);

MODULE_LICENSE("GPL");
