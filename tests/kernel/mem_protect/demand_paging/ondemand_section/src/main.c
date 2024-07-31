/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel/mm.h>
#include <zephyr/kernel/mm/demand_paging.h>
#include <mmu.h>
#include <zephyr/linker/sections.h>

static const char __ondemand_rodata * message = "was evicted";

static void __ondemand_func evictable_function(void)
{
	static int count;

	printk("This %s code, count=%d\n", message, ++count);
}

ZTEST(ondemand_section, test_ondemand_basic)
{
	printk("About to call unpaged code\n");
	evictable_function();

	printk("Forcefully evicting it from memory\n");
	zassert_ok(k_mem_page_out(&evictable_function, CONFIG_MMU_PAGE_SIZE), "");

	printk("Calling it again\n");
	evictable_function();
}

ZTEST_SUITE(ondemand_section, NULL, NULL, NULL, NULL, NULL);
