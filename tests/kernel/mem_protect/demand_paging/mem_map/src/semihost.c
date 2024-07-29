/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RAM-based memory buffer backing store implementation for demo purposes
 */
#include <mmu.h>
#include <string.h>
#include <kernel_arch_interface.h>
#include <zephyr/kernel/mm/demand_paging.h>
#include <zephyr/devicetree.h>
#include <zephyr/logging/log.h>
#include <zephyr/arch/common/semihost.h>

LOG_MODULE_REGISTER(backing_store_semihost, LOG_LEVEL_DBG);

#ifndef BACKING_STORE_PAGES
#define BACKING_STORE_PAGES 12
#endif

#if BACKING_STORE_PAGES == 0
#error "No backing store space"
#endif

#ifndef BACKING_STORE_READ_ONLY
#define BACKING_STORE_READ_ONLY 0
#endif

static const char *backing_store_file = "./backing_store.bin";

static uint32_t free_pages[DIV_ROUND_UP(BACKING_STORE_PAGES, 32)];
static size_t free_pages_cnt = BACKING_STORE_PAGES;

int k_mem_paging_backing_store_location_get(struct k_mem_page_frame *pf,
					    uintptr_t *location,
					    bool page_fault)
{
#if BACKING_STORE_READ_ONLY
	LOG_ERR("Backing store can't store any page");
	return -ENOMEM;
#else
	int page_idx = -1;
	int id;

	if ((!page_fault && free_pages_cnt == 1) || free_pages_cnt == 0) {
		return -ENOMEM;
	}

	for (int i = 0; i < ARRAY_SIZE(free_pages); i++) {
		id = find_lsb_set(free_pages[i]) - 1;
		if (id != -1) {
			page_idx = i * 32 + id;
			free_pages[i] &= ~BIT(id);
			*location = page_idx * CONFIG_MMU_PAGE_SIZE;
			break;
		}
	}
	__ASSERT(page_idx != -1, "Free data page should be available");
	free_pages_cnt--;

	return 0;
#endif
}

void k_mem_paging_backing_store_location_free(uintptr_t location)
{
	int index = location / CONFIG_MMU_PAGE_SIZE;
	int id = index / 32;

	__ASSERT(id < ARRAY_SIZE(free_pages), "Bad location");

	free_pages[id] |= BIT(index % 32);
	free_pages_cnt++;
}

void k_mem_paging_backing_store_page_out(uintptr_t location)
{
#if BACKING_STORE_READ_ONLY
	/* No need to store in backing store as it will be paged in from application binary file */
	ARG_UNUSED(location);
#else
	long fd = semihost_open(backing_store_file, SEMIHOST_OPEN_AB);

	semihost_seek(fd, location);
	semihost_write(fd, K_MEM_SCRATCH_PAGE, CONFIG_MMU_PAGE_SIZE);
	semihost_close(fd);
#endif
}

void k_mem_paging_backing_store_page_in(uintptr_t location)
{
#if BACKING_STORE_READ_ONLY

#else
	long fd = semihost_open(backing_store_file, SEMIHOST_OPEN_RB);

	semihost_seek(fd, location);
	semihost_read(fd, K_MEM_SCRATCH_PAGE, CONFIG_MMU_PAGE_SIZE);
	semihost_close(fd);
#endif
}

void k_mem_paging_backing_store_page_finalize(struct k_mem_page_frame *pf,
					      uintptr_t location)
{
#ifdef CONFIG_DEMAND_MAPPING
	/* ignore those */
	if (location == ARCH_UNPAGED_ANON_ZERO || location == ARCH_UNPAGED_ANON_UNINIT) {
		return;
	}
#endif
	k_mem_paging_backing_store_location_free(location);
}

void k_mem_paging_backing_store_init(void)
{
	memset(free_pages, 0xFF, sizeof(free_pages));
}
