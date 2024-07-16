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
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>

#if !FIXED_PARTITION_EXISTS(backing_store)
#error "Backing store partition is not defined"
#endif

LOG_MODULE_REGISTER(backing_store_flash, LOG_LEVEL_DBG);

#define FLASH_DEV	     FIXED_PARTITION_DEVICE(backing_store)
#define BACKING_STORE_SIZE   FIXED_PARTITION_SIZE(backing_store)
#define BACKING_STORE_OFFSET FIXED_PARTITION_OFFSET(backing_store)
#define BACKING_STORE_PAGES  (BACKING_STORE_SIZE / CONFIG_MMU_PAGE_SIZE)

static struct k_mutex lock;

static uint32_t free_pages[DIV_ROUND_UP(BACKING_STORE_PAGES, 32)];
static size_t free_pages_cnt = BACKING_STORE_PAGES;

static const struct device *const flash_dev = FLASH_DEV;

int k_mem_paging_backing_store_location_get(struct k_mem_page_frame *pf,
					    uintptr_t *location,
					    bool page_fault)
{
	int page_idx = -1;
	int id;

	if ((!page_fault && free_pages_cnt == 1) || free_pages_cnt == 0) {
		return -ENOMEM;
	}

	k_mutex_lock(&lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(free_pages); i++) {
		id = find_lsb_set(free_pages[i]) - 1;
		if (id != -1) {
			page_idx = i * 32 + id;
			free_pages[i] &= ~BIT(id);
			*location = page_idx * CONFIG_MMU_PAGE_SIZE;
			break;
		}
	}

	if (page_idx == -1) {
		k_mutex_unlock(&lock);
		return -ENOMEM;
	}

	free_pages_cnt--;

	k_mutex_unlock(&lock);
	return 0;
}

void k_mem_paging_backing_store_location_free(uintptr_t location)
{
	int index = location / CONFIG_MMU_PAGE_SIZE;
	int id = index / 32;

	__ASSERT(id < ARRAY_SIZE(free_pages), "Bad location");

	k_mutex_lock(&lock, K_FOREVER);
	free_pages[id] |= BIT(index % 32);
	free_pages_cnt++;
	k_mutex_unlock(&lock);
}

void k_mem_paging_backing_store_page_out(uintptr_t location)
{
	if (CONFIG_FLASH_HAS_EXPLICIT_ERASE) {
		flash_erase(flash_dev, location, CONFIG_MMU_PAGE_SIZE);
	}
	flash_write(flash_dev, location, K_MEM_SCRATCH_PAGE, CONFIG_MMU_PAGE_SIZE);
}

void k_mem_paging_backing_store_page_in(uintptr_t location)
{
	flash_read(flash_dev, location, K_MEM_SCRATCH_PAGE, CONFIG_MMU_PAGE_SIZE);
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
	k_mutex_init(&lock);
}
