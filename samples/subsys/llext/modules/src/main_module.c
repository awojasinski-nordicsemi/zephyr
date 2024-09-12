/*
 * Copyright (c) 2024 Arduino SA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(app);

#include <zephyr/llext/llext.h>
#include <zephyr/llext/buf_loader.h>
#include <zephyr/llext/fs_loader.h>

#if CONFIG_FILE_SYSTEM
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>

#define LLEXT_FILE "hello_world.llext"

#define PARTITION_NODE DT_NODELABEL(lfs1)

#if DT_NODE_EXISTS(PARTITION_NODE)
FS_FSTAB_DECLARE_ENTRY(PARTITION_NODE);
#else
FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(storage);
static struct fs_mount_t lfs_storage_mnt = {
	.type = FS_LITTLEFS,
	.fs_data = &storage,
	.storage_dev = (void *)FIXED_PARTITION_ID(storage_partition),
	.mnt_point = "/lfs",
};
#endif

struct fs_mount_t *mountpoint =
#if DT_NODE_EXISTS(PARTITION_NODE)
	&FS_FSTAB_ENTRY(PARTITION_NODE);
#else
	&lfs_storage_mnt;
#endif
#endif /* CONFIG_FILE_SYSTEM */

static uint8_t llext_buf[] = {
#include "hello_world_ext.inc"
};

int main(void)
{
	LOG_INF("Calling hello world as a module");

	char path[UINT8_MAX] = {0};
	size_t llext_buf_len = ARRAY_SIZE(llext_buf);
	struct llext_buf_loader buf_loader = LLEXT_BUF_LOADER(llext_buf, llext_buf_len);

#if CONFIG_HELLO_WORLD_LLEXT_FS
	struct fs_file_t fd;

	/* File system should be mounted before the main. If not mount it now. */
	if (!(mountpoint->flags & FS_MOUNT_FLAG_AUTOMOUNT)) {
		if (fs_mount(mountpoint)) {
			LOG_ERR("Failed to mount filesystem");
			return -EFAULT;
		}
	}

	snprintf(path, sizeof(path), "%s/%s", mountpoint->mnt_point, LLEXT_FILE);

	LOG_INF("Opening %s", path);
	fs_file_t_init(&fd);
	if (fs_open(&fd, path, FS_O_CREATE | FS_O_TRUNC | FS_O_WRITE) != 0) {
		LOG_ERR("Failed to create file %s", path);
		return -EFAULT;
	}

	LOG_INF("Writing extension to file");
	if (fs_write(&fd, llext_buf, ARRAY_SIZE(llext_buf)) != ARRAY_SIZE(llext_buf)) {
		LOG_ERR("Failed to write to the file");
		return -EIO;
	}

	LOG_INF("Extension loaded to file");
	fs_close(&fd);

#endif /* CONFIG_FILE_SYSTEM */
	struct llext_fs_loader fs_loader = LLEXT_FS_LOADER(path);
	struct llext_loader *ldr =
		IS_ENABLED(CONFIG_FILE_SYSTEM) ? &fs_loader.loader : &buf_loader.loader;

	struct llext_load_param ldr_parm = LLEXT_LOAD_PARAM_DEFAULT;
	struct llext *ext;
	int res;

	res = llext_load(ldr, "ext", &ext, &ldr_parm);
	if (res != 0) {
		LOG_ERR("Failed to load extension, return code %d\n", res);
		return res;
	}

	void (*hello_world_fn)() = llext_find_sym(&ext->exp_tab, "hello_world");

	if (hello_world_fn == NULL) {
		LOG_ERR("Failed to find symbol\n");
		return -1;
	}

	hello_world_fn();

	return llext_unload(&ext);
}
