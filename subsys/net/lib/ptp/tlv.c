/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_port, CONFIG_PTP_LOG_LEVEL);

#include <stdbool.h>

#include <zephyr/net/ptp.h>

#include "msg.h"
#include "tlv.h"

enum ptp_mgmt_op ptp_mgmt_action_get(struct ptp_msg *msg) {
	(enum ptp_mgmt_op)msg->management.action;
}
