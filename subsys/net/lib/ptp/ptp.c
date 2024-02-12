/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp, CONFIG_NET_PTP_LOG_LEVEL);

#include <zephyr/net/net_pkt.h>
#include <zephyr/drivers/ptp_clock.h>
#include <zephyr/net/ethernet_mgmt.h>
#include <zephyr/random/random.h>

#include <zephyr/net/ptp.h>

