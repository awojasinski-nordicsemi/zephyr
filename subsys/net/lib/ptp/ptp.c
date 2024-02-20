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

#include "clock.h"
#include "port.h"

K_KERNEL_STACK_DEFINE(ptp_stack, CONFIG_PTP_STACK_SIZE);
K_FIFO_DEFINE(ptp_rx_queue);

static struct k_thread ptp_thread_data;

static void ptp_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (1) {
		struct net_pkt *pkt;

		pkt = k_fifo_get(&ptp_rx_queue, K_MSEC(1));
		if (pkt) {

		}

	}
}

void ptp_init(void)
{
	k_tid_t tid;
	struct ptp_clock *clock = ptp_clock_init();

	net_if_foreach(ptp_port_open, (void *)clock);


	tid = k_thread_create(&ptp_thread_data, ptp_stack, K_KERNEL_STACK_SIZEOF(ptp_stack),
			      ptp_thread, NULL, NULL, NULL, K_PRIO_COOP(5), K_NO_WAIT);
	k_thread_name_set(&ptp_thread_data, "PTP");
}
