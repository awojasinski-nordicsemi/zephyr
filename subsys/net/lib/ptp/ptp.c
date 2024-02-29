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

static void ptp_handle_state_decision_evt(struct ptp_clock *clock);
static void ptp_handle_critical_msg(void);
static void ptp_handle_msg(void);
static void ptp_poll_events();
static void ptp_thread(void *p1, void *p2, void *p3);

static void ptp_handle_state_decision_evt(struct ptp_clock *clock)
{
	struct ptp_port *port;
	ptp_clk_id best_id;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		enum ptp_port_state state;
		enum ptp_port_event   ;

		state = ptp_bmca_state_decision(port);

		switch (state)
		{
		case PTP_PS_GRAND_MASTER:
			ptp_clock_update_grandmaster(clock);
			break;
		default:
			break;
		}
	}
}


static void ptp_handle_critical_msg()
{

}

static void ptp_handle_msg()
{

}

static void ptp_poll_events(struct ptp_clock *clock)
{
	struct ptp_port *port;
	enum ptp_port_event event;
	int cnt;

	ptp_clock_check_pollfd(clock);
	cnt = zsock_poll(clock->pollfd, clock->default_ds.n_ports, 0);

	if (!cnt) {
		return;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		event = ptp_port_event_gen(port);

		if (event == PTP_EVT_STATE_DECISION) {
			clock->state_decision_event = true;
		}

		ptp_port_event_handle(port, event, false);
	}

	if (clock->state_decision_event) {
		ptp_handle_state_decision_evt(clock);
		clock->state_decision_event = false;
	}
}

static void ptp_thread(void *p1, void *p2, void *p3)
{
	struct ptp_clock *clock = (struct ptp_clock *)p1;
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (1) {

		ptp_clock_poll_events(clock);

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
	struct ptp_port *port;

	if (!clock) {
		return;
	}

	net_if_foreach(ptp_port_open, (void *)clock);
	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		ptp_port_event_handle(port, PTP_EVT_INITIALIZE, false);
	}

	tid = k_thread_create(&ptp_thread_data, ptp_stack, K_KERNEL_STACK_SIZEOF(ptp_stack),
			      ptp_thread, clock, NULL, NULL, K_PRIO_COOP(5), K_NO_WAIT);
	k_thread_name_set(&ptp_thread_data, "PTP");
}
