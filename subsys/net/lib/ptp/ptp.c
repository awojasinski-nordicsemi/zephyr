/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ptp, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/drivers/ptp_clock.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/net/ethernet_mgmt.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ptp.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr_monitor.h>

#include "bmca.h"
#include "clock.h"
#include "port.h"
#include "transport.h"

#define NET_MGMT_EVT_MASK (NET_EVENT_L4_CONNECTED | \
			   NET_EVENT_L4_DISCONNECTED)

K_KERNEL_STACK_DEFINE(ptp_stack, CONFIG_PTP_STACK_SIZE);
K_FIFO_DEFINE(ptp_rx_queue);
K_SEM_DEFINE(ptp_sem, 0, 1);

static struct k_thread ptp_thread_data;

static struct net_mgmt_event_callback mgmt_cb;
void event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface);

static void ptp_handle_state_decision_evt(struct ptp_clock *clock)
{
	struct ptp_foreign_master_clock *best = NULL, *foreign;
	struct ptp_port *port;
	bool master_changed = false;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		foreign = ptp_port_compute_best_foreign(port);
		if (!foreign) {
			continue;
		}
		if (!best || ptp_bmca_ds_cmp(&foreign->dataset, &best->dataset)) {
			best = foreign;
		}
	}

	clock->best = best;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		enum ptp_port_state state;
		enum ptp_port_event event;

		state = ptp_bmca_state_decision(port);

		switch (state)
		{
		case PTP_PS_LISTENING:
			event = PTP_EVT_NONE;
			break;
		case PTP_PS_GRAND_MASTER:
			ptp_clock_update_grandmaster(clock);
			event = PTP_EVT_RS_GRAND_MASTER;
			break;
		case PTP_PS_MASTER:
			event = PTP_EVT_RS_MASTER;
			break;
		case PTP_PS_SLAVE:
			ptp_clock_update_slave(clock);
			event = PTP_EVT_RS_SLAVE;
			break;
		case PTP_PS_PASSIVE:
			event = PTP_EVT_RS_PASSIVE;
			break;
		default:
			event = PTP_EVT_FAULT_DETECTED;
			break;
		}

		ptp_port_event_handle(port, event, master_changed);
	}
}

#if CONFIG_NET_CONNECTION_MANAGER
void event_handler(struct net_mgmt_event_callback *cb,
		   uint32_t mgmt_event,
		   struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_L4_CONNECTED:
		LOG_DBG("Network connected");
		k_sem_give(&ptp_sem);
		break;
	case NET_EVENT_L4_DISCONNECTED:
		LOG_DBG("Network disconnected");
		k_sem_reset(&ptp_sem);
		break;
	default:
		break;
	}
}
#endif

static void ptp_thread(void *p1, void *p2, void *p3)
{
	struct ptp_clock *clock = (struct ptp_clock *)p1;
	struct ptp_port *port;
	struct zsock_pollfd *fd;
	enum ptp_port_event event;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	k_sem_take(&ptp_sem, K_FOREVER);

	while (1) {

		ptp_clock_check_pollfd(clock);
		zsock_poll(clock->pollfd, PTP_SOCKET_CNT * clock->default_ds.n_ports, 0);

		fd = clock->pollfd;

		SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {

			ptp_port_if_link_monitor(port);

			if (atomic_get(&port->timeouts) != 0) {
				struct k_timer *timers[] = {
					&port->timers.announce,
					&port->timers.delay,
					&port->timers.sync,
					&port->timers.qualification
				};

				for (int i = 0; i < ARRAY_SIZE(timers); i++) {
					event = ptp_port_event_gen(port, timers[i], -1);

					if (event == PTP_EVT_STATE_DECISION ||
					    event == PTP_EVT_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES) {
						clock->state_decision_event = true;
					}

					ptp_port_event_handle(port, event, false);
				}
			}

			for (int i = 0; i < PTP_SOCKET_CNT; i++) {
				if (!(fd->revents & (ZSOCK_POLLIN | ZSOCK_POLLPRI))) {
					fd++;
					continue;
				}

				event = ptp_port_event_gen(port, NULL, i);

				if (event == PTP_EVT_STATE_DECISION ||
				    event == PTP_EVT_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES) {
					clock->state_decision_event = true;
				}

				ptp_port_event_handle(port, event, false);
				fd++;
			}
		}

		if (clock->state_decision_event) {
			ptp_handle_state_decision_evt(clock);
			clock->state_decision_event = false;
		}

		k_msleep(10);
		//k_yield();
		//log_thread_trigger();
	}
}

static int ptp_init(void)
{
	k_tid_t tid;
	struct ptp_port *port;
	struct ptp_clock *clock = ptp_clock_init();

	if (!clock) {
		return -ENODEV;
	}

	if (IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		net_mgmt_init_event_callback(&mgmt_cb, event_handler, NET_MGMT_EVT_MASK);
		net_mgmt_add_event_callback(&mgmt_cb);

		conn_mgr_mon_resend_status();
	} else {
		k_sem_give(&ptp_sem);
	}

	net_if_foreach(ptp_port_init, (void *)clock);

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		ptp_port_event_handle(port, PTP_EVT_INITIALIZE, false);
	}

	tid = k_thread_create(&ptp_thread_data, ptp_stack, K_KERNEL_STACK_SIZEOF(ptp_stack),
			      ptp_thread, clock, NULL, NULL, K_PRIO_COOP(5), 0, K_NO_WAIT);
	k_thread_name_set(&ptp_thread_data, "PTP");

	return 0;
}

SYS_INIT(ptp_init, APPLICATION, CONFIG_NET_PTP_INIT_PRIO);
