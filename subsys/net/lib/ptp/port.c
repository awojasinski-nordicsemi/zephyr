/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_port, CONFIG_PTP_LOG_LEVEL);

#include <stdbool.h>

#include "port.h"
#include "msg.h"

static bool ptp_port_ignore_msg(struct ptp_port *port, struct ptp_msg *msg);
static void ptp_port_ds_init(struct ptp_port *port);

static bool ptp_port_ignore_msg(struct ptp_port *port, struct ptp_msg *msg)
{
	if (ptp_port_id_eq(msg->header.src_port_id, port->port_ds.id)) {
		return true;
	}

	return false;
}

static void ptp_port_ds_init(struct ptp_port *port)
{
	struct ptp_port_ds *ds = &port->dataset;
	struct ptp_clock *clock = port->clock;

	/* static */
	memcpy(&ds->id.clk_id, &clock->default_ds.clk_id, sizeof(ptp_clk_id));
	ds->id.port_number = clock->default_ds.n_ports;

	/* dynamic */
	ds->state = PTP_PS_INITIALIZING;
	ds->log_min_delay_req_interval = CONFIG_PTP_DALAY_REQ_INTERVAL;
	ds->announce_receipt_timeout = CONFIG_PTP_ANNOUNCE_RECV_TIMEOUT;
	ds->log_sync_interval = CONFIG_PTP_SYNC_INTERVAL;
	ds->delay_mechanism = ;
	ds->log_min_pdelay_req_interval = CONFIG_PTP_PDALAY_REQ_INTERVAL;
	ds->version = PTP_VERSION;
	ds->delay_asymmetry = 0;
}

void ptp_port_open(struct net_if *iface, void *user_data)
{
	struct ptp_clock *clock = (struct ptp_clock *)user_data;

	if (clock->default_ds.n_ports > CONFIG_PTP_NUM_PORTS) {
		return;
	}

	struct ptp_port *p = &clock->ports[clock->default_ds.n_ports];

	p->clock = clock;

	ptp_port_ds_init(p);

	p->state_machine = clock->default_ds.slave_only ? ptp_so_state_machine : ptp_state_machine;

	clock->default_ds.n_ports++;
}

enum ptp_port_state ptp_port_state(struct ptp_port *port)
{
	return port->port_ds.state;
}

bool ptp_port_enabled(struct ptp_port *port)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state == PTP_PS_FAULTY ||
	    state == PTP_PS_DISABLED ||
	    state == PTP_PS_INITIALIZING) {
		return false;
	}
	return true;
}

bool ptp_port_id_eq(const struct ptp_port_id *p1, const struct ptp_port_id *p2) {
	return memcmp(p1, p2, sizeof(struct ptp_port_id)) == 0;
}

enum ptp_port_event ptp_port_event_gen(struct ptp_port *port)
{
	enum ptp_port_event event;
	struct ptp_msg *msg;

	if (ptp_port_ignore_msg(port, msg)) {
		return PTP_EVT_NONE;
	}

	switch (ptp_msg_type_get(msg))
	{
	case PTP_MSG_SYNC:
		ptp_sync_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_REQ:
		ptp_delay_req_msg_process(port, msg);
		break;
	case PTP_MSG_PDELAY_REQ:
		/* code */
		break;
	case PTP_MSG_PDELAY_RESP:
		/* code */
		break;
	case PTP_MSG_FOLLOW_UP:
		ptp_follow_up_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_RESP:
		ptp_delay_resp_msg_process(port, msg);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		/* code */
		break;
	case PTP_MSG_ANNOUNCE:
		if (ptp_announce_msg_process(port, msg)) {
			event = PTP_EVT_STATE_DECISION;
		}
		break;
	case PTP_MSG_SIGNALING:
		/* code */
		break;
	case PTP_MSG_MANAGEMENT:
		/* code */
		break;
	default:
		break;
	}

	return event;
}

void ptp_port_event_handle(struct ptp_port *port, enum ptp_port_event event, bool master_diff)
{
	if (ptp_port_state_update(port, event, master_diff)) {
		return;
	}
}

int ptp_port_state_update(struct ptp_port *port, enum ptp_port_event event, bool master_diff)
{
	enum ptp_port_state next_state = port->state_machine(ptp_port_state(port),
							     event,
							     master_diff);

	if (next_state == PTP_PS_INITIALIZING) {
		if (ptp_port_enabled(port)) {
			ptp_port_disable(port);
		}
		if (ptp_port_initialize(port)) {
			event = PTP_EVT_FAULT_DETECTED;
		} else {
			event = PTP_EVT_INIT_COMPLETE;
		}
		next_state = port->state_machine(next_state, event, false);
	}

	if (next_state != ptp_port_state(port)) {
		port->port_ds.state = next_state;
		return 1;
	}

	return 0;
}

int ptp_port_add_foreign_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign;
	bool foreign_present = false;

	for (int i = 0; i < CONFIG_PTP_FOREIGN_MASTER_LIST_SIZE; i++) {
		foreign = &port->foreigns[i];

		/* check whether the foreign clock entry is used */
		if (foreign->port == NULL) {
			break;
		}
		if (ptp_msg_src_equal(msg, foreign)) {
			foreign_present = true;
			break;
		}
	}

	// TODO solve issue when list of foreigns is full

	if (!foreign_present) {
		memcpy(&foreign->recent_msg, msg, sizeof(ptp_announce_msg));
		foreign->port_id = port->port_ds.id;
		foreign->port = port;
		foreign->dataset.sender = msg->header.src_port_id;

		return 0;
	}

}

int ptp_port_update_current_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign = port->best;

	if (!ptp_msg_src_equal(msg, foreign)) {
		return ptp_port_add_foreign_master(port, msg);
	}


	return 0;
}
