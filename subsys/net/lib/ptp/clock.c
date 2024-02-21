/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_clock, CONFIG_PTP_LOG_LEVEL);

#include "bmca.h"
#include "clock.h"
#include "port.h"

static void ptp_clock_update_grandmaster(struct ptp_clock *clock);
static void ptp_clock_update_slave(struct ptp_clock *clock);
static void ptp_handle_state_decision_evt(struct ptp_clock *clock)

static struct ptp_clock clock = {
	.type = (enum ptp_clock_type)CONFIG_PTP_CLOCK_TYPE;
	.default_ds = {
		.n_ports = 0,
		.domain = 0,
		.clk_quality = {
			.accuracy = CONFIG_PTP_CLOCK_ACCURACY,
		},
		.priority1 = CONFIG_PTP_PRIORITY1,
		.priority2 = CONFIG_PTP_PRIORITY2,
		.slave_only = CONFIG_PTP_SLAVE_ONLY,
		.inst_type = CONFIG_PTP_CLOCK_TYPE,
	},
	.current_ds = {

	},
	.parent_ds = {

	},
	.time_prop_ds = {

	}
};

/* 9.3.5 Table 30 - Updates for state decision code M1 and M2 */
static void ptp_clock_update_grandmaster(struct ptp_clock *clock)
{
	memset(&clock->current_ds, 0, sizeof(clock->current_ds));

	clock->parent_ds.port_id.clk_id = clock->default_ds.clk_id;
	clock->parent_ds.port_id.port_number = 0;
	clock->parent_ds.gm_id = clock->default_ds.clk_id;
	clock->parent_ds.gm_clk_quality = clock->default_ds.clk_quality;
	clock->parent_ds.gm_priority1 = clock->default_ds.priority1;
	clock->parent_ds.gm_priority2 = clock->default_ds.priority2;

	clock->time_prop_ds;
}

/* 9.3.5 Table 33 - Updates for state decision code S1 */
static void ptp_clock_update_slave(struct ptp_clock *clock)
{
	struct ptp_msg *best_msg = clock->best->recent_msg;

	clock->current_ds.steps_rm = 1 + clock->best->dataset.steps_rm;

	clock->parent_ds.port_id = clock->best->dataset.sender;
	clock->parent_ds.gm_id = best_msg->announce.gm_id;
	clock->parent_ds.gm_clk_quality = best_msg->announce.gm_clk_quality;
	clock->parent_ds.gm_priority1 = best_msg->announce.gm_priority1;
	clock->parent_ds.gm_priority2 = best_msg->announce.gm_priority2;

	clock->time_prop_ds.current_utc_offset = best_msg->announce.current_utc_offset;
	clock->time_prop_ds.current_utc_offset_valid = ;
	clock->time_prop_ds.time_src = best_msg->announce.time_src;

}

static void ptp_handle_state_decision_evt(struct ptp_clock *clock)
{
	struct ptp_clk_id best_id;
	struct ptp_port *port;

	for (int inst = 0; inst < clock->default_ds.n_ports; inst++) {
		enum ptp_port_state state;
		enum ptp_port_event evt;

		port = clock->port[inst];
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

struct ptp_clock *ptp_clock_init()
{
	struct ptp_clock *clk = &clock;
	struct ptp_default_ds *dds = &clk->default_ds;

	/* Initialize default_ds */
	if (dds->slave_only) {
		dds->clk_quality.class = 255;
	} else {
		dds->clk_quality.class = 248;
	}
	dds->clk_quality.offset_scaled_log_variance = //TODO;

	return clk;
}

void ptp_clock_poll_events(struct ptp_clock *clock)
{
	struct ptp_port *port;
	enum ptp_port_event event;

	for (int i = 0; i < clock->default_ds.n_ports; i++) {
		port = clock->ports[i];
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
