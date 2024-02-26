/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_clock, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>

#include "net_private.h"

#include "bmca.h"
#include "clock.h"
#include "port.h"

static int ptp_clock_generate_id(ptp_clk_id *clk_id, const struct ptp_port *port);

static struct ptp_clock clock = { 0 };

static int ptp_clock_generate_id(ptp_clk_id *clk_id, struct net_if *iface)
{
	struct net_linkaddr addr = net_if_get_link_addr(iface);

	if (addr) {
		clk_id[0] = addr.addr[0];
		clk_id[1] = addr.addr[1];
		clk_id[2] = addr.addr[2];
		clk_id[3] = 0xFF;
		clk_id[4] = 0xFE;
		clk_id[5] = addr.addr[3];
		clk_id[6] = addr.addr[4];
		clk_id[7] = addr.addr[5];
		return 0;
	}
	return -1;
}

void ptp_clock_update_grandmaster(struct ptp_clock *clock)
{
	memset(&clock->current_ds, 0, sizeof(clock->current_ds));

	clock->parent_ds.port_id.clk_id = clock->default_ds.clk_id;
	clock->parent_ds.port_id.port_number = 0;
	clock->parent_ds.gm_id = clock->default_ds.clk_id;
	clock->parent_ds.gm_clk_quality = clock->default_ds.clk_quality;
	clock->parent_ds.gm_priority1 = clock->default_ds.priority1;
	clock->parent_ds.gm_priority2 = clock->default_ds.priority2;

	clock->time_prop_ds.current_utc_offset = ; //TODO
	clock->time_prop_ds.time_src = clock->time_src;
	clock->time_prop_ds.flags = ; //TODO

	//TODO compare parent ds before and after if changed send notification to subscribers.
}

void ptp_clock_update_slave(struct ptp_clock *clock)
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

char *ptp_clock_sprint_clk_id()
{
	net_sprint_ll_addr_buf();
}

struct ptp_clock *ptp_clock_init()
{
	int ret;
	struct ptp_clock *clk = &clock;
	struct ptp_default_ds *dds = &clk->default_ds;
	struct ptp_current_ds *cds = &clk->current_ds;
	struct ptp_parent_ds *pds  = &clk->parent_ds;

	clk->time_src = (enum ptp_time_src)PTP_TIME_SRC_INTERNAL_OSC;

	/* Initialize Default Dataset. */
	ret = ptp_clock_generate_id(&dds->clk_id,
				    net_if_get_first_by_type(&NET_L2_GET_NAME(ETHERNET)));
	if (ret) {
		LOG_ERR("Couldn't assign Clock Identity");
		return NULL;
	}

	dds->type = (enum ptp_clock_type)CONFIG_PTP_CLOCK_TYPE;

	dds->clk_quality.class = CONFIG_PTP_SLAVE_ONLY ? 255 : 248;
	dds->clk_quality.accuracy = CONFIG_PTP_CLOCK_ACCURACY;
	dds->clk_quality.offset_scaled_log_variance = ;//TODO

	dds->max_steps_rm = ;//TODO

	dds->priority1 = CONFIG_PTP_PRIORITY1;
	dds->priority2 = CONFIG_PTP_PRIORITY2;

	/* Initialize Parent Dataset. */
	ptp_clock_update_grandmaster(clk);
	pds->obsreved_parent_offset_scaled_log_variance = 0xFFFF;
	pds->obsreved_parent_clk_phase_change_rate = 0x7FFFFFFF;

	clk->ptp_clock = net_eth_get_ptp_clock(net_if_get_default());

	return clk;
}
