/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_clock, CONFIG_PTP_LOG_LEVEL);

#include <stdlib.h>
#include <string.h>

#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>

#include "net_private.h"

#include "bmca.h"
#include "ddt.h"
#include "clock.h"
#include "port.h"
#include "tlv.h"

static struct ptp_clock domain_clock = { 0 };

static int clock_generate_id(ptp_clk_id *clock_id, struct net_if *iface)
{
	struct net_linkaddr *addr = net_if_get_link_addr(iface);

	if (addr) {
		clock_id->id[0] = addr->addr[0];
		clock_id->id[1] = addr->addr[1];
		clock_id->id[2] = addr->addr[2];
		clock_id->id[3] = 0xFF;
		clock_id->id[4] = 0xFE;
		clock_id->id[5] = addr->addr[3];
		clock_id->id[6] = addr->addr[4];
		clock_id->id[7] = addr->addr[5];
		return 0;
	}
	return -1;
}

static const char *clock_id_str(ptp_clk_id *clock_id)
{
	static char id[] = "FF:FF:FF:FF:FF:FF:FF:FF";
	uint8_t *cid = clock_id->id;

	snprintk(id, strlen(id), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		 cid[0],
		 cid[1],
		 cid[2],
		 cid[3],
		 cid[4],
		 cid[5],
		 cid[6],
		 cid[7]);

	return id;
}

static int clock_update_pollfd(struct zsock_pollfd *dest, struct ptp_port *port)
{
	dest->fd = port->socket;
	dest->events = ZSOCK_POLLIN | ZSOCK_POLLPRI;

	return 1;
}

static int clock_parent_ds_cmp(struct ptp_parent_ds *a, struct ptp_parent_ds *b)
{
	//TODO implement function
	return 0;
}

void ptp_clock_check_pollfd(struct ptp_clock *clock)
{
	struct ptp_port *port;
	struct zsock_pollfd *fd = clock->pollfd;

	if (clock->pollfd_valid) {
		return;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		fd += clock_update_pollfd(fd, port);
	}

	clock->pollfd_valid = true;
}

void ptp_clock_pollfd_invalidate(struct ptp_clock *clock)
{
	clock->pollfd_valid = false;
}

struct ptp_port *ptp_clock_get_port_from_iface(struct net_if *iface)
{
	struct ptp_clock *clock = &domain_clock;
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (port->iface == iface) {
			return port;
		}
	}

	return NULL;
}

void ptp_clock_update_grandmaster(struct ptp_clock *clock)
{
	struct ptp_parent_ds old_parent = clock->parent_ds;

	memset(&clock->current_ds, 0, sizeof(clock->current_ds));

	memcpy(&clock->parent_ds.port_id.clk_id,
	       &clock->default_ds.clk_id,
	       sizeof(clock->default_ds.clk_id));
	memcpy(&clock->parent_ds.gm_id,
	       &clock->default_ds.clk_id,
	       sizeof(clock->default_ds.clk_id));
	clock->parent_ds.port_id.port_number = 0;
	clock->parent_ds.gm_clk_quality = clock->default_ds.clk_quality;
	clock->parent_ds.gm_priority1 = clock->default_ds.priority1;
	clock->parent_ds.gm_priority2 = clock->default_ds.priority2;

	clock->time_prop_ds.current_utc_offset = 0; //TODO IEEE 1588-2019 9.4
	clock->time_prop_ds.time_src = clock->time_src;
	clock->time_prop_ds.flags = 0; //TODO IEEE 1588-2019 9.4

	if (clock_parent_ds_cmp(&old_parent, &clock->parent_ds)) {
		//TODO send notification to subscribers.
	}
}

void ptp_clock_update_slave(struct ptp_clock *clock)
{
	struct ptp_msg *best_msg = (struct ptp_msg *)(&clock->best->messages);

	clock->current_ds.steps_rm = 1 + clock->best->dataset.steps_rm;

	memcpy(&clock->parent_ds.gm_id,
	       &best_msg->announce.gm_id,
	       sizeof(best_msg->announce.gm_id));
	memcpy(&clock->parent_ds.port_id,
	       &clock->best->dataset.sender,
	       sizeof(clock->best->dataset.sender));
	clock->parent_ds.gm_clk_quality = best_msg->announce.gm_clk_quality;
	clock->parent_ds.gm_priority1 = best_msg->announce.gm_priority1;
	clock->parent_ds.gm_priority2 = best_msg->announce.gm_priority2;

	clock->time_prop_ds.current_utc_offset = best_msg->announce.current_utc_offset;
	clock->time_prop_ds.flags = best_msg->header.flags[1];
	clock->time_prop_ds.time_src = best_msg->announce.time_src;
}

struct ptp_dataset *ptp_clock_default_ds(struct ptp_clock *clock)
{
	struct ptp_dataset *dds = &clock->dataset;

	dds->priority1		  = clock->default_ds.priority1;
	dds->clk_quality	  = clock->default_ds.clk_quality;
	dds->priority2		  = clock->default_ds.priority2;
	dds->steps_rm		  = 0;
	dds->sender.port_number	  = 0;
	dds->receiver.port_number = 0;
	memcpy(&dds->clk_id, &clock->default_ds.clk_id, sizeof(ptp_clk_id));
	memcpy(&dds->sender.clk_id, &clock->default_ds.clk_id, sizeof(ptp_clk_id));
	memcpy(&dds->receiver.clk_id, &clock->default_ds.clk_id, sizeof(ptp_clk_id));
	return dds;
}

struct ptp_dataset *ptp_clock_best_foreign_ds(struct ptp_clock *clock)
{
	return clock->best ? &clock->best->dataset : NULL;
}

struct ptp_clock *ptp_clock_init(void)
{
	struct ptp_clock *clock = &domain_clock;
	struct ptp_default_ds *dds = &clock->default_ds;
	struct ptp_parent_ds *pds  = &clock->parent_ds;
	struct net_if *iface = net_if_get_first_by_type(&NET_L2_GET_NAME(ETHERNET));

	clock->time_src = (enum ptp_time_src)PTP_TIME_SRC_INTERNAL_OSC;

	/* Initialize Default Dataset. */
	int ret = clock_generate_id(&dds->clk_id, iface);
	if (ret) {
		LOG_ERR("Couldn't assign Clock Identity.");
		return NULL;
	}

	dds->type = (enum ptp_clock_type)CONFIG_PTP_CLOCK_TYPE;
	dds->n_ports = 0;
	dds->slave_only = IS_ENABLED(CONFIG_PTP_SLAVE_ONLY) ? true : false;

	dds->clk_quality.class = dds->slave_only ? 255 : 248;
	dds->clk_quality.accuracy = CONFIG_PTP_CLOCK_ACCURACY;
	/* 0xFFFF means that value has not been computed - IEEE 1588-2019 7.6.3.3 */
	dds->clk_quality.offset_scaled_log_variance = 0xFFFF;

	dds->max_steps_rm = 255;

	dds->priority1 = CONFIG_PTP_PRIORITY1;
	dds->priority2 = CONFIG_PTP_PRIORITY2;

	/* Initialize Parent Dataset. */
	ptp_clock_update_grandmaster(clock);
	pds->obsreved_parent_offset_scaled_log_variance = 0xFFFF;
	pds->obsreved_parent_clk_phase_change_rate = 0x7FFFFFFF;
	/* Parent statistics haven't been measured - IEEE 1588-2019 7.6.4.2 */
	pds->stats = false;

	clock->phc = net_eth_get_ptp_clock(iface);
	if (!clock->phc) {
		LOG_ERR("Couldn't get PTP HW Clock for the interface.");
		return NULL;
	}

	sys_slist_init(&clock->subs_list);
	sys_slist_init(&clock->ports_list);
	LOG_DBG("PTP Clock %s initialized", clock_id_str(&dds->clk_id));
	return clock;
}

bool ptp_clock_id_eq(const ptp_clk_id *c1, const ptp_clk_id *c2)
{
	return memcmp(c1, c2, sizeof(ptp_clk_id)) == 0;
}
