/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_port, CONFIG_PTP_LOG_LEVEL);

#include <stdbool.h>

#include <zephyr/net/ptp.h>

#include "clock.h"
#include "port.h"
#include "msg.h"
#include "transport.h"

#define DEFAULT_LOG_MSG_INTERVAL (0x7F)

static bool port_ignore_msg(struct ptp_port *port, struct ptp_msg *msg)
{
	if (ptp_port_id_eq(&msg->header.src_port_id, &port->port_ds.id)) {
		return true;
	}

	return false;
}

static void port_ds_init(struct ptp_port *port)
{
	struct ptp_port_ds *ds = &port->port_ds;
	struct ptp_clock *clock = port->clock;

	/* static */
	memcpy(&ds->id.clk_id, &clock->default_ds.clk_id, sizeof(ptp_clk_id));
	ds->id.port_number = clock->default_ds.n_ports + 1;

	/* dynamic */
	ds->state = PTP_PS_INITIALIZING;
	ds->log_min_delay_req_interval = CONFIG_PTP_DELAY_REQ_INTERVAL;
	ds->log_announce_interval = CONFIG_PTP_ANNOUNCE_INTERVAL;
	ds->announce_receipt_timeout = CONFIG_PTP_ANNOUNCE_RECV_TIMEOUT;
	ds->log_sync_interval = CONFIG_PTP_SYNC_INTERVAL;
	ds->delay_mechanism = (enum ptp_delay_mechanism)CONFIG_PTP_DELAY_MECHANISM;
	ds->log_min_pdelay_req_interval = CONFIG_PTP_PDALAY_REQ_INTERVAL;
	ds->version = PTP_VERSION;
	ds->delay_asymmetry = 0;
}

static int port_initialize(struct ptp_port *port)
{
	if (ptp_transport_open(port)) {
		LOG_ERR("Couldn't open socket.");
		return -1;
	}

	ptp_clock_pollfd_invalidate(port->clock);
	return 0;
}

static void port_disable(struct ptp_port *port)
{
	ptp_transport_close(port);
	ptp_port_free_foreign_masters(port);

	port->best = NULL;
	port->socket = -1;
	ptp_clock_pollfd_invalidate(port->clock);
}

static void port_timer_init(struct k_timer *timer, k_timer_expiry_t timeout_fn, void *user_data)
{
	k_timer_init(timer, timeout_fn, NULL);
	k_timer_user_data_set(timer, user_data);
}

static void port_set_announce_timeout(struct ptp_port *port)
{

}

static void port_set_delay_timeout(struct ptp_port *port)
{

}

static void port_set_sync_rx_timeout(struct ptp_port *port)
{

}

static void port_set_sync_tx_timeout(struct ptp_port *port)
{

}

static void port_set_qualification_timeout(struct ptp_port *port)
{
	uint32_t timeout = (port->clock->current_ds.steps_rm + 1) *
			   (2 << port->port_ds.log_announce_interval);

	k_timer_start(port->qualification_timer, K_SECONDS(timeout), K_NO_WAIT);
}

static void port_announce_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->announce_timer) {
			port->announce_t_expired = true;
		}
	}
}

static void port_delay_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->delay_timer) {
			port->delay_t_expired = true;
		}
	}
}

static void port_sync_rx_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->sync_rx_timer) {
			port->sync_rx_t_expired = true;
		}
	}
}

static void port_sync_tx_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->sync_tx_timer) {
			port->sync_tx_t_expired = true;
		}
	}
}

static void port_qualification_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->announce_timer) {
			port->announce_t_expired = true;
		}
	}
}

static void port_p2p_transition(struct ptp_port *port, enum ptp_port_state next_state)
{
	k_timer_stop(&port->delay_timer);
	k_timer_stop(&port->announce_timer);
	k_timer_stop(&port->sync_rx_timer);
	k_timer_stop(&port->sync_tx_timer);
	k_timer_stop(&port->qualification_timer);

	switch (next_state) {
	case PTP_PS_INITIALIZING:
		break;
	case PTP_PS_FAULTY:
	case PTP_PS_DISABLED:
		port_disable(port);
		break;
	case PTP_PS_LISTENING:
		port_set_announce_timeout(port);
		port_set_delay_timeout(port);
		break;
	case PTP_PS_PRE_MASTER:
		port_set_qualification_timeout(port);
		break;
	case PTP_PS_GRAND_MASTER:
	case PTP_PS_MASTER:
		if (!p->inhibit_announce) {
			set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
		}
		port_set_sync_tx_timeout(port);
		break;
	case PTP_PS_PASSIVE:
		port_set_announce_timeout(port);
		break;
	case PTP_PS_UNCALIBRATED:
		flush_last_sync(p);
		flush_peer_delay(p);
		/* fall through */
	case PTP_PS_SLAVE:
		port_set_announce_timeout(port);
		break;
	};
}

static void port_e2e_transition(struct ptp_port *port, enum ptp_port_state next_state)
{
	k_timer_stop(&port->delay_timer);
	k_timer_stop(&port->announce_timer);
	k_timer_stop(&port->sync_rx_timer);
	k_timer_stop(&port->sync_tx_timer);
	k_timer_stop(&port->qualification_timer);

	switch (next_state) {
	case PTP_PS_INITIALIZING:
		break;
	case PTP_PS_FAULTY:
	case PTP_PS_DISABLED:
		port_disable(port);
		break;
	case PTP_PS_LISTENING:
		port_set_announce_timeout(port);
		port_set_delay_timeout(port);
		break;
	case PTP_PS_PRE_MASTER:
		port_set_qualification_timeout(port);
		break;
	case PTP_PS_GRAND_MASTER:
	case PTP_PS_MASTER:
		if (!p->inhibit_announce) {
			set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
		}
		port_set_sync_tx_timeout(port);
		break;
	case PTP_PS_PASSIVE:
		port_set_announce_timeout(port);
		break;
	case PTP_PS_UNCALIBRATED:
		flush_last_sync(p);
		flush_peer_delay(p);
		/* fall through */
	case PTP_PS_SLAVE:
		port_set_announce_timeout(port);
		break;
	};
}

static void port_pdelay_timer_to(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);


}

int port_announce_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	int ret = 0;

	switch (ptp_port_state(port))
	{
	case PTP_PS_INITIALIZING:
	case PTP_PS_DISABLED:
	case PTP_PS_FAULTY:
		break;
	case PTP_PS_LISTENING:
	case PTP_PS_PRE_MASTER:
	case PTP_PS_MASTER:
	case PTP_PS_GRAND_MASTER:
#if CONFIG_PTP_FOREIGN_MASTER_FEATURE
		ret = ptp_port_add_foreign_master(port, msg);
		break;
#endif
	case PTP_PS_SLAVE:
	case PTP_PS_UNCALIBRATED:
	case PTP_PS_PASSIVE:
		ret = ptp_port_update_current_master(port, msg);
		break;
	default:
		break;
	}

	return ret;
}


void port_sync_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_SLAVE && state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (ptp_check_if_current_parent(port, msg)) {
		return;
	}

	if (!(msg->header.flags[0] && PTP_MSG_TWO_STEP_FLAG)) {
		ptp_clock_adj(port->clock,);
	}
}

void port_follow_up_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_SLAVE && state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (ptp_check_if_current_parent(port, msg)) {
		return;
	}
}

int port_delay_req_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);
	struct ptp_msg *resp;

	if (state != PTP_PS_MASTER && state != PTP_PS_GRAND_MASTER) {
		return;
	}

	// TODO prepare delay_resp message
	resp = ptp_msg_allocate();
	if (!resp) {
		LOG_ERR("Couldn't allocate memory for the message");
		return -1;
	}

	resp->header.version = PTP_VERSION;
	resp->header.msg_length = sizeof(struct ptp_delay_resp_msg);
	resp->header.src_port_id = port->port_ds.id;
	resp->header.log_msg_interval = port->port_ds.log_min_delay_req_interval;
	resp->header.sequence_id = msg->header.sequence_id;
	resp->header.req_port_id = msg->header.src_port_id;

	if (msg->header.flags && PTP_MSG_UNICAST_FLAG) {
		// do stuff specific for unicast message
		resp->header.flags[0] |= PTP_MSG_UNICAST_FLAG;
		resp->header.log_msg_interval = DEFAULT_LOG_MSG_INTERVAL;
	}

	ptp_port_send(port, resp);
}

void port_delay_resp_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{

}

static void foreign_clock_cleanup(struct ptp_foreign_master_clock *foreign)
{
	struct ptp_msg *msg;
	int64_t time, timeout, current = k_uptime_get();

	while (foreign->messages_count > FOREIGN_MASTER_THRESHOLD) {
		(void*)k_fifo_get(foreign->messages, K_NO_WAIT);
		foreign->messages_count--;
		// TODO free memory for new message
	}

	/* Remove messages that don't arrived at
	   FOREIGN_MASTER_TIME_WINDOW (4 * announce interval) - IEEE 1588-2019 9.3.2.4.5 */
	while (!k_fifo_is_empty(foreign->messages)) {
		msg = (struct ptp_msg*)k_fifo_peek_head(foreign->messages);
		time = msg->timestamp.host.seconds * MSEC_PER_SEC +
		       msg->timestamp.host.nanoseconds * NSEC_PER_MSEC;

		if (msg->header.log_msg_interval <= -31) {
			timeout = 0;
		} else if (msg->header.log_msg_interval >= 31) {
			timeout = INT64_MAX;
		} else if (msg->header.log_msg_interval > 0) {
			timeout = FOREIGN_MASTER_TIME_WINDOW_MUL *
				  (1 << msg->header.log_msg_interval) * NSEC_PER_MSEC;
		} else {
			timeout = FOREIGN_MASTER_TIME_WINDOW_MUL * NSEC_PER_MSEC /
				  (1 << (-msg->header.log_msg_interval));
		}

		if (current - time < timeout) {
			/* Remaining messages are within time window */
			break;
		}

		(void*)k_fifo_get(foreign->messages, K_NO_WAIT);
		foreign->messages_count--;
		// TODO free memory for new message
	}
}

void ptp_port_open(struct net_if *iface, void *user_data)
{
	struct ptp_clock *clock = (struct ptp_clock *)user_data;

	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return;
	}

	if (clock->default_ds.n_ports > CONFIG_PTP_NUM_PORTS) {
		LOG_WRN("Exceeded number of PTP Ports.");
		return;
	}

	struct ptp_port *port = (struct ptp_port *)k_malloc(sizeof(*port));

	if (!port) {
		LOG_ERR("Couldn't open the PTP Port.");
		return;
	}

	port->clock = clock;
	port->iface = iface;
	port->best = NULL;
	port->socket = -1;

	port->state_machine = clock->default_ds.slave_only ?
		ptp_so_state_machine : ptp_state_machine;

	port_ds_init(port);
	sys_slist_init(&port->foreign_list);

	port_timer_init(&port->delay_timer, port_delay_timer_to, user_data);
	port_timer_init(&port->announce_timer, port_announce_timer_to, user_data);
	port_timer_init(&port->sync_rx_timer, port_sync_rx_timer_to, user_data);
	port_timer_init(&port->sync_tx_timer, port_sync_tx_timer_to, user_data);
	port_timer_init(&port->qualification_timer, port_qualification_timer_to, user_data);

	clock->default_ds.n_ports++;
	if (ptp_clock_realloc_pollfd(clock, clock->default_ds.n_ports)) {
		LOG_ERR("Couldn't allocate space for file descriptors.");
		k_free(port);
		return;
	}

	ptp_clock_pollfd_invalidate(clock);
	sys_slist_append(&clock->ports_list, &port->node);
	LOG_DBG("PTP Port %d opened", port->port_ds.id.port_number);
}

void ptp_port_close(struct ptp_port *port)
{
	if (ptp_port_enabled(port)) {
		port_disable(port);
	}

	if (sys_slist_find_and_remove(&port->clock->ports_list, &port->node)) {
		port->clock->default_ds.n_ports--;
	}

	k_free(port);
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

bool ptp_port_id_eq(const struct ptp_port_id *p1, const struct ptp_port_id *p2)
{
	return memcmp(p1, p2, sizeof(struct ptp_port_id)) == 0;
}

struct ptp_dataset *ptp_port_best_foreign_ds(struct ptp_port *port)
{
	return port->best ? &port->best->dataset : NULL;
}

enum ptp_port_event ptp_port_event_gen(struct ptp_port *port)
{
	enum ptp_port_event event;
	struct ptp_msg *msg;

	if (port->announce_t_expierd) {
		port->announce_t_expierd = false;
		return PTP_EVT_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES;
	}

	if (port_ignore_msg(port, msg)) {
		return PTP_EVT_NONE;
	}

	switch (ptp_msg_type_get(msg))
	{
	case PTP_MSG_SYNC:
		port_sync_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_REQ:
		port_delay_req_msg_process(port, msg);
		break;
	case PTP_MSG_PDELAY_REQ:
		/* code */
		break;
	case PTP_MSG_PDELAY_RESP:
		/* code */
		break;
	case PTP_MSG_FOLLOW_UP:
		port_follow_up_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_RESP:
		port_delay_resp_msg_process(port, msg);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		/* code */
		break;
	case PTP_MSG_ANNOUNCE:
		if (port_announce_msg_process(port, msg)) {
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
	if (!ptp_port_state_update(port, event, master_diff)) {
		return;
	}

	if (port->port_ds.delay_mechanism == PTP_DM_P2P) {
		port_p2p_transition(port, ptp_port_state(port));
	} else {
		port_e2e_transition(port, ptp_port_state(port));
	}
}

int ptp_port_state_update(struct ptp_port *port, enum ptp_port_event event, bool master_diff)
{
	enum ptp_port_state next_state = port->state_machine(ptp_port_state(port),
							     event,
							     master_diff);

	if (next_state == PTP_PS_INITIALIZING) {
		if (ptp_port_enabled(port)) {
			port_disable(port);
		}
		if (port_initialize(port)) {
			event = PTP_EVT_FAULT_DETECTED;
		} else {
			event = PTP_EVT_INIT_COMPLETE;
		}
		next_state = port->state_machine(next_state, event, false);
	}

	if (next_state != ptp_port_state(port)) {
		port->port_ds.state = next_state;
		LOG_DBG("PTP Port %d changed state to %s",
			port->port_ds.id.port_number,
			ptp_state_machine_state_str(next_state));
		return 1;
	}

	return 0;
}

int ptp_port_add_foreign_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign;
	struct ptp_msg *last;
	int diff = 0;


	SYS_SLIST_FOR_EACH_CONTAINER(&port->foreign_list, foreign, node) {
		if (ptp_msg_src_equal(msg, foreign)) {
			break;
		}
	}

	if (!foreign) {

		LOG_DBG("Port %d: new foreign master %s",
			port->port_ds.id.port_number,
			port_id_to_str(&msg->header.src_port_id));

		foreign = k_malloc(sizeof(*foreign));
		if (!foreign) {
			LOG_ERR("Couldn't allocate memory for new foreign master");
			return 0;
		}

		memset(foreign, 0, sizeof(*foreign));
		memcpy(&foreign->dataset.sender,
		       &msg->header.src_port_id,
		       sizeof(foreign->dataset.sender));
		k_fifo_init(foreign->messages);
		foreign->port = port;

		sys_slist_append(&port->foreign_list, &foreign->node);

		return 0;
	}

	foreign_clock_cleanup(foreign);

	foreign->messages_count++;
	k_fifo_put(foreign->messages, (void*)msg);

	if (foreign->messages_count > 1) {
		last = (struct ptp_msg*)k_fifo_peek_tail(foreign->messages);
		diff = ptp_announce_msg_cmp(msg, last);
	}

	return (foreign->messages_count == FOREIGN_MASTER_THRESHOLD ? 1 : 0) || diff;
}

int ptp_port_update_current_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign = port->best;

	if (!ptp_msg_src_equal(msg, foreign)) {
		return ptp_port_add_foreign_master(port, msg);
	}

	foreign_clock_cleanup(foreign);
	k_fifo_put(foreign->messages, (void*)msg);
	foreign->messages_count++;
	port_set_announce_timeout(port);

	if (foreign->messages_count > 1) {
		struct ptp_msg *last = (struct ptp_msg *)k_fifo_peek_tail(foreign->messages);

		return ptp_announce_msg_cmp(msg, last);
	}

	return 0;
}
