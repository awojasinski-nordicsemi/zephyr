/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ptp_port, CONFIG_PTP_LOG_LEVEL);

#include <stdbool.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/ptp.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>

#include "clock.h"
#include "port.h"
#include "msg.h"
#include "transport.h"
#include "tlv.h"

#define DEFAULT_LOG_MSG_INTERVAL (0x7F)

struct ptp_port ports[CONFIG_PTP_NUM_PORTS];

static const char *port_id_str(struct ptp_port_id *port_id)
{
	static char id[] = "FF:FF:FF:FF:FF:FF:FF:FF-FFFF";
	uint8_t *pid = port_id->clk_id.id;

	snprintk(id, sizeof(id), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X-%04X",
		 pid[0],
		 pid[1],
		 pid[2],
		 pid[3],
		 pid[4],
		 pid[5],
		 pid[6],
		 pid[7],
		 port_id->port_number);

	return id;
}

static const char *port_state_str(enum ptp_port_state state) {
	static const char *states[] = {
		[PTP_PS_INITIALIZING] = "INITIALIZING",
		[PTP_PS_FAULTY]	      = "FAULTY",
		[PTP_PS_DISABLED]     = "DISABLED",
		[PTP_PS_LISTENING]    = "LISTENING",
		[PTP_PS_PRE_MASTER]   = "PRE MASTER",
		[PTP_PS_MASTER]	      = "MASTER",
		[PTP_PS_GRAND_MASTER] = "GRAND MASTER",
		[PTP_PS_PASSIVE]      = "PASSIVE",
		[PTP_PS_UNCALIBRATED] = "UNCALIBRATED",
		[PTP_PS_SLAVE]	      = "SLAVE",
	};

	return states[state];
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
	ds->log_min_delay_req_interval = CONFIG_PTP_MIN_DELAY_REQ_LOG_INTERVAL;
	ds->log_announce_interval = CONFIG_PTP_ANNOUNCE_LOG_INTERVAL;
	ds->announce_receipt_timeout = CONFIG_PTP_ANNOUNCE_RECV_TIMEOUT;
	ds->log_sync_interval = CONFIG_PTP_SYNC_LOG_INTERVAL;
	ds->delay_mechanism = (enum ptp_delay_mechanism)CONFIG_PTP_DELAY_MECHANISM;
	ds->log_min_pdelay_req_interval = CONFIG_PTP_MIN_PDELAY_REQ_LOG_INTERVAL;
	ds->version = PTP_VERSION;
	ds->delay_asymmetry = 0;
}

static void port_disable(struct ptp_port *port)
{
	ptp_transport_close(port);
	ptp_port_free_foreign_masters(port);

	k_timer_stop(&port->announce_timer);
	k_timer_stop(&port->master_announce_timer);
	k_timer_stop(&port->delay_timer);
	k_timer_stop(&port->sync_rx_timer);
	k_timer_stop(&port->sync_tx_timer);
	k_timer_stop(&port->qualification_timer);

	port->announce_t_expired = false;
	port->master_announce_t_expired = false;
	port->delay_t_expired = false;
	port->sync_rx_t_expired = false;
	port->sync_tx_t_expired = false;
	port->qualification_t_expired = false;

	port->best = NULL;
	ptp_clock_pollfd_invalidate(port->clock);
	LOG_DBG("Port %d disabled", port->port_ds.id.port_number);
}

static int port_msg_send(struct ptp_port *port, struct ptp_msg *msg)
{
	ptp_msg_pre_send(port->clock, msg);

	return ptp_transport_send(port, msg);
}

static void port_timer_init(struct k_timer *timer, k_timer_expiry_t timeout_fn, void *user_data)
{
	k_timer_init(timer, timeout_fn, NULL);
	k_timer_user_data_set(timer, user_data);
}

static void port_timer_set_timeout(struct k_timer *timer, uint8_t factor, int8_t log_seconds)
{
	int timeout = log_seconds < 0 ? (NSEC_PER_SEC * factor) >> (log_seconds * -1) :
					(NSEC_PER_SEC * factor) << log_seconds;

	k_timer_start(timer, K_NSEC(timeout), K_NO_WAIT);
}

static void port_timer_set_timeout_random(struct k_timer *timer,
					  int min_factor,
					  int span,
					  int log_seconds)
{
	int timeout, random_ns;

	if (log_seconds < 0) {
		timeout = (NSEC_PER_SEC * min_factor) >> -log_seconds;
		random_ns = NSEC_PER_SEC >> -log_seconds;
	} else {
		timeout = (NSEC_PER_SEC * min_factor) << log_seconds;
		random_ns = NSEC_PER_SEC << log_seconds;
	}

	timeout = timeout + (random_ns * (sys_rand32_get() % (1 << 15) + 1) >> 15);
	k_timer_start(timer, K_NSEC(timeout), K_NO_WAIT);
}

static int port_enable(struct ptp_port *port)
{
	while (!net_if_is_up(port->iface)) {
		k_sleep(K_SECONDS(1));
	}
	if (ptp_transport_open(port)) {
		LOG_ERR("Couldn't open socket on Port %d.", port->port_ds.id.port_number);
		return -1;
	}

	port->port_ds.enable = true;

	port_timer_set_timeout_random(&port->announce_timer,
				      port->port_ds.announce_receipt_timeout,
				      1,
				      port->port_ds.log_announce_interval);
	ptp_clock_pollfd_invalidate(port->clock);
	LOG_DBG("Port %d opened", port->port_ds.id.port_number);
	return 0;
}

static void port_timer_to_handler(struct k_timer *timer)
{
	struct ptp_clock *clock = (struct ptp_clock *)k_timer_user_data_get(timer);
	struct ptp_port *port;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		if (timer == &port->master_announce_timer) {
			port->master_announce_t_expired = true;
		} else if (timer == &port->announce_timer) {
			port->announce_t_expired = true;
		} else if (timer == &port->sync_rx_timer) {
			port->sync_rx_t_expired = true;
		} else if (timer == &port->delay_timer) {
			port->delay_t_expired = true;
		} else if (timer == &port->sync_tx_timer) {
			port->sync_tx_t_expired = true;
		} else if (timer == &port->qualification_timer) {
			port->qualification_t_expired = true;
		}
	}
}

static void port_sync_timestamp_cb(struct net_pkt *pkt)
{
	struct ptp_port *port = ptp_clock_get_port_from_iface(pkt->iface);
	struct ptp_msg *msg = ptp_msg_get_from_pkt(pkt);

	if (!port || !msg) {
		return;
	}

	msg->header.src_port_id.port_number = ntohs(msg->header.src_port_id.port_number);

	if (ptp_port_id_eq(&port->port_ds.id, &msg->header.src_port_id) &&
	    ptp_msg_type_get(msg) == PTP_MSG_SYNC) {

		struct ptp_clock *clock = port->clock;
		struct ptp_msg *resp = ptp_msg_alloc();

		if (!resp) {
			return;
		}

		resp->header.type_major_sdo_id = PTP_MSG_FOLLOW_UP;
		resp->header.version	       = PTP_VERSION;
		resp->header.msg_length	       = sizeof(struct ptp_follow_up_msg);
		resp->header.domain_number     = clock->default_ds.domain;
		resp->header.flags[1]	       = clock->time_prop_ds.flags;
		resp->header.src_port_id       = port->port_ds.id;
		resp->header.sequence_id       = port->seq_id.sync++;
		resp->header.log_msg_interval  = port->port_ds.log_sync_interval;

		resp->follow_up.precise_origin_timestamp.seconds_high = pkt->timestamp._sec.high;
		resp->follow_up.precise_origin_timestamp.seconds_low = pkt->timestamp._sec.low;
		resp->follow_up.precise_origin_timestamp.nanoseconds = pkt->timestamp.nanosecond;

		port_msg_send(port, resp);
		ptp_msg_unref(resp);

		LOG_DBG("Port %d sends Follow_Up message", port->port_ds.id.port_number);

		port->sync_ts_cb_registered = false;
		net_if_unregister_timestamp_cb(&port->sync_ts_cb);
	}
}

#if 0
static void port_pdelay_resp_timestamp_cb(struct net_pkt *pkt)
{
	struct ptp_port *port = ptp_clock_get_port_from_iface(pkt->iface);
	struct ptp_msg *msg = ptp_msg_get_from_pkt(pkt);

	if (!port) {
		return;
	}

	if (ptp_msg_type_get(ptp_msg_get_from_pkt(pkt)) == PTP_MSG_PDELAY_RESP) {

		struct ptp_clock *clock = port->clock;
		struct ptp_msg *resp = ptp_msg_alloc();

		if (!resp) {
			return;
		}

		resp->header.type_major_sdo_id = PTP_MSG_PDELAY_RESP_FOLLOW_UP;
		resp->header.version	       = PTP_VERSION;
		resp->header.msg_length	       = sizeof(struct ptp_pdelay_resp_follow_up_msg);
		resp->header.domain_number     = clock->default_ds.domain;
		resp->header.flags[1]	       = clock->time_prop_ds.flags;
		resp->header.src_port_id       = port->port_ds.id;
		resp->header.sequence_id       = port->seq_id.delay;
		resp->header.log_msg_interval  = port->port_ds.log_sync_interval;

		resp->pdelay_resp_follow_up.resp_origin_timestamp.seconds_high =
			pkt->timestamp._sec.high;
		resp->pdelay_resp_follow_up.resp_origin_timestamp.seconds_low =
			pkt->timestamp._sec.low;
		resp->pdelay_resp_follow_up.resp_origin_timestamp.nanoseconds =
			pkt->timestamp.nanosecond;

		port_msg_send(port, msg);
		ptp_msg_unref(msg);

		port->pdelay_resp_ts_cb_registered = false;
		net_if_unregister_timestamp_cb(&port->pdelay_resp_ts_cb);
	}
}
#endif

static void port_synchronize(struct ptp_port *port,
			     struct ptp_timestamp ingress_ts,
			     struct ptp_timestamp origin_ts,
			     int64_t correction1,
			     int64_t correction2)
{
	// TODO Implement PTP Instance adjustment IEEE 1588-2019 12.1 and 11.2
	uint64_t t1, t2, t1c, offset;

	port_timer_set_timeout(&port->sync_rx_timer, 3, port->port_ds.log_sync_interval);

	t1 = origin_ts.seconds * NSEC_PER_SEC + origin_ts.nanoseconds;
	t2 = ingress_ts.seconds * NSEC_PER_SEC + ingress_ts.nanoseconds;
	t1c = t1 + (correction1 >> 16) + (correction2 >> 16);

	offset = t2 - t1c;
}

static void port_sync_fup_ooo_handle(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_msg *last = port->last_sync_fup;

	if (ptp_msg_type_get(msg) != PTP_MSG_FOLLOW_UP &&
	    ptp_msg_type_get(msg) != PTP_MSG_SYNC) {
		return;
	}

	if (!last) {
		port->last_sync_fup = msg;
		msg->ref++;
		return;
	}

	if (ptp_msg_type_get(last) == PTP_MSG_SYNC &&
	    ptp_msg_type_get(msg) == PTP_MSG_FOLLOW_UP &&
	    msg->header.sequence_id == last->header.sequence_id) {

			port_synchronize(port,
					 last->timestamp.host,
					 msg->timestamp.protocol,
					 last->header.correction,
					 msg->header.correction);

			ptp_msg_unref(port->last_sync_fup);
			port->last_sync_fup = NULL;
	} else if (ptp_msg_type_get(last) == PTP_MSG_FOLLOW_UP &&
		   ptp_msg_type_get(msg) == PTP_MSG_SYNC &&
		   msg->header.sequence_id == last->header.sequence_id) {

			port_synchronize(port,
					 msg->timestamp.host,
					 last->timestamp.protocol,
					 msg->header.correction,
					 last->header.correction);

			ptp_msg_unref(port->last_sync_fup);
			port->last_sync_fup = NULL;
	} else {
		ptp_msg_unref(port->last_sync_fup);
		port->last_sync_fup = msg;
		msg->ref++;
	}
}

static int port_announce_msg_process(struct ptp_port *port, struct ptp_msg *msg)
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

	ptp_msg_unref(msg);
	return ret;
}


static void port_sync_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_SLAVE && state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (!ptp_msg_current_parent_check(port, msg)) {
		return;
	}

	if (port->port_ds.log_sync_interval != msg->header.log_msg_interval) {
		port->port_ds.log_sync_interval = msg->header.log_msg_interval;
	}

	msg->header.correction += port->port_ds.delay_asymmetry;

	if (!(msg->header.flags[0] && PTP_MSG_TWO_STEP_FLAG)) {
		// TODO adjust PTP Clock
		port_synchronize(port,
				 msg->timestamp.host,
				 msg->timestamp.protocol,
				 msg->header.correction,
				 0);

		if (port->last_sync_fup) {
			ptp_msg_unref(port->last_sync_fup);
			port->last_sync_fup = NULL;
		}

		return;
	}

	port_sync_fup_ooo_handle(port, msg);
	return;
}

static void port_follow_up_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_SLAVE && state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (!ptp_msg_current_parent_check(port, msg)) {
		return;
	}

	port_sync_fup_ooo_handle(port, msg);
}

static int port_delay_req_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	int ret;
	enum ptp_port_state state = ptp_port_state(port);
	struct ptp_msg *resp;

	if (state != PTP_PS_MASTER && state != PTP_PS_GRAND_MASTER) {
		return 0;
	}

	resp = ptp_msg_alloc();
	if (!resp) {
		return -ENOMEM;
	}

	resp->header.type_major_sdo_id = PTP_MSG_DELAY_RESP;
	resp->header.version	       = PTP_VERSION;
	resp->header.msg_length	       = sizeof(struct ptp_delay_resp_msg);
	resp->header.domain_number     = port->clock->default_ds.domain;
	resp->header.correction	       = msg->header.correction;
	resp->header.src_port_id       = port->port_ds.id;
	resp->header.sequence_id       = msg->header.sequence_id;
	resp->header.log_msg_interval  = port->port_ds.log_min_delay_req_interval;

	// TODO handle timestamp properly
	resp->delay_resp.receive_timestamp.seconds_high = (msg->timestamp.host.seconds >> 32) &
							  UINT16_MAX;
	resp->delay_resp.receive_timestamp.seconds_low = msg->timestamp.host.seconds & UINT32_MAX;
	resp->delay_resp.receive_timestamp.nanoseconds = msg->timestamp.host.nanoseconds;
	resp->delay_resp.req_port_id = msg->header.src_port_id;

	if (msg->header.flags[0] && PTP_MSG_UNICAST_FLAG) {
		// do stuff specific for unicast message
		// specify address for the message
		resp->header.flags[0] |= PTP_MSG_UNICAST_FLAG;
		resp->header.log_msg_interval = DEFAULT_LOG_MSG_INTERVAL;
	}

	ret = port_msg_send(port, resp);
	ptp_msg_unref(resp);

	if (ret < 0) {
		return -EFAULT;
	} else {
		LOG_DBG("Port %d responds to Delay_Req message", port->port_ds.id.port_number);
		return 0;
	}
}

static void port_delay_resp_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_UNCALIBRATED && state != PTP_PS_SLAVE) {
		return;
	}

	if (!ptp_port_id_eq(&msg->delay_resp.req_port_id, &port->port_ds.id)) {
		// Message is not meant for this PTP Port
		return;
	}

}

static void port_signaling_process(struct ptp_port *port,
				   struct ptp_port *ingress,
				   struct ptp_msg *msg)
{
	struct ptp_tlv_container *container;

	SYS_SLIST_FOR_EACH_CONTAINER(&msg->tlvs, container, node) {
		struct ptp_tlv *tlv = container->tlv;

		switch (tlv->type) {
		case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:
			break;
		case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
			break;
		case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:
			break;
		case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
			break;
		}
	}
}

static void port_signaling_msg_process(struct ptp_port *ingress, struct ptp_msg *msg)
{
	const static ptp_clk_id all_ones = {
		.id = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	};

	struct ptp_port_id *target_port = &msg->signaling.target_port_id;
	struct ptp_clock *clock = ingress->clock;
	struct ptp_port *port;
	enum ptp_port_state state = ptp_port_state(ingress);

	if (state == PTP_PS_INITIALIZING || state == PTP_PS_DISABLED || state == PTP_PS_FAULTY) {
		return;
	}

	if (!sys_slist_len(&msg->tlvs)) {
		return;
	}

	if (!ptp_clock_id_eq(&ingress->clock->default_ds.clk_id, &target_port->clk_id) &&
	    !ptp_clock_id_eq(&ingress->clock->default_ds.clk_id, &all_ones)) {
		// Message is not meant for this PTP Port
		return;
	}

	if (target_port->port_number == ingress->port_ds.id.port_number) {
		port_signaling_process(ingress, ingress, msg);
	} else if (target_port->port_number == UINT16_MAX) {
		SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
			port_signaling_process(port, ingress, msg);
		}
	}

}

static int port_announce_msg_transmit(struct ptp_port *port)
{
	struct ptp_clock *clock = port->clock;
	struct ptp_msg *msg = ptp_msg_alloc();
	int ret;

	if (!msg) {
		return -ENOMEM;
	}

	msg->header.type_major_sdo_id = PTP_MSG_ANNOUNCE;
	msg->header.version	      = PTP_VERSION;
	msg->header.msg_length	      = sizeof(struct ptp_announce_msg);
	msg->header.domain_number     = clock->default_ds.domain;
	msg->header.flags[1]	      = clock->time_prop_ds.flags;
	msg->header.src_port_id	      = port->port_ds.id;
	msg->header.sequence_id	      = port->seq_id.announce++;
	msg->header.log_msg_interval  = port->port_ds.log_sync_interval;

	msg->announce.current_utc_offset = clock->time_prop_ds.current_utc_offset;
	msg->announce.gm_priority1	 = clock->parent_ds.gm_priority1;
	msg->announce.gm_clk_quality	 = clock->parent_ds.gm_clk_quality;
	msg->announce.gm_priority2	 = clock->parent_ds.gm_priority2;
	msg->announce.gm_id		 = clock->parent_ds.gm_id;
	msg->announce.steps_rm		 = clock->current_ds.steps_rm;
	msg->announce.time_src		 = clock->time_prop_ds.time_src;

	ret = port_msg_send(port, msg);
	ptp_msg_unref(msg);

	if (ret < 0) {
		return -EFAULT;
	} else {
		LOG_DBG("Port %d sends Announce message", port->port_ds.id.port_number);
		return 0;
	}
}

static int port_sync_msg_transmit(struct ptp_port *port)
{
	struct ptp_clock *clock = port->clock;
	struct ptp_msg *msg = ptp_msg_alloc();
	int ret;

	if (!msg) {
		return -ENOMEM;
	}

	msg->header.type_major_sdo_id = PTP_MSG_SYNC;
	msg->header.version	      = PTP_VERSION;
	msg->header.msg_length	      = sizeof(struct ptp_sync_msg);
	msg->header.domain_number     = clock->default_ds.domain;
	msg->header.flags[0]	      = PTP_MSG_TWO_STEP_FLAG;
	msg->header.flags[1]	      = clock->time_prop_ds.flags;
	msg->header.src_port_id	      = port->port_ds.id;
	msg->header.sequence_id	      = port->seq_id.sync;
	msg->header.log_msg_interval  = port->port_ds.log_sync_interval;

	net_if_register_timestamp_cb(&port->sync_ts_cb,
				     NULL,
				     port->iface,
				     port_sync_timestamp_cb);

	ret = port_msg_send(port, msg);
	ptp_msg_unref(msg);

	if (ret < 0) {
		return -EFAULT;
	} else {
		LOG_DBG("Port %d sends Sync message", port->port_ds.id.port_number);
		return 0;
	}
}

static struct ptp_msg *port_management_resp_prepare(struct ptp_port *port,
						    struct ptp_msg *req)
{
	struct ptp_msg *resp = ptp_msg_alloc();

	if (!resp) {
		return NULL;
	}

	resp->header.type_major_sdo_id = PTP_MSG_MANAGEMENT;
	resp->header.version	       = PTP_VERSION;
	resp->header.msg_length	       = sizeof(struct ptp_management_msg);
	resp->header.domain_number     = port->clock->default_ds.domain;
	resp->header.src_port_id       = port->port_ds.id;
	resp->header.sequence_id       = req->header.sequence_id;
	resp->header.log_msg_interval  = port->port_ds.log_min_delay_req_interval;

	if (req->management.action == PTP_MGMT_GET || req->management.action == PTP_MGMT_SET) {
		resp->management.action = PTP_MGMT_RESP;
	} else if (req->management.action == PTP_MGMT_CMD) {
		resp->management.action = PTP_MGMT_ACK;
	}

	memcpy(&resp->management.target_port_id,
	       &req->header.src_port_id,
	       sizeof(struct ptp_port_id));

	resp->management.starting_boundry_hops = req->management.starting_boundry_hops -
						 req->management.boundry_hops;
	resp->management.boundry_hops = resp->management.starting_boundry_hops;

	return resp;
}

static int port_management_resp_tlv_fill(struct ptp_port *port,
					 struct ptp_msg *req,
					 struct ptp_msg *resp,
					 struct ptp_tlv_mgmt *req_mgmt)
{
	struct ptp_clock *clock = port->clock;
	struct ptp_tlv *tlv;
	struct ptp_tlv_mgmt *mgmt;
	struct ptp_tlv_container *container  = ptp_tlv_alloc();
	int length = 0;

	if (!container) {
		return -ENOMEM;
	}

	tlv = container->tlv;
	tlv = (struct ptp_tlv *)resp->management.suffix;
	mgmt = (struct ptp_tlv_mgmt *)tlv;
	mgmt->type = PTP_TLV_TYPE_MANAGEMENT;
	mgmt->id = req_mgmt->id;

	switch (mgmt->id) {
	case PTP_MGMT_DEFAULT_DATA_SET:
		memcpy(mgmt->data, &clock->default_ds, sizeof(clock->default_ds));
		length = sizeof(clock->default_ds);
		break;
	case PTP_MGMT_CURRENT_DATA_SET:
		memcpy(mgmt->data, &clock->current_ds, sizeof(clock->current_ds));
		length = sizeof(clock->current_ds);
		break;
	case PTP_MGMT_PARENT_DATA_SET:
		memcpy(mgmt->data, &clock->parent_ds, sizeof(clock->parent_ds));
		length = sizeof(clock->parent_ds);
		break;
	case PTP_MGMT_TIME_PROPERTIES_DATA_SET:
		memcpy(mgmt->data, &clock->time_prop_ds, sizeof(clock->time_prop_ds));
		length = sizeof(clock->time_prop_ds);
		break;
	case PTP_MGMT_PORT_DATA_SET:
		memcpy(mgmt->data, &port->port_ds, sizeof(port->port_ds));
		length = sizeof(port->port_ds);
		break;
	case PTP_MGMT_PRIORITY1:
		*mgmt->data = clock->default_ds.priority1;
		length = sizeof(clock->default_ds.priority1);
		break;
	case PTP_MGMT_PRIORITY2:
		*mgmt->data = clock->default_ds.priority2;
		length = sizeof(clock->default_ds.priority2);
		break;
	case PTP_MGMT_DOMAIN:
		*mgmt->data = clock->default_ds.domain;
		length = sizeof(clock->default_ds.domain);
		break;
	case PTP_MGMT_SLAVE_ONLY:
		*mgmt->data = clock->default_ds.slave_only;
		length = sizeof(clock->default_ds.slave_only);
		break;
	case PTP_MGMT_LOG_ANNOUNCE_INTERVAL:
		*mgmt->data = port->port_ds.log_announce_interval;
		length = sizeof(port->port_ds.log_announce_interval);
		break;
	case PTP_MGMT_LOG_SYNC_INTERVAL:
		*mgmt->data = port->port_ds.log_sync_interval;
		length = sizeof(port->port_ds.log_sync_interval);
		break;
	case PTP_MGMT_VERSION_NUMBER:
		*mgmt->data = port->port_ds.version;
		length = sizeof(port->port_ds.version);
		break;
	case PTP_MGMT_CLOCK_ACCURACY:
		*mgmt->data = clock->default_ds.clk_quality.accuracy;
		length = sizeof(clock->default_ds.clk_quality.accuracy);
		break;
	case PTP_MGMT_UTC_PROPERTIES:
		break;
	case PTP_MGMT_TIMESCALE_PROPERTIES:
		break;
	case PTP_MGMT_UNICAST_NEGOTIATION_ENABLE:
		break;
	case PTP_MGMT_UNICAST_MASTER_TABLE:
		break;
	case PTP_MGMT_UNICAST_MASTER_MAX_TABLE_SIZE:
		break;
	case PTP_MGMT_DELAY_MECHANISM:
		*(uint16_t *)mgmt->data = port->port_ds.delay_mechanism;
		length = sizeof(port->port_ds.delay_mechanism);
		break;
	default:
		ptp_tlv_free(container);
		return -EINVAL;
	}

	/* Management TLV length shall be an even number */
	if (length % 2) {
		mgmt->data[length] = 0;
		length++;
	}

	tlv->length = sizeof(mgmt->id) + length;
	resp->header.msg_length += sizeof(*tlv) + length;
	sys_slist_append(&resp->tlvs, &container->node);

	return 0;
}

static int port_management_resp(struct ptp_port *port,
				struct ptp_msg *req,
				struct ptp_tlv_mgmt *mgmt_tlv)
{
	int ret;
	struct ptp_msg *resp = port_management_resp_prepare(port, req);

	if (!resp) {
		return -ENOMEM;
	}

	ret = port_management_resp_tlv_fill(port, req, resp, mgmt_tlv);
	if (ret) {
		return ret;
	}

	ret = port_msg_send(port, resp);
	ptp_msg_unref(resp);

	if (ret) {
		return -EFAULT;
	} else {
		LOG_DBG("Port %d sends Menagement message response", port->port_ds.id.port_number);
		return 0;
	}
}

static int port_management_error(struct ptp_port *port, struct ptp_msg *msg, enum ptp_mgmt_err err)
{
	int ret;
	struct ptp_tlv *tlv;
	struct ptp_tlv_mgmt_err *mgmt_err;
	struct ptp_tlv_mgmt *mgmt = (struct ptp_tlv_mgmt *)msg->management.suffix;

	struct ptp_msg *resp = port_management_resp_prepare(port, msg);

	if (!resp) {
		return -ENOMEM;
	}

	tlv = ptp_msg_add_tlv(resp, sizeof(struct ptp_tlv_mgmt_err));

	if (!tlv) {
		ptp_msg_unref(resp);
		return -ENOMEM;
	}

	mgmt_err = (struct ptp_tlv_mgmt_err *)tlv;

	mgmt_err->type = PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS;
	mgmt_err->length = 8;
	mgmt_err->err_id = err;
	mgmt_err->id = mgmt->id;

	ret = port_msg_send(port, resp);
	ptp_msg_unref(resp);

	if (ret) {
		return -EFAULT;
	} else {
		LOG_DBG("Port %d sends Menagement Error message", port->port_ds.id.port_number);
		return 0;
	}
}

static void port_management_forward(struct ptp_port *ingress, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(ingress);
	struct ptp_clock *clock = ingress->clock;
	struct ptp_port *port;

	if (clock->default_ds.type != PTP_CLOCK_TYPE_BOUNDARY) {
		/* Clocks other than Boundary Clock shouldn't retransmit messages. */
		return;
	}

	if (!msg->header.flags[0] && PTP_MSG_UNICAST_FLAG) {
		return;
	}

	if (state != PTP_PS_MASTER &&
	    state != PTP_PS_PRE_MASTER &&
	    state != PTP_PS_SLAVE &&
	    state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (msg->management.boundry_hops == 0) {
		return;
	}

	msg->management.boundry_hops--;

	SYS_SLIST_FOR_EACH_CONTAINER(&clock->ports_list, port, node) {
		//struct ptp_msg *forward;
		enum ptp_port_state cur_port_state = ptp_port_state(port);

		if (port == ingress) {
			continue;
		}

		if (cur_port_state != PTP_PS_MASTER &&
		    cur_port_state != PTP_PS_PRE_MASTER &&
		    cur_port_state != PTP_PS_SLAVE &&
		    cur_port_state != PTP_PS_UNCALIBRATED) {
			continue;
		}
	}
}

static int port_management_clock_set(struct ptp_port *port,
				     struct ptp_msg *req,
				     struct ptp_tlv_mgmt *tlv)
{
	bool send_resp = false;

	switch (tlv->id) {
	case PTP_MGMT_PRIORITY1:
		port->clock->default_ds.priority1 = *tlv->data;
		send_resp = true;
		break;
	case PTP_MGMT_PRIORITY2:
		port->clock->default_ds.priority2 = *tlv->data;
		send_resp = true;
		break;
	}

	return send_resp ? port_management_resp(port, req, tlv) : 0;
}

static int port_management_set(struct ptp_port *port,
			       struct ptp_msg *req,
			       struct ptp_tlv_mgmt *tlv)
{
	bool send_resp = false;

	switch (tlv->id) {
	case PTP_MGMT_LOG_ANNOUNCE_INTERVAL:
		port->port_ds.log_announce_interval = *tlv->data;
		send_resp = true;
		break;
	case PTP_MGMT_LOG_SYNC_INTERVAL:
		port->port_ds.log_sync_interval = *tlv->data;
		send_resp = true;
		break;
	case PTP_MGMT_UNICAST_NEGOTIATION_ENABLE:
		// TODO unicast
		break;
	}

	return send_resp ? port_management_resp(port, req, tlv) : 0;
}

static int port_management_process(struct ptp_port *port,
				   struct ptp_port *ingress,
				   struct ptp_msg *msg,
				   struct ptp_tlv_mgmt *tlv)
{
	int ret = 0;
	 //TODO check if message applies to this port

	if (ptp_mgmt_action_get(msg) == PTP_MGMT_SET) {
		ret = port_management_set(port, msg, tlv);
	} else {
		ret = port_management_resp(port, msg, tlv);
	}

	return ret;
}


static bool port_management_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	static const ptp_clk_id all_ones = {
		.id = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	};

	bool state_decision_required = false;
	struct ptp_port_id *target_port = &msg->management.target_port_id;
	struct ptp_tlv_mgmt *mgmt = (struct ptp_tlv_mgmt *)msg->management.suffix;
	struct ptp_port *p;

	if (!ptp_clock_id_eq(&port->clock->default_ds.clk_id, &target_port->clk_id) &&
	    !ptp_clock_id_eq(&port->clock->default_ds.clk_id, &all_ones)) {
		return state_decision_required;
	}

	if (sys_slist_len(&msg->tlvs) != 1) {
		/* IEEE 1588-2019 15.3.2 - PTP mgmt msg transports single mgmt TLV */
		return state_decision_required;
	}

	port_management_forward(port, msg);

	if (ptp_mgmt_action_get(msg) == PTP_MGMT_SET) {
		if (port_management_clock_set(port, msg, mgmt)) {
			return state_decision_required;
		}
		state_decision_required = true;
	}

	switch(mgmt->id) {
	case PTP_MGMT_CLOCK_DESCRIPTION:
		break;
	case PTP_MGMT_USER_DESCRIPTION:
		break;
	case PTP_MGMT_SAVE_IN_NON_VOLATILE_STORAGE:
	case PTP_MGMT_RESET_NON_VOLATILE_STORAGE:
		port_management_error(port, msg, PTP_MGMT_ERR_NOT_SUPPORTED);
		break;
	case PTP_MGMT_INITIALIZE:
		break;
	case PTP_MGMT_FAULT_LOG:
		break;
	case PTP_MGMT_FAULT_LOG_RESET:
		break;
	case PTP_MGMT_DOMAIN:
		break;
	case PTP_MGMT_SLAVE_ONLY:
		break;
	case PTP_MGMT_ANNOUNCE_RECEIPT_TIMEOUT:
		break;
	case PTP_MGMT_VERSION_NUMBER:
		break;
	case PTP_MGMT_ENABLE_PORT:
		break;
	case PTP_MGMT_DISABLE_PORT:
		break;
	case PTP_MGMT_TIME:
		break;
	case PTP_MGMT_CLOCK_ACCURACY:
		break;
	case PTP_MGMT_UTC_PROPERTIES:
		break;
	case PTP_MGMT_TRACEBILITY_PROPERTIES:
		break;
	case PTP_MGMT_TIMESCALE_PROPERTIES:
		break;
	case PTP_MGMT_UNICAST_NEGOTIATION_ENABLE:
		break;
	case PTP_MGMT_PATH_TRACE_LIST:
		break;
	case PTP_MGMT_PATH_TRACE_ENABLE:
		break;
	case PTP_MGMT_GRANDMASTER_CLUSTER_TABLE:
		break;
	case PTP_MGMT_UNICAST_MASTER_TABLE:
		break;
	case PTP_MGMT_UNICAST_MASTER_MAX_TABLE_SIZE:
		break;
	case PTP_MGMT_ACCEPTABLE_MASTER_TABLE:
		break;
	case PTP_MGMT_ACCEPTABLE_MASTER_TABLE_ENABLED:
		break;
	case PTP_MGMT_ACCEPTABLE_MASTER_MAX_TABLE_SIZE:
		break;
	case PTP_MGMT_ALTERNATE_MASTER:
		break;
		break;
		break;
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_ENABLE:
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_NAME:
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_MAX_KEY:
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_PROPERTIES:
	case PTP_MGMT_EXTERNAL_PORT_CONFIGURATION_ENABLED:
	case PTP_MGMT_MASTER_ONLY:
	case PTP_MGMT_HOLDOVER_UPGRADE_ENABLE:
	case PTP_MGMT_EXT_PORT_CONFIG_PORT_DATA_SET:
	case PTP_MGMT_TRANSPARENT_CLOCK_DEFAULT_DATA_SET:
	case PTP_MGMT_TRANSPARENT_CLOCK_PORT_DATA_SET:
	case PTP_MGMT_PRIMARY_DOMAIN:
		break;
	case PTP_MGMT_DELAY_MECHANISM:
		break;
	case PTP_MGMT_LOG_MIN_PDELAY_REQ_INTERVAL:
		break;
	default:
		if (target_port->port_number == port->port_ds.id.port_number) {
			port_management_process(port, port, msg, mgmt);
		} else if (target_port->port_number == UINT16_MAX) {
			SYS_SLIST_FOR_EACH_CONTAINER(&port->clock->ports_list, p, node) {
				if (port_management_process(p, port, msg, mgmt)) {
					break;
				}
			}
		}
		break;
	}

	return state_decision_required;
}

static void foreign_clock_cleanup(struct ptp_foreign_master_clock *foreign)
{
	struct ptp_msg *msg;
	int64_t time, timeout, current = k_uptime_get();

	while (foreign->messages_count > FOREIGN_MASTER_THRESHOLD) {
		msg = (struct ptp_msg*)k_fifo_get(&foreign->messages, K_NO_WAIT);
		ptp_msg_unref(msg);
		foreign->messages_count--;
	}

	/* Remove messages that don't arrived at
	   FOREIGN_MASTER_TIME_WINDOW (4 * announce interval) - IEEE 1588-2019 9.3.2.4.5 */
	while (!k_fifo_is_empty(&foreign->messages)) {
		msg = (struct ptp_msg*)k_fifo_peek_head(&foreign->messages);
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

		msg = (struct ptp_msg*)k_fifo_get(&foreign->messages, K_NO_WAIT);
		ptp_msg_unref(msg);
		foreign->messages_count--;
	}
}

static void port_clear_foreign_clock_records(struct ptp_foreign_master_clock *foreign)
{
	struct ptp_msg *msg;

	while (!k_fifo_is_empty(&foreign->messages)) {
		msg = (struct ptp_msg*)k_fifo_get(&foreign->messages, K_NO_WAIT);
		ptp_msg_unref(msg);
		foreign->messages_count--;
	}
}

static enum ptp_port_event port_timers_process(struct ptp_port *port, struct k_timer *timer)
{
	enum ptp_port_event event = PTP_EVT_NONE;

	if ((timer == &port->announce_timer || timer == &port->sync_rx_timer) &&
	    (port->announce_t_expired || port->sync_rx_t_expired)) {
		LOG_DBG("Port %d %s timeout", port->port_ds.id.port_number,
			timer == &port->announce_timer ? "Announce" : "RX Sync");

		if (port->best) {
			port_clear_foreign_clock_records(port->best);
		}

		port_timer_set_timeout_random(&port->announce_timer,
					      port->port_ds.announce_receipt_timeout,
					      1,
					      port->port_ds.log_announce_interval);
		port->announce_t_expired = false;
		port->sync_rx_t_expired = false;
		return PTP_EVT_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES;
	}

	if (timer == &port->sync_tx_timer && port->sync_tx_t_expired) {
		LOG_DBG("Port %d TX Sync timeout", port->port_ds.id.port_number);
		port_timer_set_timeout(&port->sync_tx_timer, 1, port->port_ds.log_sync_interval);
		port->sync_tx_t_expired = false;

		return port_sync_msg_transmit(port) == 0 ? PTP_EVT_NONE : PTP_EVT_FAULT_DETECTED;
	}

	if (timer == &port->qualification_timer && port->qualification_t_expired) {
		LOG_DBG("Port %d Qualification timeout", port->port_ds.id.port_number);
		port->qualification_t_expired = false;

		return PTP_EVT_QUALIFICATION_TIMEOUT_EXPIRES;
	}

	if (timer == &port->master_announce_timer && port->master_announce_t_expired) {
		LOG_DBG("Port %d Master Announce timeout", port->port_ds.id.port_number);
		port_timer_set_timeout(&port->master_announce_timer,
				       1,
				       port->port_ds.log_announce_interval);
		port->master_announce_t_expired = false;

		return port_announce_msg_transmit(port) == 0 ? PTP_EVT_NONE :
							       PTP_EVT_FAULT_DETECTED;
	}

	return event;
}

void ptp_port_init(struct net_if *iface, void *user_data)
{
	struct ptp_clock *clock = (struct ptp_clock *)user_data;

	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return;
	}

	if (clock->default_ds.n_ports > CONFIG_PTP_NUM_PORTS) {
		LOG_WRN("Exceeded number of PTP Ports.");
		return;
	}

	struct ptp_port *port = ports + clock->default_ds.n_ports;

	port->clock = clock;
	port->iface = iface;
	port->best = NULL;
	port->socket = -1;

	port->state_machine = clock->default_ds.slave_only ? ptp_so_state_machine :
							     ptp_state_machine;

	port_ds_init(port);
	sys_slist_init(&port->foreign_list);

	port_timer_init(&port->delay_timer, port_timer_to_handler, user_data);
	port_timer_init(&port->announce_timer, port_timer_to_handler, user_data);
	port_timer_init(&port->master_announce_timer, port_timer_to_handler, user_data);
	port_timer_init(&port->sync_rx_timer, port_timer_to_handler, user_data);
	port_timer_init(&port->sync_tx_timer, port_timer_to_handler, user_data);
	port_timer_init(&port->qualification_timer, port_timer_to_handler, user_data);

	clock->default_ds.n_ports++;

	ptp_clock_pollfd_invalidate(clock);
	sys_slist_append(&clock->ports_list, &port->node);
	LOG_DBG("Port %d initialized", port->port_ds.id.port_number);
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
	LOG_DBG("Port %d closed", port->port_ds.id.port_number);
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

int ptp_port_id_cmp(const struct ptp_port_id *p1, const struct ptp_port_id *p2)
{
	if (memcmp(p1->clk_id.id, p2->clk_id.id, sizeof(p1->clk_id.id)) == 0) {
		if (p1->port_number == p2->port_number) {
			return 0;
		}
		return 1;
	}

	return -1;
}

struct ptp_dataset *ptp_port_best_foreign_ds(struct ptp_port *port)
{
	return port->best ? &port->best->dataset : NULL;
}

enum ptp_port_event ptp_port_event_gen(struct ptp_port *port, struct k_timer *timer)
{
	enum ptp_port_event event = PTP_EVT_NONE;
	struct ptp_msg *msg;
	int ret, cnt;

	if (timer) {
		return port_timers_process(port, timer);
	}

	msg = ptp_msg_alloc();
	if (!msg) {
		return PTP_EVT_FAULT_DETECTED;
	}

	cnt = zsock_recv(port->socket, (void *)msg, sizeof(msg->mtu), ZSOCK_MSG_WAITALL);

	if (cnt <= 0) {
		LOG_ERR("Error during message reception");
		ptp_msg_unref(msg);
		return PTP_EVT_FAULT_DETECTED;
	}

	ret = ptp_msg_post_recv(port, msg, cnt);
	if (ret) {
		ptp_msg_unref(msg);
		return PTP_EVT_FAULT_DETECTED;
	}

	if (ptp_port_id_eq(&msg->header.src_port_id, &port->port_ds.id)) {
		ptp_msg_unref(msg);
		return PTP_EVT_NONE;
	}

	switch (ptp_msg_type_get(msg))
	{
	case PTP_MSG_SYNC:
		port_sync_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_REQ:
		if (port_delay_req_msg_process(port, msg)) {
			event = PTP_EVT_FAULT_DETECTED;
		}
		break;
	case PTP_MSG_PDELAY_REQ:
	case PTP_MSG_PDELAY_RESP:
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		/* P2P delay machanism not supported */
		break;
	case PTP_MSG_FOLLOW_UP:
		port_follow_up_msg_process(port, msg);
		break;
	case PTP_MSG_DELAY_RESP:
		port_delay_resp_msg_process(port, msg);
		break;
	case PTP_MSG_ANNOUNCE:
		if (port_announce_msg_process(port, msg)) {
			event = PTP_EVT_STATE_DECISION;
		}
		break;
	case PTP_MSG_SIGNALING:
		port_signaling_msg_process(port, msg);
		break;
	case PTP_MSG_MANAGEMENT:
		if (port_management_msg_process(port, msg)) {
			event = PTP_EVT_STATE_DECISION;
		}
		break;
	default:
		break;
	}

	ptp_msg_unref(msg);
	return event;
}

void ptp_port_event_handle(struct ptp_port *port, enum ptp_port_event event, bool master_diff)
{
	if (!ptp_port_state_update(port, event, master_diff)) {
		/* No PTP Port state change */
		return;
	}

	k_timer_stop(&port->announce_timer);
	k_timer_stop(&port->master_announce_timer);
	k_timer_stop(&port->delay_timer);
	k_timer_stop(&port->sync_rx_timer);
	k_timer_stop(&port->sync_tx_timer);
	k_timer_stop(&port->qualification_timer);

	switch (port->port_ds.state) {
	case PTP_PS_INITIALIZING:
		break;
	case PTP_PS_FAULTY:
	case PTP_PS_DISABLED:
		port_disable(port);
		break;
	case PTP_PS_LISTENING:
		port_timer_set_timeout_random(&port->announce_timer,
					      port->port_ds.announce_receipt_timeout,
					      1,
					      port->port_ds.log_announce_interval);
		port_timer_set_timeout_random(&port->delay_timer,
					      0,
					      2,
					      port->port_ds.log_min_delay_req_interval);
		break;
	case PTP_PS_PRE_MASTER:
		port_timer_set_timeout(&port->qualification_timer,
				       1 + port->clock->current_ds.steps_rm,
				       port->port_ds.log_announce_interval);
		break;
	case PTP_PS_GRAND_MASTER:
	case PTP_PS_MASTER:
		port_timer_set_timeout(&port->master_announce_timer,
				       1,
				       port->port_ds.log_announce_interval);
		port_timer_set_timeout(&port->sync_tx_timer, 1, port->port_ds.log_sync_interval);
		break;
	case PTP_PS_PASSIVE:
		port_timer_set_timeout_random(&port->announce_timer,
					      port->port_ds.announce_receipt_timeout,
					      1,
					      port->port_ds.log_announce_interval);
		break;
	case PTP_PS_UNCALIBRATED:
		if (port->last_sync_fup) {
			ptp_msg_unref(port->last_sync_fup);
			port->last_sync_fup = NULL;
		}
		/* fall through */
	case PTP_PS_SLAVE:
		port_timer_set_timeout_random(&port->announce_timer,
					      port->port_ds.announce_receipt_timeout,
					      1,
					      port->port_ds.log_announce_interval);
		break;
	};
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
		if (port_enable(port)) {
			event = PTP_EVT_FAULT_DETECTED;
		} else {
			event = PTP_EVT_INIT_COMPLETE;
		}
		next_state = port->state_machine(next_state, event, false);
	}

	if (next_state != ptp_port_state(port)) {
		port->port_ds.state = next_state;
		LOG_DBG("Port %d changed state to %s",
			port->port_ds.id.port_number,
			port_state_str(next_state));
		return 1;
	}

	return 0;
}

void ptp_port_free_foreign_masters(struct ptp_port *port)
{
	struct ptp_foreign_master_clock *foreign;

	SYS_SLIST_FOR_EACH_CONTAINER(&port->foreign_list, foreign, node) {

		while (foreign->messages_count > FOREIGN_MASTER_THRESHOLD) {
			struct ptp_msg *msg = (struct ptp_msg *)k_fifo_get(&foreign->messages,
									   K_NO_WAIT);
			foreign->messages_count--;
			ptp_msg_unref(msg);
		}

		sys_slist_find_and_remove(&port->foreign_list, &foreign->node);
		k_free(foreign);
	}
}

int ptp_port_add_foreign_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign;
	struct ptp_msg *last;
	int diff = 0;


	SYS_SLIST_FOR_EACH_CONTAINER(&port->foreign_list, foreign, node) {
		struct ptp_msg *foreign_msg =
			(struct ptp_msg *)k_fifo_peek_head(&foreign->messages);

		if (foreign_msg &&
		    ptp_port_id_eq(&msg->header.src_port_id, &foreign_msg->header.src_port_id)) {
			break;
		}
	}

	if (!foreign) {
		LOG_DBG("Port %d has a new foreign master %s",
			port->port_ds.id.port_number,
			port_id_str(&msg->header.src_port_id));

		foreign = 0;//k_malloc(sizeof(*foreign));
		if (!foreign) {
			LOG_ERR("Couldn't allocate memory for new foreign master");
			return 0;
		}

		memset(foreign, 0, sizeof(*foreign));
		memcpy(&foreign->dataset.sender,
		       &msg->header.src_port_id,
		       sizeof(foreign->dataset.sender));
		k_fifo_init(&foreign->messages);
		foreign->port = port;

		sys_slist_append(&port->foreign_list, &foreign->node);

		return 0;
	}

	foreign_clock_cleanup(foreign);

	foreign->messages_count++;
	k_fifo_put(&foreign->messages, (void*)msg);

	if (foreign->messages_count > 1) {
		last = (struct ptp_msg*)k_fifo_peek_tail(&foreign->messages);
		diff = ptp_msg_announce_cmp(msg, last);
	}

	return (foreign->messages_count == FOREIGN_MASTER_THRESHOLD ? 1 : 0) || diff;
}

int ptp_port_update_current_master(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_foreign_master_clock *foreign = port->best;
	struct ptp_msg *foreign_msg = (struct ptp_msg *)k_fifo_peek_head(&foreign->messages);

	if (foreign_msg &&
	    !ptp_port_id_eq(&msg->header.src_port_id, &foreign_msg->header.src_port_id)) {
		return ptp_port_add_foreign_master(port, msg);
	}

	foreign_clock_cleanup(foreign);
	k_fifo_put(&foreign->messages, (void*)msg);
	foreign->messages_count++;
	port_timer_set_timeout_random(&port->announce_timer,
				      port->port_ds.announce_receipt_timeout,
				      1,
				      port->port_ds.log_announce_interval);

	if (foreign->messages_count > 1) {
		struct ptp_msg *last = (struct ptp_msg *)k_fifo_peek_tail(&foreign->messages);

		return ptp_msg_announce_cmp(msg, last);
	}

	return 0;
}
