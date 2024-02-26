/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_msg, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/net/net_ip.h>
#include <zephyr/drivers/ptp_clock.h>

#include "msg.h"
#include "port.h"

static void timestamp_post_recv(struct ptp_msg *msg, struct ptp_protocol_timestamp *ts)
{
	uint16_t high = ntohs(ts->seconds_high);
	uint32_t low = ntohl(ts->seconds_low);

	msg->timestamp.protocol.seconds = ((uint64_t)high << 32 | (uint64_t)low);
	msg->timestamp.protocol.nanoseconds = ntohl(ts->nanoseconds);
}

static void timestamp_pre_send(struct ptp_protocol_timestamp *ts)
{
	ts->seconds_high = htons(ts->seconds_high);
	ts->seconds_low = htonl(ts->seconds_low);
	ts->nanoseconds = htonl(ts->nanoseconds);
}

static int msg_header_post_recv(struct ptp_header *header)
{
	if (header->version & 0xF != PTP_MAJOR_VERSION) {
		/* Incompatible protocol version */
		return -1;
	}

	header->msg_length = ntohs(header->msg_length);
	header->correction = ntohll(header->correction);
	header->src_port_id.port_number = ntohs(header->src_port_id.port_number);
	header->sequence_id = ntohs(header->sequence_id);

	return 0;
}

static void msg_header_pre_send(struct ptp_header *header)
{
	header->msg_length = htons(header->msg_length);
	header->correction = htonll(header->correction);
	header->src_port_id.port_number = htons(header->src_port_id.port_number);
	header->sequence_id = htons(header->sequence_id);
}

static void port_id_post_recv(struct ptp_port_id *port_id)
{
	port_id->port_number = ntohs(port_id->port_number);
}

static void port_id_pre_send(struct ptp_port_id *port_id)
{
	port_id->port_number = htons(port_id->port_number);
}

bool ptp_check_if_current_parent(struct ptp_port *port, struct ptp_msg *msg) {
	struct ptp_port_id master = port->clock->parent_ds.port_id;

	return ptp_port_id_eq(&master, msg->header.src_port_id);
}

int ptp_announce_msg_process(struct ptp_port *port, struct ptp_msg *msg)
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
		break:
	default:
		break;
	}

	return ret;
}

int ptp_announce_msg_cmp(const struct ptp_msg *m1, const struct ptp_msg *m2)
{
	int len = sizeof(m1->announce.gm_priority1) +
		  sizeof(m1->announce.gm_clk_quality) +
		  sizeof(m1->announce.gm_priority1) +
		  sizeof(m1->announce.gm_id) +
		  sizeof(m1->announce.steps_rm);

	return memcmp(&m1->announce.gm_priority1, &m2->announce.gm_priority1, len);
}

void ptp_sync_msg_process(struct ptp_port *port, struct ptp_msg *msg)
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

void ptp_follow_up_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);

	if (state != PTP_PS_SLAVE && state != PTP_PS_UNCALIBRATED) {
		return;
	}

	if (ptp_check_if_current_parent(port, msg)) {
		return;
	}
}

void ptp_delay_req_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	enum ptp_port_state state = ptp_port_state(port);
	struct ptp_msg resp;

	if (state != PTP_PS_MASTER && state != PTP_PS_GRAND_MASTER) {
		return;
	}

	// TODO prepare delay_resp message

	resp.header.version = PTP_VERSION;
	resp.header.msg_length = sizeof(struct ptp_delay_resp_msg);
	resp.header.src_port_id = port->port_ds.id;
	resp.header.log_msg_interval = port->port_ds.log_min_delay_req_interval;
	resp.header.sequence_id = msg->header.sequence_id;
	resp.header.req_port_id = msg->header.src_port_id;

	if (msg->header.flags && PTP_MSG_UNICAST_FLAG) {
		// do stuff specific for unicast message
	}

	ptp_port_send(port, resp);

}

void ptp_delay_resp_msg_process(struct ptp_port *port, struct ptp_msg *msg)
{
	if
}

enum ptp_msg_type ptp_msg_type_get(const struct ptp_msg *msg)
{
	return (enum ptp_msg_type)msg->header.type;
}

int ptp_mgs_pre_send(struct ptp_clock *clock, struct ptp_msg *msg)
{
	enum ptp_msg_type type = ptp_msg_type_get(msg);

	msg_header_pre_send(&msg->header);

	switch (type)
	{
	case PTP_MSG_SYNC:
		break;
	case PTP_MSG_DELAY_REQ:
		ptp_clock_get(clock->ptp_clock, &msg->timestamp.host);
		break;
	case PTP_MSG_PDELAY_REQ:
		break;
	case PTP_MSG_PDELAY_RESP:
		timestamp_pre_send(&msg->pdelay_resp.req_receipt_timestamp);
		port_id_pre_send(&msg->pdelay_resp.req_port_id);
		break;
	case PTP_MSG_FOLLOW_UP:
		break;
	case PTP_MSG_DELAY_RESP:
		timestamp_pre_send(&msg->delay_resp.receive_timestamp);
		port_id_pre_send(&msg->delay_resp.req_port_id);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		timestamp_pre_send(&msg->pdelay_resp_follow_up.resp_origin_timestamp);
		port_id_pre_send(&msg->pdelay_resp_follow_up.req_port_id);
		break;
	case PTP_MSG_ANNOUNCE:
		msg->announce.current_utc_offset = htons(msg->announce.current_utc_offset);
		msg->announce.gm_clk_quality.offset_scaled_log_variance =
			htons(msg->announce.gm_clk_quality.offset_scaled_log_variance);
		msg->announce.steps_rm = htons(msg->announce.steps_rm);
		break;
	case PTP_MSG_SIGNALING:
		port_id_pre_send(&msg->signaling.target_port_id);
		break;
	case PTP_MSG_MANAGEMENT:
		port_id_pre_send(&msg->management.target_port_id);
		break;
	}
}

int ptp_mgs_post_recv(struct ptp_msg *msg, int cnt)
{
	int msg_size;

	if (cnt < sizeof(struct ptp_header)) {
		return -1;
	}

	if (msg_header_post_recv(&msg->header)) {
		return -1;
	}

	enum ptp_msg_type type = ptp_msg_type_get(msg);

	switch (type)
	{
	case PTP_MSG_SYNC:
		msg_size = sizeof(struct ptp_sync_msg);
		break;
	case PTP_MSG_DELAY_REQ:
		msg_size = sizeof(struct ptp_delay_req_msg);
		break;
	case PTP_MSG_PDELAY_REQ:
		msg_size = sizeof(struct ptp_pdelay_req_msg);
		break;
	case PTP_MSG_PDELAY_RESP:
		msg_size = sizeof(struct ptp_pdelay_resp_msg);
		break;
	case PTP_MSG_FOLLOW_UP:
		msg_size = sizeof(struct ptp_follow_up_msg);
		break;
	case PTP_MSG_DELAY_RESP:
		msg_size = sizeof(struct ptp_delay_resp_msg);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		msg_size = sizeof(struct ptp_pdelay_resp_follow_up_msg);
		break;
	case PTP_MSG_ANNOUNCE:
		msg_size = sizeof(struct ptp_announce_msg);
		break;
	case PTP_MSG_SIGNALING:
		msg_size = sizeof(struct ptp_signaling_msg);
		break;
	case PTP_MSG_MANAGEMENT:
		msg_size = sizeof(struct ptp_management_msg);
		break;
	}

	if (msg_size > cnt) {
		return -1;
	}

	switch (type)
	{
	case PTP_MSG_SYNC:
		timestamp_post_recv(msg, &msg->sync.origin_timestamp);
		break;
	case PTP_MSG_DELAY_REQ:
		break;
	case PTP_MSG_PDELAY_REQ:
		break;
	case PTP_MSG_PDELAY_RESP:
		timestamp_post_recv(msg, &msg->pdelay_resp.req_receipt_timestamp);
		port_id_post_recv(&msg->pdelay_resp.req_port_id);
		break;
	case PTP_MSG_FOLLOW_UP:
		timestamp_post_recv(msg, &msg->follow_up.precise_origin_timestamp);
		break;
	case PTP_MSG_DELAY_RESP:
		timestamp_post_recv(msg, &msg->delay_resp.receive_timestamp);
		port_id_post_recv(&msg->delay_resp.req_port_id);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		timestamp_post_recv(msg, &msg->pdelay_resp_follow_up.resp_origin_timestamp);
		port_id_post_recv(&msg->pdelay_resp_follow_up.req_port_id);
		break;
	case PTP_MSG_ANNOUNCE:
		timestamp_post_recv(msg, &msg->announce.origin_timestamp);
		msg->announce.current_utc_offset = ntohs(msg->announce.current_utc_offset);
		msg->announce.gm_clk_quality.offset_scaled_log_variance =
			ntohs(msg->announce.gm_clk_quality.offset_scaled_log_variance);
		msg->announce.steps_rm = ntohs(msg->announce.steps_rm);
		break;
	case PTP_MSG_SIGNALING:
		port_id_post_recv(&msg->signaling.target_port_id);
		break;
	case PTP_MSG_MANAGEMENT:
		port_id_post_recv(&msg->management.target_port_id);
		break;
	}

	return 0;
}
