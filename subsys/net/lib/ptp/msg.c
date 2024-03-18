/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_msg, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/drivers/ptp_clock.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ptp.h>

#include "clock.h"
#include "msg.h"
#include "port.h"

#define NET_BUF_TIMEOUT K_MSEC(100)

struct ptp_msg_container {
	uint8_t protocol_header[];
	struct ptp_msg __aligned(8) msg;
};

static struct ptp_msg *msg_allocate(struct ptp_port *port, size_t size)
{
	struct net_pkt *pkt;
	struct ptp_msg *msg;

	pkt = net_pkt_alloc_with_buffer(port->iface, size, , , NET_BUF_TIMEOUT);
	net_buf_add(pkt->buffer, len);

	if (!pkt) {
		LOG_ERR("Cannot allocate space for message");
		return NULL;
	}



	return msg;
}

static void msg_free(struct ptp_msg *msg)
{
	struct net_pkt *pkt = CONTAINER_OF(msg, struct net_pkt, );

	net_pkt_unref(pkt);
}

static void msg_timestamp_post_recv(struct ptp_msg *msg, struct ptp_protocol_timestamp *ts)
{
	uint16_t high = ntohs(ts->seconds_high);
	uint32_t low = ntohl(ts->seconds_low);

	msg->timestamp.protocol.seconds = ((uint64_t)high << 32 | (uint64_t)low);
	msg->timestamp.protocol.nanoseconds = ntohl(ts->nanoseconds);
}

static void msg_timestamp_pre_send(struct ptp_protocol_timestamp *ts)
{
	ts->seconds_high = htons(ts->seconds_high);
	ts->seconds_low = htonl(ts->seconds_low);
	ts->nanoseconds = htonl(ts->nanoseconds);
}

static int msg_header_post_recv(struct ptp_header *header)
{
	if ((header->version & 0xF) != PTP_MAJOR_VERSION) {
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

static void msg_port_id_post_recv(struct ptp_port_id *port_id)
{
	port_id->port_number = ntohs(port_id->port_number);
}

static void msg_port_id_pre_send(struct ptp_port_id *port_id)
{
	port_id->port_number = htons(port_id->port_number);
}

struct ptp_msg *ptp_msg_duplicate(struct ptp_msg *msg, size_t lenght)
{
	struct ptp_msg *duplicate;

	return duplicate;
}

bool ptp_check_if_current_parent(struct ptp_port *port, struct ptp_msg *msg) {
	struct ptp_port_id master = port->clock->parent_ds.port_id;
	struct ptp_port_id msg_id = msg->header.src_port_id;

	return ptp_port_id_eq(&master, &msg_id);
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
		struct net_ptp_time ts;
		ptp_clock_get(clock->phc, &ts);
		break;
	case PTP_MSG_PDELAY_REQ:
		break;
	case PTP_MSG_PDELAY_RESP:
		msg_timestamp_pre_send(&msg->pdelay_resp.req_receipt_timestamp);
		msg_port_id_pre_send(&msg->pdelay_resp.req_port_id);
		break;
	case PTP_MSG_FOLLOW_UP:
		break;
	case PTP_MSG_DELAY_RESP:
		msg_timestamp_pre_send(&msg->delay_resp.receive_timestamp);
		msg_port_id_pre_send(&msg->delay_resp.req_port_id);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		msg_timestamp_pre_send(&msg->pdelay_resp_follow_up.resp_origin_timestamp);
		msg_port_id_pre_send(&msg->pdelay_resp_follow_up.req_port_id);
		break;
	case PTP_MSG_ANNOUNCE:
		msg->announce.current_utc_offset = htons(msg->announce.current_utc_offset);
		msg->announce.gm_clk_quality.offset_scaled_log_variance =
			htons(msg->announce.gm_clk_quality.offset_scaled_log_variance);
		msg->announce.steps_rm = htons(msg->announce.steps_rm);
		break;
	case PTP_MSG_SIGNALING:
		msg_port_id_pre_send(&msg->signaling.target_port_id);
		break;
	case PTP_MSG_MANAGEMENT:
		msg_port_id_pre_send(&msg->management.target_port_id);
		break;
	}

	return 0;
}

int ptp_mgs_post_recv(struct ptp_msg *msg, int cnt)
{
	int msg_size = 0;

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
		msg_timestamp_post_recv(msg, &msg->sync.origin_timestamp);
		break;
	case PTP_MSG_DELAY_REQ:
		break;
	case PTP_MSG_PDELAY_REQ:
		break;
	case PTP_MSG_PDELAY_RESP:
		msg_timestamp_post_recv(msg, &msg->pdelay_resp.req_receipt_timestamp);
		msg_port_id_post_recv(&msg->pdelay_resp.req_port_id);
		break;
	case PTP_MSG_FOLLOW_UP:
		msg_timestamp_post_recv(msg, &msg->follow_up.precise_origin_timestamp);
		break;
	case PTP_MSG_DELAY_RESP:
		msg_timestamp_post_recv(msg, &msg->delay_resp.receive_timestamp);
		msg_port_id_post_recv(&msg->delay_resp.req_port_id);
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		msg_timestamp_post_recv(msg, &msg->pdelay_resp_follow_up.resp_origin_timestamp);
		msg_port_id_post_recv(&msg->pdelay_resp_follow_up.req_port_id);
		break;
	case PTP_MSG_ANNOUNCE:
		msg_timestamp_post_recv(msg, &msg->announce.origin_timestamp);
		msg->announce.current_utc_offset = ntohs(msg->announce.current_utc_offset);
		msg->announce.gm_clk_quality.offset_scaled_log_variance =
			ntohs(msg->announce.gm_clk_quality.offset_scaled_log_variance);
		msg->announce.steps_rm = ntohs(msg->announce.steps_rm);
		break;
	case PTP_MSG_SIGNALING:
		msg_port_id_post_recv(&msg->signaling.target_port_id);
		break;
	case PTP_MSG_MANAGEMENT:
		msg_port_id_post_recv(&msg->management.target_port_id);
		break;
	}

	return 0;
}
