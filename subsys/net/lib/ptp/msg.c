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
#include "tlv.h"

#define PTP_MSG_POOL 10

#if CONFIG_PTP_UDP_IPv4_PROTOCOL
#define HDR_LEN (NET_IPV4H_LEN + NET_UDPH_LEN)
#elif CONFIG_PTP_UDP_IPv6_PROTOCOL
#define HDR_LEN (NET_IPV6H_LEN + NET_UDPH_LEN)
#endif

struct msg_container {
	uint8_t reserved[HDR_LEN];
	struct ptp_msg msg __aligned(8);
};

struct msg_container msg_pool[PTP_MSG_POOL];

static int msg_tlv_post_recv(struct ptp_tlv *tlv)
{
	int ret = 0;
	struct ptp_tlv_mgmt *mgmt;
	enum ptp_tlv_type type = ptp_tlv_type_get(tlv);

	switch (type) {
	case PTP_TLV_TYPE_MANAGEMENT:
		mgmt = (struct ptp_tlv_mgmt *)tlv;
		mgmt->id = ntohs(mgmt->id);
		break;
	case PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
		break;
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION:
		break;
	case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:

		break;
	case PTP_TLV_TYPE_PATH_TRACE:
		break;
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE:
		break;
	case PTP_TLV_TYPE_ENHANCED_ACCURACY_METRICS:
		break;
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE:
		break;
	case PTP_TLV_TYPE_L1_SYNC:
		break;
	case PTP_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY:
		break;
	case PTP_TLV_TYPE_PROTOCOL_ADDRESS:
		break;
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA:
		break;
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA:
		break;
	case PTP_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS:
		break;
	case PTP_TLV_TYPE_CUMULATIVE_RATE_RATIO:
		break;
	case PTP_TLV_TYPE_PAD:
		break;
	case PTP_TLV_TYPE_AUTHENTICATION:
		break;
	default:
		break;
	}

	return ret;
}

static int msg_tlv_organize(struct ptp_msg *msg, int lenght)
{
	uint8_t *suffix;
	int suffix_len;
	struct ptp_tlv_container *tlv_container;
	enum ptp_msg_type type = ptp_msg_type_get(msg);

	switch (type) {
	case PTP_MSG_SYNC:
		suffix = msg->sync.suffix;
		break;
	case PTP_MSG_DELAY_REQ:
		suffix = msg->delay_req.suffix;
		break;
	case PTP_MSG_PDELAY_REQ:
		suffix = msg->pdelay_req.suffix;
		break;
	case PTP_MSG_PDELAY_RESP:
		suffix = msg->pdelay_resp.suffix;
		break;
	case PTP_MSG_FOLLOW_UP:
		suffix = msg->follow_up.suffix;
		break;
	case PTP_MSG_DELAY_RESP:
		suffix = msg->delay_resp.suffix;
		break;
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		suffix = msg->pdelay_resp_follow_up.suffix;
		break;
	case PTP_MSG_ANNOUNCE:
		suffix = msg->announce.suffix;
		break;
	case PTP_MSG_SIGNALING:
		suffix = msg->signaling.suffix;
		break;
	case PTP_MSG_MANAGEMENT:
		suffix = msg->management.suffix;
		break;
	}

	if (!suffix) {
		LOG_DBG("No TLV attached to the message");
		return 0;
	}

	while (lenght >= sizeof(struct ptp_tlv)) {
		tlv_container = ptp_tlv_allocate();
		if(!tlv_container) {
			LOG_ERR("Couldn't allocate memory for TLV");
			return -ENOMEM;
		}

		tlv_container->tlv = (struct ptp_tlv*)suffix;
		tlv_container->tlv->type = ntohs(tlv_container->tlv->type);
		tlv_container->tlv->length = ntohs(tlv_container->tlv->length);

		msg_tlv_post_recv(tlv_container->tlv);

	}
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

struct ptp_msg *ptp_msg_allocate(void)
{
	struct ptp_msg *msg = NULL;

	for (size_t i = 0; i < PTP_MSG_POOL; i++) {
		if (msg_pool[i].msg.ref == 0) {
			msg = &msg_pool[i].msg;
			msg->ref++;
		}
	}

	if (!msg) {
		LOG_ERR("Cannot allocate space for message");
		return NULL;
	}

	return;
}

void ptp_msg_unref(struct ptp_msg *msg)
{
	if (msg->ref > 0) {
		msg->ref--;

		if (msg->ref == 0) {
			msg_container *container = CONTAINER_OF(msg, struct msg_container, msg);
			memset(container, 0, sizeof(*container));
		}
	}
}

bool ptp_check_if_current_parent(struct ptp_port *port, struct ptp_msg *msg)
{
	struct ptp_port_id master = port->clock->parent_ds.port_id;
	struct ptp_port_id msg_id = msg->header.src_port_id;

	return ptp_port_id_eq(&master, &msg_id);
}

int ptp_announce_msg_cmp(const struct ptp_msg *m1, const struct ptp_msg *m2)
{
	int len = sizeof(m1->announce.gm_priority1) + sizeof(m1->announce.gm_clk_quality) +
		  sizeof(m1->announce.gm_priority1) + sizeof(m1->announce.gm_id) +
		  sizeof(m1->announce.steps_rm);

	return memcmp(&m1->announce.gm_priority1, &m2->announce.gm_priority1, len);
}

struct ptp_msg *ptp_msg_get_from_pkt(struct net_pkt *pkt)
{
	// TODO: Strip UDP headers from net_pkt

	return;
}

enum ptp_msg_type ptp_msg_type_get(const struct ptp_msg *msg)
{
	return (enum ptp_msg_type)msg->header.type;
}

int ptp_msg_pre_send(struct ptp_clock *clock, struct ptp_msg *msg)
{
	enum ptp_msg_type type = ptp_msg_type_get(msg);

	msg_header_pre_send(&msg->header);

	switch (type) {
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

int ptp_msg_post_recv(struct ptp_msg *msg, int cnt)
{
	enum ptp_msg_type type = ptp_msg_type_get(msg);
	int tlv_len;
	static const int msg_size[] = {
		[PTP_MSG_SYNC]		        = sizeof(struct ptp_sync_msg),
		[PTP_MSG_DELAY_REQ]	        = sizeof(struct ptp_delay_req_msg),
		[PTP_MSG_PDELAY_REQ]	        = sizeof(struct ptp_pdelay_req_msg),
		[PTP_MSG_PDELAY_RESP]	        = sizeof(struct ptp_pdelay_resp_msg),
		[PTP_MSG_FOLLOW_UP]	        = sizeof(struct ptp_follow_up_msg),
		[PTP_MSG_DELAY_RESP]	        = sizeof(struct ptp_delay_resp_msg),
		[PTP_MSG_PDELAY_RESP_FOLLOW_UP] = sizeof(struct ptp_pdelay_resp_follow_up_msg),
		[PTP_MSG_ANNOUNCE]	        = sizeof(struct ptp_announce_msg),
		[PTP_MSG_SIGNALING]	        = sizeof(struct ptp_signaling_msg),
		[PTP_MSG_MANAGEMENT]	        = sizeof(struct ptp_management_msg),
	};

	if (msg_size[type] > cnt) {
		LOG_ERR();
		return -1;
	}

	if (msg_header_post_recv(&msg->header)) {
		return -1;
	}


	switch (type) {
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

	tlv_len = msg_tlv_organize(msg, cnt - msg_size[type]);

	if (tlv_len < 0) {
		LOG_ERR("Failed processing TLVs");
		return -1;
	}

	if (msg_size[type] + tlv_len != msg->header.msg_length) {
		LOG_ERR("Length and TLVs don't correspond to the length specified in the message");
		return -1;
	}

	return 0;
}
