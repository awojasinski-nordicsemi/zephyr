/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ptp_msg, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/drivers/ptp_clock.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ptp.h>

#include "clock.h"
#include "msg.h"
#include "port.h"
#include "tlv.h"

#if CONFIG_PTP_UDP_IPv4_PROTOCOL
#define HDR_LEN (NET_IPV4H_LEN + NET_UDPH_LEN)
#elif CONFIG_PTP_UDP_IPv6_PROTOCOL
#define HDR_LEN (NET_IPV6H_LEN + NET_UDPH_LEN)
#else
#define HDR_LEN 14
#endif

struct msg_container {
	uint8_t reserved[HDR_LEN];
	struct ptp_msg msg __aligned(8);
};

static struct k_mem_slab msg_slab;

K_MEM_SLAB_DEFINE_STATIC(msg_slab, sizeof(struct msg_container), CONFIG_PTP_MSG_POLL_SIZE, 8);

static const char *msg_type_str(struct ptp_msg *msg)
{
	switch (ptp_msg_type_get(msg)) {
	case PTP_MSG_SYNC:
		return "Sync";
	case PTP_MSG_DELAY_REQ:
		return "Delay_Req";
	case PTP_MSG_PDELAY_REQ:
		return "Pdelay_Req";
	case PTP_MSG_PDELAY_RESP:
		return "Pdelay_Resp";
	case PTP_MSG_FOLLOW_UP:
		return "Follow_Up";
	case PTP_MSG_DELAY_RESP:
		return "Delay_Resp";
	case PTP_MSG_PDELAY_RESP_FOLLOW_UP:
		return "Pdelay_Resp_Follow_Up";
	case PTP_MSG_ANNOUNCE:
		return "Announce";
	case PTP_MSG_SIGNALING:
		return "Signaling";
	case PTP_MSG_MANAGEMENT:
		return "Management";
	default:
		return "Not recognized";
	}
}

static uint8_t *msg_suffix_get(struct ptp_msg *msg)
{
	uint8_t *suffix = NULL;

	switch (ptp_msg_type_get(msg)) {
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

	return suffix;
}

static int msg_tlv_preprocess(struct ptp_msg *msg, int lenght)
{
	int suffix_len = 0, ret = 0;
	struct ptp_tlv_container *tlv_container;
	uint8_t *suffix = msg_suffix_get(msg);

	if (!suffix) {
		LOG_DBG("No TLV attached to the message");
		return 0;
	}

	sys_slist_init(&msg->tlvs);

	while (lenght >= sizeof(struct ptp_tlv)) {
		tlv_container = ptp_tlv_alloc();
		if(!tlv_container) {
			return -ENOMEM;
		}

		tlv_container->tlv = (struct ptp_tlv*)suffix;
		tlv_container->tlv->type = ntohs(tlv_container->tlv->type);
		tlv_container->tlv->length = ntohs(tlv_container->tlv->length);

		if (tlv_container->tlv->length % 2) {
			/* IEEE 1588-2019 Section 5.3.8 - length is an even number */
			LOG_ERR("Incorrect length of TLV");
			ptp_tlv_free(tlv_container);
			return -EBADMSG;
		}

		lenght -= sizeof(struct ptp_tlv);
		suffix += sizeof(struct ptp_tlv);
		suffix_len += sizeof(struct ptp_tlv);

		if (tlv_container->tlv->length > lenght) {
			LOG_ERR("Incorrect length of TLV");
			ptp_tlv_free(tlv_container);
			return -EBADMSG;
		}

		lenght -= tlv_container->tlv->length;
		suffix += tlv_container->tlv->length;
		suffix_len += tlv_container->tlv->length;

		ret = ptp_tlv_post_recv(tlv_container->tlv);
		if (ret) {
			ptp_tlv_free(tlv_container);
			return ret;
		}

		sys_slist_append(&msg->tlvs, &tlv_container->node);
	}

	return suffix_len;
}

static void msg_tlv_postprocess(struct ptp_msg *msg)
{
	struct ptp_tlv_container *tlv_container;

	SYS_SLIST_FOR_EACH_CONTAINER(&msg->tlvs, tlv_container, node) {
		ptp_tlv_pre_send(tlv_container->tlv);
	}

	/* No need to track TLVs attached to the message. */
	SYS_SLIST_FOR_EACH_CONTAINER(&msg->tlvs, tlv_container, node) {
		ptp_tlv_free(tlv_container);
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

struct ptp_msg *ptp_msg_alloc(void)
{
	struct msg_container *container = NULL;

	if (k_mem_slab_alloc(&msg_slab, (void **)&container, K_FOREVER)) {
		memset(container, 0, sizeof(*container));
		container->msg.ref++;
		return &container->msg;
	} else {
		LOG_ERR("Couldn't allocate memory for the message");
		return NULL;
	}
}

void ptp_msg_unref(struct ptp_msg *msg)
{
	msg->ref--;
	if (msg->ref) {
		return;
	}

	struct ptp_tlv_container *tlv_container;
	struct msg_container *container = CONTAINER_OF(msg, struct msg_container, msg);

	SYS_SLIST_FOR_EACH_CONTAINER(&msg->tlvs, tlv_container, node) {
		ptp_tlv_free(tlv_container);
	}

	k_mem_slab_free(&msg_slab, (void *)container);
}

bool ptp_msg_current_parent_check(const struct ptp_port *port, const struct ptp_msg *msg)
{
	struct ptp_port_id master = port->clock->parent_ds.port_id;
	struct ptp_port_id msg_id = msg->header.src_port_id;

	return ptp_port_id_eq(&master, &msg_id);
}

int ptp_msg_announce_cmp(const struct ptp_msg *m1, const struct ptp_msg *m2)
{
	int len = sizeof(m1->announce.gm_priority1) + sizeof(m1->announce.gm_clk_quality) +
		  sizeof(m1->announce.gm_priority1) + sizeof(m1->announce.gm_id) +
		  sizeof(m1->announce.steps_rm);

	return memcmp(&m1->announce.gm_priority1, &m2->announce.gm_priority1, len);
}

struct ptp_msg *ptp_msg_get_from_pkt(struct net_pkt *pkt)
{
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ip_access,
#if CONFIG_PTP_UDP_IPv4_PROTOCOL
		struct net_ipv4_hdr
#else
		struct net_ipv6_hdr
#endif
		);
	uint8_t *buf;
	int offset = pkt->ip_hdr_len;

	buf = (uint8_t *)net_pkt_get_data(pkt, &ip_access);

	if (!buf) {
		LOG_ERR("Couldn't retrive PTP message from net packet");
		return NULL;
	}

	return (struct ptp_msg *)(buf + offset);
}

enum ptp_msg_type ptp_msg_type_get(const struct ptp_msg *msg)
{
	return (enum ptp_msg_type)(msg->header.type_major_sdo_id & 0xF);
}

int ptp_msg_pre_send(struct ptp_clock *clock, struct ptp_msg *msg)
{
	msg_header_pre_send(&msg->header);

	switch (ptp_msg_type_get(msg)) {
	case PTP_MSG_SYNC:
		break;
	case PTP_MSG_DELAY_REQ:
		struct net_ptp_time ts;
		ptp_clock_get(clock->phc, &ts);
		msg->timestamp.host.nanoseconds = ts.nanosecond;
		msg->timestamp.host.seconds = ts.second;
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

	msg_tlv_postprocess(msg);
	return 0;
}

int ptp_msg_post_recv(struct ptp_port *port, struct ptp_msg *msg, int cnt)
{
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
	enum ptp_msg_type type = ptp_msg_type_get(msg);
	int tlv_len;

	if (msg_size[type] > cnt) {
		LOG_ERR("Received message with incorrect lenght");
		return -EBADMSG;
	}

	if (msg_header_post_recv(&msg->header)) {
		LOG_ERR("Received message incomplient with supported PTP version");
		return -EBADMSG;
	}

	LOG_DBG("Port %d received %s message", port->port_ds.id.port_number, msg_type_str(msg));

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
		struct net_ptp_time ts;
		ptp_clock_get(port->clock->phc, &ts);
		msg->timestamp.host.nanoseconds = ts.nanosecond;
		msg->timestamp.host.seconds = ts.second;
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

	tlv_len = msg_tlv_preprocess(msg, cnt - msg_size[type]);

	if (tlv_len < 0) {
		LOG_ERR("Failed processing TLVs");
		return -EBADMSG;
	}

	if (msg_size[type] + tlv_len != msg->header.msg_length) {
		LOG_ERR("Length and TLVs don't correspond with specified in the message");
		return -EMSGSIZE;
	}

	return 0;
}

struct ptp_tlv *ptp_msg_add_tlv(struct ptp_msg *msg, int length)
{
	struct ptp_tlv_container *tlv_container;
	uint8_t *suffix = msg_suffix_get(msg);

	if (!suffix) {
		return NULL;
	}

	tlv_container = (struct ptp_tlv_container *)sys_slist_peek_tail(&msg->tlvs);
	if (tlv_container) {
		suffix = (uint8_t *)tlv_container->tlv;
		suffix += sizeof(*tlv_container->tlv);
		suffix += tlv_container->tlv->length;
	}

	if ((intptr_t)(suffix + length) >= (intptr_t)&msg->ref) {
		LOG_ERR("Not enough space for TLV of %d length", length);
		return NULL;
	}

	tlv_container = ptp_tlv_alloc();
	if (tlv_container) {
		tlv_container->tlv = (struct ptp_tlv *)suffix;
		msg->header.msg_length += length;
	}

	return tlv_container ? tlv_container->tlv : NULL;
}
