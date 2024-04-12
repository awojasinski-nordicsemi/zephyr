/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_port, CONFIG_PTP_LOG_LEVEL);

#include <stdbool.h>

#include <zephyr/net/ptp.h>

#include "msg.h"
#include "tlv.h"

struct ptp_tlv_container tlv_pool[];

#define TLV_MANUFACTURER_ID_LEN (3)
#define TLV_PROFILE_ID_LEN (6)
#define TLV_ADDR_LEN_MAX (16)

#define TLV_NTOHS(ptr)				 \
	do {					 \
		uint16_t val = *(uint16_t *)ptr; \
		ntohs(val);			 \
		mamcpy(ptr, val, sizeof(val));	 \
	} while(0)

#define TLV_HTONS(ptr)				 \
	do {					 \
		uint16_t val = *(uint16_t *)ptr; \
		htons(val);			 \
		mamcpy(ptr, val, sizeof(val));	 \
	} while(0)

static int tlv_mgmt_post_recv(struct ptp_tlv_mgmt *tlv, uint16_t length)
{
	enum ptp_mgmt_id id = (enum ptp_mgmt_id)tlv->id;

	switch (id) {
	case PTP_MGMT_NULL_PTP_MANAGEMENT:
	case PTP_MGMT_SAVE_IN_NON_VOLATILE_STORAGE:
	case PTP_MGMT_RESET_NON_VOLATILE_STORAGE:
	case PTP_MGMT_FAULT_LOG_RESET:
	case PTP_MGMT_ENABLE_PORT:
	case PTP_MGMT_DISABLE_PORT:
		if (length != 0) {
			return -EBADMSG;
		}
		break;
	case PTP_MGMT_CLOCK_DESCRIPTION:
		struct ptp_tlv_container *container =
			CONTAINER_OF(tlv, struct ptp_tlv_container, tlv);
		struct ptp_tlv_mgmt_clock_desc *clock_desc = &container->clock_desc;
		uint8_t *data = (uint8_t *)tlv->data;
		uint16_t data_lenght = length;

		clock_desc->type = (uint16_t *)data;
		data += sizeof(*clock_desc->type);
		data_lenght -= sizeof(*clock_desc->type);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		TLV_NTOHS(&clock_desc->type);

		clock_desc->phy_protocol = (struct ptp_text *)data;
		data += sizeof(*clock_desc->phy_protocol);
		data_length -= sizeof(*clock_desc->phy_protocol);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		data += clock_desc->phy_protocol->lenght;
		data_lenght -= clock_desc->phy_protocol->lenght;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->phy_addr_len = (uint16_t *)data;
		data += sizeof(*clock_desc->phy_addr_len);
		data_length -= sizeof(*clock_desc->phy_addr_len);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		TLV_NTOHS(&clock_desc->phy_addr_len);
		if (*clock_desc->phy_addr_len > TLV_ADDR_LEN_MAX) {
			return -EBADMSG;
		}

		clock_desc->phy_addr = data;
		data += *clock_desc->phy_addr_len;
		data_length -= *clock_desc->phy_addr_len;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->protocol_addr = (struct ptp_port_addr *)data;
		data += sizeof(*clock_desc->protocol_addr);
		data_length -= sizeof(*clock_desc->protocol_addr);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		TLV_NTOHS(&clock_desc->protocol_addr->protocol);
		TLV_NTOHS(&clock_desc->protocol_addr->addr_len);
		if (clock_desc->protocol_addr->addr_len > TLV_ADDR_LEN_MAX) {
			return -EBADMSG;
		}

		data += clock_desc->protocol_addr->addr_len;
		data_lenght -= clock_desc->protocol_addr->addr_len;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->manufacturer_id = data;
		/* extra byte for reserved field - see IEEE 1588-2019 15.5.3.1.2 */
		data += TLV_MANUFACTURER_ID_LEN + 1;
		data_lenght -= TLV_MANUFACTURER_ID_LEN + 1;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->product_desc = (struct ptp_text *)data;
		data += sizeof(*clock_desc->product_desc);
		data_length -= sizeof(*clock_desc->product_desc);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		data += clock_desc->product_desc->lenght;
		data_lenght -= clock_desc->product_desc->lenght;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->revision_data = (struct ptp_text *)data;
		data += sizeof(*clock_desc->revision_data);
		data_length -= sizeof(*clock_desc->revision_data);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		data += clock_desc->revision_data->lenght;
		data_lenght -= clock_desc->revision_data->lenght;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->user_desc = (struct ptp_text *)data;
		data += sizeof(*clock_desc->user_desc);
		data_length -= sizeof(*clock_desc->user_desc);
		if (data_lenght < 0) {
			return -EBADMSG;
		}
		data += clock_desc->user_desc->lenght;
		data_lenght -= clock_desc->user_desc->lenght;
		if (data_lenght < 0) {
			return -EBADMSG;
		}

		clock_desc->profile_id = data;
		data += TLV_PROFILE_ID_LEN;
		data_lenght -= TLV_PROFILE_ID_LEN;

		break;
	case PTP_MGMT_USER_DESCRIPTION:
		struct ptp_tlv_container *container =
			CONTAINER_OF(tlv, struct ptp_tlv_container, tlv);

		if (length < sizeof(struct ptp_text)) {
			return -EBADMSG;
		}
		container->clock_desc.user_desc = (struct ptp_text *)tlv->data;
		break;
	case PTP_MGMT_DEFAULT_DATA_SET:
		struct ptp_default_ds *default_ds;

		if (length != sizeof(*default_ds)) {
			return -EBADMSG;
		}
		default_ds = (struct ptp_default_ds *)tlv->data;

		default_ds->n_ports = ntohs(default_ds->n_ports);
		default_ds->clk_quality.offset_scaled_log_variance =
			ntohs(default_ds->clk_quality.offset_scaled_log_variance);
		break;
	case PTP_MGMT_CURRENT_DATA_SET:
		struct ptp_current_ds *current_ds;

		if (length != sizeof(*current_ds)) {
			return -EBADMSG;
		}
		current_ds = (struct ptp_current_ds *)tlv->data;

		current_ds->steps_rm = ntohs(current_ds->steps_rm);
		current_ds->offset_from_master = ntohll(current_ds->offset_from_master);
		current_ds->mean_delay = ntohll(current_ds->mean_delay);
		break;
	case PTP_MGMT_PARENT_DATA_SET:
		struct ptp_parent_ds *parent_ds;

		if (length != sizeof(*parent_ds)) {
			return -EBADMSG;
		}
		parent_ds = (struct ptp_parent_ds *)tlv->data;

		parent_ds->port_id.port_number = ntohs(parent_ds->port_id.port_number);
		parent_ds->obsreved_parent_offset_scaled_log_variance =
			ntohs(parent_ds->obsreved_parent_offset_scaled_log_variance);
		parent_ds->obsreved_parent_clk_phase_change_rate =
			ntohl(parent_ds->obsreved_parent_clk_phase_change_rate);
		parent_ds->gm_clk_quality.offset_scaled_log_variance =
			ntohs(parent_ds->gm_clk_quality.offset_scaled_log_variance);
		break;
	case PTP_MGMT_TIME_PROPERTIES_DATA_SET:
		struct ptp_time_prop_ds *time_prop_ds;

		if (length != sizeof(*time_prop_ds)) {
			return -EBADMSG;
		}
		time_prop_ds = (struct ptp_time_prop_ds *)tlv->data;

		time_prop_ds->current_utc_offset = ntohs(time_prop_ds->current_utc_offset);
		break;
	case PTP_MGMT_PORT_DATA_SET:
		struct ptp_port_ds *port_ds;

		if (length != sizeof(*port_ds)) {
			return -EBADMSG;
		}
		port_ds = (struct ptp_port_ds *)tlv->data;

		port_ds->id.port_number = ntohs(port_ds->id.port_number);
		port_ds->mean_link_delay = ntohll(port_ds->mean_link_delay);
		break;
	case PTP_MGMT_TIME:
		struct ptp_protocol_timestamp t = *(struct ptp_protocol_timestamp *)tlv->data;
		struct ptp_timestamp time;

		t.seconds_high = ntohs(t.seconds_high);
		t.seconds_low = ntohl(t.seconds_low);
		t.nanoseconds = ntohl(t.nanoseconds);

		time.seconds = ((uint64_t)t.seconds_high << 32 | (uint64_t)t.seconds_low);
		time.nanoseconds = t.nanoseconds;

		memcpy(tlv->data, &time, sizeof(time));
		break;
	case PTP_MGMT_UTC_PROPERTIES:
		// TODO IEEE 1588-2019 15.5.3.6.2
		break;
	case PTP_MGMT_PATH_TRACE_LIST:
		// TODO IEEE 1588-2019 15.5.3.3.6
		break;
	case PTP_MGMT_GRANDMASTER_CLUSTER_TABLE:
		// TODO IEEE 1588-2019 15.5.3.3.13
		break;
	case PTP_MGMT_UNICAST_MASTER_TABLE:
		// TODO IEEE 1588-2019 15.5.3.7.12
		break;
	case PTP_MGMT_UNICAST_MASTER_MAX_TABLE_SIZE:
		TLV_NTOHS(tlv->data);
		break;
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_NAME:
		// TODO IEEE 1588-2019 15.5.3.3.9
		break;
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_PROPERTIES:
		struct ptp_tlv_alt_time_offset_prop *prop;

		if (length != sizeof(*prop)) {
			return -EBADMSG;
		}
		prop = (struct ptp_tlv_alt_time_offset_prop *)tlv->data;

		/* struct fields are unaligned, need special treatment */
		prop->current_offset = ntohl(prop->current_offset);
		prop->jump_seconds = ntohl(prop->jump_seconds);

		break;
	}

	return 0;
}

static void tlv_mgmt_pre_send(struct ptp_tlv_mgmt *tlv)
{
	enum ptp_mgmt_id id = (enum ptp_mgmt_id)tlv->id;

	switch (id) {
	case PTP_MGMT_CLOCK_DESCRIPTION:
		struct ptp_tlv_container *container =
			CONTAINER_OF(tlv, struct ptp_tlv_container, tlv);
		struct ptp_tlv_mgmt_clock_desc *clock_desc = &container->clock_desc;

		TLV_HTONS(&clock_desc->type);
		TLV_HTONS(&clock_desc->phy_addr_len);
		TLV_HTONS(&clock_desc->protocol_addr->protocol);
		TLV_HTONS(&clock_desc->protocol_addr->addr_len);
		break;
	case PTP_MGMT_DEFAULT_DATA_SET:
		struct ptp_default_ds *default_ds = (struct ptp_default_ds *)tlv->data;

		default_ds->n_ports = htons(default_ds->n_ports);
		default_ds->clk_quality.offset_scaled_log_variance =
			htons(default_ds->clk_quality.offset_scaled_log_variance);
		default_ds->clk_id = htonll(default_ds->clk_id);
		break;
	case PTP_MGMT_CURRENT_DATA_SET:
		struct ptp_current_ds *current_ds = (struct ptp_current_ds *)tlv->data;

		current_ds->steps_rm = htons(current_ds->steps_rm);
		current_ds->offset_from_master = htonll(current_ds->offset_from_master);
		current_ds->mean_delay = htonll(current_ds->mean_delay);
		break;
	case PTP_MGMT_PARENT_DATA_SET:
		struct ptp_parent_ds *parent_ds = (struct ptp_parent_ds *)tlv->data;

		parent_ds->port_id.port_number = htons(parent_ds->port_id.port_number);
		parent_ds->obsreved_parent_offset_scaled_log_variance =
			htons(parent_ds->obsreved_parent_offset_scaled_log_variance);
		parent_ds->obsreved_parent_clk_phase_change_rate =
			htons(parent_ds->obsreved_parent_clk_phase_change_rate);
		parent_ds->gm_clk_quality.offset_scaled_log_variance =
			htons(parent_ds->gm_clk_quality.offset_scaled_log_variance);
		break;
	case PTP_MGMT_TIME_PROPERTIES_DATA_SET:
		struct ptp_time_prop_ds *time_prop_ds = (struct ptp_time_prop_ds *)tlv->data;

		time_prop_ds->current_utc_offset = htons(time_prop_ds->current_utc_offset);
		break;
	case PTP_MGMT_PORT_DATA_SET:
		struct ptp_port_ds *port_ds = (struct ptp_port_ds *)tlv->data;

		port_ds->id.port_number = htons(port_ds->id.port_number);
		port_ds->mean_link_delay = htonll(port_ds->mean_link_delay);
		break;
	case PTP_MGMT_TIME:
		struct ptp_protocol_timestamp t = *(struct ptp_protocol_timestamp *)tlv->data;
		struct ptp_timestamp time;

		t.seconds_high = htons(t.seconds_high);
		t.seconds_low = htonl(t.seconds_low);
		t.nanoseconds = htonl(t.nanoseconds);

		time.seconds = ((uint64_t)t.seconds_high << 32 | (uint64_t)t.seconds_low);
		time.nanoseconds = t.nanoseconds;

		memcpy(tlv->data, &time, sizeof(time));
		break;
	case PTP_MGMT_UTC_PROPERTIES:
		// TODO IEEE 1588-2019 15.5.3.6.2
		break;
	case PTP_MGMT_PATH_TRACE_LIST:
		// TODO IEEE 1588-2019 15.5.3.3.6
		break;
	case PTP_MGMT_GRANDMASTER_CLUSTER_TABLE:
		// TODO IEEE 1588-2019 15.5.3.3.13
		break;
	case PTP_MGMT_UNICAST_MASTER_TABLE:
		// TODO IEEE 1588-2019 15.5.3.7.12
		break;
	case PTP_MGMT_UNICAST_MASTER_MAX_TABLE_SIZE:
		TLV_HTONS(tlv->data);
		break;
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_NAME:
		// TODO IEEE 1588-2019 15.5.3.3.9
		break;
	case PTP_MGMT_ALTERNATE_TIME_OFFSET_PROPERTIES:
		// TODO IEEE 1588-2019 15.5.3.3.11
		break;
	}
}

struct ptp_tlv_container *ptp_tlv_alloc(void)
{
	struct ptp_tlv_container *tlv_container;

	if (!tlv_container) {
		LOG_ERR("Couldn't allocate memory for the message");
		return NULL;
	}

	return tlv_container;
}

void ptp_tlv_free(struct ptp_tlv_container *tlv_container)
{

}

enum ptp_mgmt_op ptp_mgmt_action_get(struct ptp_msg *msg) {
	(enum ptp_mgmt_op)msg->management.action;
}

enum ptp_tlv_type ptp_tlv_type_get(struct ptp_tlv *tlv) {
	(enum ptp_tlv_type)tlv->type;
}

int ptp_tlv_post_recv(struct ptp_tlv *tlv)
{
	int ret = 0;

	switch (ptp_tlv_type_get(tlv)) {
	case PTP_TLV_TYPE_MANAGEMENT:
		struct ptp_tlv_mgmt *mgmt;

		if (tlv->length < (sizeof(struct ptp_tlv_mgmt) - sizeof(struct ptp_tlv))) {
			return -EBADMSG;
		}
		mgmt = (struct ptp_tlv_mgmt *)tlv;
		mgmt->id = ntohs(mgmt->id);

		/* Value of length is 2 + N, where N is length of data field
		   based on IEEE 1588-2019 Section 15.5.2.2. */
		ret = tlv_mgmt_post_recv(mgmt, tlv->length - 2);
		break;
	case PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
		struct ptp_tlv_mgmt_err *mgmt_err;

		if (tlv->length < (sizeof(struct ptp_tlv_mgmt_err) - sizeof(struct ptp_tlv))) {
			return -EBADMSG;
		}
		mgmt_err = (struct ptp_tlv_mgmt_err *)tlv;
		mgmt_err->error = ntohs(mgmt_err->error);
		mgmt_err->id = ntohs(mgmt_err->id);
		break;
	case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		// TODO process unicast negotiation message
		break;
	case PTP_TLV_TYPE_PATH_TRACE:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE:
	case PTP_TLV_TYPE_ENHANCED_ACCURACY_METRICS:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE:
	case PTP_TLV_TYPE_L1_SYNC:
	case PTP_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY:
	case PTP_TLV_TYPE_PROTOCOL_ADDRESS:
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA:
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA:
	case PTP_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS:
	case PTP_TLV_TYPE_CUMULATIVE_RATE_RATIO:
	case PTP_TLV_TYPE_PAD:
	case PTP_TLV_TYPE_AUTHENTICATION:
		break;
	default:
		break;
	}

	return ret;
}

void ptp_tlv_pre_send(struct ptp_tlv *tlv)
{
	switch (ptp_tlv_type_get(tlv)) {
	case PTP_TLV_TYPE_MANAGEMENT:
		struct ptp_tlv_mgmt *mgmt = (struct ptp_tlv_mgmt *)tlv;

		/* Check if management TLV contains data */
		if (tlv->length > sizeof(mgmt->id)) {
			tlv_mgmt_pre_send(mgmt);
		}
		mgmt->id = htons(mgmt->id);
		break;
	case PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
		struct ptp_tlv_mgmt_err *mgmt_err = (struct ptp_tlv_mgmt_err *)tlv;

		mgmt_err->error = htons(mgmt_err->error);
		mgmt_err->id = htons(mgmt_err->id);
		break;
	case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:
	case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		// TODO process unicast negotiation message
		break;
	case PTP_TLV_TYPE_PATH_TRACE:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE:
	case PTP_TLV_TYPE_ENHANCED_ACCURACY_METRICS:
	case PTP_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE:
	case PTP_TLV_TYPE_L1_SYNC:
	case PTP_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY:
	case PTP_TLV_TYPE_PROTOCOL_ADDRESS:
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA:
	case PTP_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA:
	case PTP_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS:
	case PTP_TLV_TYPE_CUMULATIVE_RATE_RATIO:
	case PTP_TLV_TYPE_PAD:
	case PTP_TLV_TYPE_AUTHENTICATION:
		break;
	default:
		break;
	}

	tlv->length = htons(tlv->length);
	tlv->type = htons(tlv->type);
}
