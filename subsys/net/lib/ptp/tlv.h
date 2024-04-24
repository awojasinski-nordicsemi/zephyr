/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file tlv.h
 * @brief
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_TLV_H_
#define ZEPHYR_INCLUDE_PTP_TLV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "msg.h"

/**
 * @brief Type of TLV (time, lenght, value)
 *
 * @note based on IEEE 1588-2019 Section 14.1.1 Table 52
 */
enum ptp_tlv_type {
	PTP_TLV_TYPE_MANAGEMENT = 1,
	PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS,
	PTP_TLV_TYPE_ORGANIZATION_EXTENSION,
	PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION,
	PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION,
	PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION,
	PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION,
	PTP_TLV_TYPE_PATH_TRACE,
	PTP_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE = 0x4000,
	PTP_TLV_TYPE_ENHANCED_ACCURACY_METRICS,
	PTP_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE = 0x8000,
	PTP_TLV_TYPE_L1_SYNC,
	PTP_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY,
	PTP_TLV_TYPE_PROTOCOL_ADDRESS,
	PTP_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA,
	PTP_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA,
	PTP_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS,
	PTP_TLV_TYPE_CUMULATIVE_RATE_RATIO,
	PTP_TLV_TYPE_PAD,
	PTP_TLV_TYPE_AUTHENTICATION,
};

/**
 * @brief PTP managenment message action field
 *
 * @note based on IEEE 1588-2019 Section 15.4.1.6 Table 57
 */
enum ptp_mgmt_op {
	PTP_MGMT_GET,
	PTP_MGMT_SET,
	PTP_MGMT_RESP,
	PTP_MGMT_CMD,
	PTP_MGMT_ACK,
};

/**
 * @brief PTP managenment message ID
 *
 * @note based on IEEE 1588-2019 Section 15.5.2.3 Table 59
 */
enum ptp_mgmt_id {
	PTP_MGMT_NULL_PTP_MANAGEMENT = 0x0,
	PTP_MGMT_CLOCK_DESCRIPTION,
	PTP_MGMT_USER_DESCRIPTION,
	PTP_MGMT_SAVE_IN_NON_VOLATILE_STORAGE,
	PTP_MGMT_RESET_NON_VOLATILE_STORAGE,
	PTP_MGMT_INITIALIZE,
	PTP_MGMT_FAULT_LOG,
	PTP_MGMT_FAULT_LOG_RESET,
	PTP_MGMT_DEFAULT_DATA_SET = 0x2000,
	PTP_MGMT_CURRENT_DATA_SET,
	PTP_MGMT_PARENT_DATA_SET,
	PTP_MGMT_TIME_PROPERTIES_DATA_SET,
	PTP_MGMT_PORT_DATA_SET,
	PTP_MGMT_PRIORITY1,
	PTP_MGMT_PRIORITY2,
	PTP_MGMT_DOMAIN,
	PTP_MGMT_SLAVE_ONLY,
	PTP_MGMT_LOG_ANNOUNCE_INTERVAL,
	PTP_MGMT_ANNOUNCE_RECEIPT_TIMEOUT,
	PTP_MGMT_LOG_SYNC_INTERVAL,
	PTP_MGMT_VERSION_NUMBER,
	PTP_MGMT_ENABLE_PORT,
	PTP_MGMT_DISABLE_PORT,
	PTP_MGMT_TIME,
	PTP_MGMT_CLOCK_ACCURACY,
	PTP_MGMT_UTC_PROPERTIES,
	PTP_MGMT_TRACEBILITY_PROPERTIES,
	PTP_MGMT_TIMESCALE_PROPERTIES,
	PTP_MGMT_UNICAST_NEGOTIATION_ENABLE,
	PTP_MGMT_PATH_TRACE_LIST,
	PTP_MGMT_PATH_TRACE_ENABLE,
	PTP_MGMT_GRANDMASTER_CLUSTER_TABLE,
	PTP_MGMT_UNICAST_MASTER_TABLE,
	PTP_MGMT_UNICAST_MASTER_MAX_TABLE_SIZE,
	PTP_MGMT_ACCEPTABLE_MASTER_TABLE,
	PTP_MGMT_ACCEPTABLE_MASTER_TABLE_ENABLED,
	PTP_MGMT_ACCEPTABLE_MASTER_MAX_TABLE_SIZE,
	PTP_MGMT_ALTERNATE_MASTER,
	PTP_MGMT_ALTERNATE_TIME_OFFSET_ENABLE,
	PTP_MGMT_ALTERNATE_TIME_OFFSET_NAME,
	PTP_MGMT_ALTERNATE_TIME_OFFSET_MAX_KEY,
	PTP_MGMT_ALTERNATE_TIME_OFFSET_PROPERTIES,
	PTP_MGMT_EXTERNAL_PORT_CONFIGURATION_ENABLED = 0x3000,
	PTP_MGMT_MASTER_ONLY,
	PTP_MGMT_HOLDOVER_UPGRADE_ENABLE,
	PTP_MGMT_EXT_PORT_CONFIG_PORT_DATA_SET,
	PTP_MGMT_TRANSPARENT_CLOCK_DEFAULT_DATA_SET = 0x4000,
	PTP_MGMT_TRANSPARENT_CLOCK_PORT_DATA_SET,
	PTP_MGMT_PRIMARY_DOMAIN,
	PTP_MGMT_DELAY_MECHANISM = 0x6000,
	PTP_MGMT_LOG_MIN_PDELAY_REQ_INTERVAL,
};

/**
 * @brief Management error ID
 *
 * @note based on IEEE 1588-2019 Section 15.5.4.4 Table 109
 */
enum ptp_mgmt_err {
	PTP_MGMT_ERR_RESPONSE_TOO_BIG = 0x1,
	PTP_MGMT_ERR_NO_SUCH_ID,
	PTP_MGMT_ERR_WRONG_LENGTH,
	PTP_MGMT_ERR_WRONG_VALUE,
	PTP_MGMT_ERR_NOT_SETABLE,
	PTP_MGMT_ERR_NOT_SUPPORTED,
	PTP_MGMT_ERR_UNPOPULATED,
	PTP_MGMT_ERR_GENERAL = 0xFFFE,
};

/**
 * @brief PAD TLV - used to increase length of any PTP message.
 *
 * @note 14.4.2 - PAD TLV
 */
struct ptp_tlv_pad {
	uint16_t type;
	uint16_t length;
	uint8_t  pad[];
} __packed;

/**
 * @brief Organization-specific TLV.
 *
 * @note 14.3.2 - Vendor and standard organization extension TLVs.
 */
struct ptp_tlv_org {
	uint16_t type;
	uint16_t length;
	uint8_t  id[3];
	uint8_t  subtype[3];
	uint8_t  data[];
} __packed;

/**
 * @brief Management TLV.
 *
 * @note 15.5.2 - MANAGEMENT TLV field format.
 */
struct ptp_tlv_mgmt {
	uint16_t type;
	uint16_t length;
	uint16_t id;
	uint8_t  data[];
} __packed;

/**
 * @brief TLV for timescale offset attributes
 *
 * @note 15.5.3.3.11 - ALTERNATE_TIME_OFFSET_PROPERTIES management TLV
 */
struct ptp_tlv_alt_time_offset_prop {
	uint8_t  key;
	int32_t  current_offset;
	int32_t  jump_seconds;
	struct {
		uint16_t seconds_high;
		uint32_t seconds_low;
	} __packed next_jump_time;
	uint8_t  reserved;
} __packed;

/**
 * @brief Management error status TLV.
 *
 * @note 15.5.4 - MANAGEMENT_ERROR_STATUS TLV format.
 */
struct ptp_tlv_mgmt_err {
	uint16_t	type;
	uint16_t	length;
	uint16_t	err_id;
	uint16_t	id;
	uint32_t	reserved;
	struct ptp_text display_data;
} __packed;

/**
 * @brief
*/
struct ptp_tlv_mgmt_clock_desc {
	uint16_t	     *type;
	struct ptp_text	     *phy_protocol;
	uint16_t	     *phy_addr_len;
	uint8_t		     *phy_addr;
	struct ptp_port_addr *protocol_addr;
	uint8_t		     *manufacturer_id;
	struct ptp_text	     *product_desc;
	struct ptp_text	     *revision_data;
	struct ptp_text	     *user_desc;
	uint8_t		     *profile_id;
};

struct ptp_tlv_container {
	sys_snode_t		       node;
	struct ptp_tlv		       *tlv;
	struct ptp_tlv_mgmt_clock_desc clock_desc;
};

/**
 * @brief Function allocating memory for TLV container structure.
 *
 * @return Pointer to the TLV container structure.
 */
struct ptp_tlv_container *ptp_tlv_alloc(void);

/**
 * @brief Function freeing memory used by TLV container.
 *
 * @param[in] tlv_container Pointer to the TLV container structure.
 */
void ptp_tlv_free(struct ptp_tlv_container *tlv_container);

/**
 * @brief Function for getting type of action to be taken on recipt of the PTP message.
 *
 * @param[in] msg Pointer to the PTP message.
 *
 * @return Type of action to be taken.
 */
enum ptp_mgmt_op ptp_mgmt_action_get(struct ptp_msg *msg);

/**
 * @brief Function for getting type of the TLV.
 *
 * @param[in] tlv Pointer to the TLV.
 *
 * @return Type of TLV message.
 */
enum ptp_tlv_type ptp_tlv_type_get(struct ptp_tlv *tlv);

/**
 * @brief Function processing TLV after reception, and before processing by PTP stack.
 *
 * @param[in] tlv Pointer to the received TLV.
 *
 * @return Zero on success, othervise negative.
*/
int ptp_tlv_post_recv(struct ptp_tlv *tlv);

/**
 * @brief Function preparing TLV to on-wire format before transmitting.
 *
 * @param[in] tlv Pointer to the received TLV.
 */
void ptp_tlv_pre_send(struct ptp_tlv *tlv);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */


#endif /* ZEPHYR_INCLUDE_PTP_TLV_H_ */
