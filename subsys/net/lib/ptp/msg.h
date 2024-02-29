/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file msg.h
 * @brief Derived data types.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_MSG_H_
#define ZEPHYR_INCLUDE_PTP_MSG_H_

#include <zephyr/kernel.h>

#include "port.h"

#ifdef __cplusplus
extern "C" {
#endif

/* values of the bits of the flagField array for PTP message */
#define PTP_MSG_ALT_MASTER_FLAG	    BIT(0)
#define PTP_MSG_TWO_STEP_FLAG	    BIT(1)
#define PTP_MSG_UNICAST_FLAG	    BIT(2)

#define PTP_MSG_LEAP_61_FLAG	    BIT(0)
#define PTP_MSG_LEAP_59_FLAG	    BIT(1)
#define PTP_MSG_UTC_OFF_VALID_FLAG  BIT(2)
#define PTP_MSG_PTP_TIMESCALE_FLAG  BIT(3)
#define PTP_MSG_TIME_TRACEABLE_FLAG BIT(4)
#define PTP_MSG_FREQ_TRACEABLE_FLAG BIT(5)
#define PTP_MSG_SYNC_UNCERTAIN_FLAG BIT(5)

/**
 * @brief PTP message type.
 */
enum ptp_msg_type {
	/* PTP event message types */
	PTP_MSG_SYNC = 0,
	PTP_MSG_DELAY_REQ,
	PTP_MSG_PDELAY_REQ,
	PTP_MSG_PDELAY_RESP,
	/* General PTP message types */
	PTP_MSG_FOLLOW_UP = 8,
	PTP_MSG_DELAY_RESP,
	PTP_MSG_PDELAY_RESP_FOLLOW_UP,
	PTP_MSG_ANNOUNCE,
	PTP_MSG_SIGNALING,
	PTP_MSG_MANAGEMENT,
};

/**
 * @brief Common PTP message header.
 */
struct ptp_header {
	uint8_t		   type:4;
	uint8_t		   major_sdo_id:4;
	uint8_t		   version;
	uint16_t	   msg_length;
	uint8_t		   domain_number;
	uint8_t		   minor_sdo_id;
	uint8_t		   flags[2];
	int64_t		   correction;
	uint32_t	   reserved;
	struct ptp_port_id src_port_id;
	uint16_t	   sequence_id;
	uint8_t		   control;
	int8_t		   log_msg_interval;
} __packed;

/**
 * @brief PTP Announce message header.
 */
struct ptp_announce_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp origin_timestamp;
	uint16_t		      current_utc_offset;
	uint8_t			      reserved;
	uint8_t			      gm_priority1;
	struct ptp_clk_quality	      gm_clk_quality;
	uint8_t			      gm_priority2;
	ptp_clk_id		      gm_id;
	uint16_t		      steps_rm;
	uint8_t			      time_src;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Sync message header.
 */
struct ptp_sync_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp origin_timestamp;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Delay_Req message header.
 */
struct ptp_delay_req_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp origin_timestamp;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Follow_Up message header.
 */
struct ptp_follow_up_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp precise_origin_timestamp;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Delay_Resp message header.
 */
struct ptp_delay_resp_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp receive_timestamp;
	struct ptp_port_id	      req_port_id;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Pdelay_Req message header.
 */
struct ptp_pdelay_req_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp origin_timestamp;
	struct ptp_port_id	      reserved; /* make it the same length as ptp_pdelay_resp */
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Pdelay_Resp message header.
 */
struct ptp_pdelay_resp_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp req_receipt_timestamp;
	struct ptp_port_id	      req_port_id;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Pdelay_Resp_Follow_Up message header.
 */
struct ptp_pdelay_resp_follow_up_msg {
	struct ptp_header	      hdr;
	struct ptp_protocol_timestamp resp_origin_timestamp;
	struct ptp_port_id	      req_port_id;
	uint8_t			      suffix[0];
} __packed;

/**
 * @brief PTP Signaling message header.
 */
struct ptp_signaling_msg {
	struct ptp_header  hdr;
	struct ptp_port_id target_port_id;
	uint8_t		   suffix[0];
} __packed;

/**
 * @brief PTP Management message header.
 */
struct ptp_management_msg {
	struct ptp_header  hdr;
	struct ptp_port_id target_port_id;
	uint8_t		   starting_boundry_hops;
	uint8_t		   action:5;
	uint8_t		   reserved;
	uint8_t		   suffix[0];
} __packed;

/**
 * @brief Generic PTP message structure.
 */
struct ptp_msg {
	union {
		struct ptp_header		     header;
		struct ptp_announce_msg		     announce;
		struct ptp_sync_msg		     sync;
		struct ptp_delay_req_msg	     delay_req;
		struct ptp_follow_up_msg	     follow_up;
		struct ptp_delay_resp_msg	     delay_resp;
		struct ptp_pdelay_req_msg	     pdelay_req;
		struct ptp_pdelay_resp_msg	     pdelay_resp;
		struct ptp_pdelay_resp_follow_up_msg pdelay_resp_follow_up;
		struct ptp_signaling_msg	     signaling;
		struct ptp_management_msg	     management;
	};
	struct {
		struct ptp_timestamp protocol;
		struct ptp_timestamp host;
	} timestamp;

	struct sockaddr addr;
};

/**
 * @brief Function processing receipt of an announce message.
 *
 * @param[in] port Pointer to the PTP Port structure.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Non-zero if the announce message is qualified for consideration by BMCA.
 */
void ptp_announce_msg_process(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function compering content of two PTP announce messages.
 *
 * @param[in] m1 Pointer to the announce message to be compared.
 * @param[in] m2 Pointer to the announce message to be compared.
 *
 * @return Negative if m1 < m2, 0 if equal, else positive
*/
int ptp_announce_msg_cmp(const struct ptp_msg *m1, const struct ptp_msg *m2);

/**
 * @brief Function processing receipt of a sync message.
 *
 * @param[in] port Pointer to the PTP Port structure.
 * @param[in] msg  Pointer to the received PTP message.
 */
void ptp_sync_msg_process(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function processing receipt of a follow_up message.
 *
 * @param[in] port Pointer to the PTP Port structure.
 * @param[in] msg  Pointer to the received PTP message.
 */
void ptp_follow_up_msg_process(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function processing receipt of a delay_req message.
 *
 * @param[in] port Pointer to the PTP Port structure.
 * @param[in] msg  Pointer to the received PTP message.
 */
void ptp_delay_req_msg_process(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function processing receipt of a delay_resp message.
 *
 * @param[in] port Pointer to the PTP Port structure.
 * @param[in] msg  Pointer to the received PTP message.
 */
void ptp_delay_resp_msg_process(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function extracting message type from it.
 *
 * @param[in] msg Pointer to the message.
 *
 * @return Type of the message.
*/
enum ptp_msg_type ptp_msg_type_get(const struct ptp_msg *msg);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_MSG_H_ */
