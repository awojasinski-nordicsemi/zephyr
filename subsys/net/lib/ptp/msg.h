/*
 * Copyright (c) 2024 BayLibre SAS
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

#include <stdbool.h>

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/ptp_time.h>

#include "ddt.h"

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
	uint8_t		   type_major_sdo_id;
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
	struct ptp_header      hdr;
	struct ptp_timestamp   origin_timestamp;
	uint16_t	       current_utc_offset;
	uint8_t		       reserved;
	uint8_t		       gm_priority1;
	struct ptp_clk_quality gm_clk_quality;
	uint8_t		       gm_priority2;
	ptp_clk_id	       gm_id;
	uint16_t	       steps_rm;
	uint8_t		       time_src;
	uint8_t		       suffix[];
} __packed;

/**
 * @brief PTP Sync message header.
 */
struct ptp_sync_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp origin_timestamp;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Delay_Req message header.
 */
struct ptp_delay_req_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp origin_timestamp;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Follow_Up message header.
 */
struct ptp_follow_up_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp precise_origin_timestamp;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Delay_Resp message header.
 */
struct ptp_delay_resp_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp receive_timestamp;
	struct ptp_port_id   req_port_id;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Pdelay_Req message header.
 */
struct ptp_pdelay_req_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp origin_timestamp;
	struct ptp_port_id   reserved; /* make it the same length as ptp_pdelay_resp */
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Pdelay_Resp message header.
 */
struct ptp_pdelay_resp_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp req_receipt_timestamp;
	struct ptp_port_id   req_port_id;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Pdelay_Resp_Follow_Up message header.
 */
struct ptp_pdelay_resp_follow_up_msg {
	struct ptp_header    hdr;
	struct ptp_timestamp resp_origin_timestamp;
	struct ptp_port_id   req_port_id;
	uint8_t		     suffix[];
} __packed;

/**
 * @brief PTP Signaling message header.
 */
struct ptp_signaling_msg {
	struct ptp_header  hdr;
	struct ptp_port_id target_port_id;
	uint8_t		   suffix[];
} __packed;

/**
 * @brief PTP Management message header.
 */
struct ptp_management_msg {
	struct ptp_header  hdr;
	struct ptp_port_id target_port_id;
	uint8_t		   starting_boundry_hops;
	uint8_t		   boundry_hops;
	uint8_t		   action:5;
	uint8_t		   reserved;
	uint8_t		   suffix[];
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
		uint8_t				     mtu[1500]; // MTU of Ethernet II frame
	} __packed;
	struct {
		/**
		 * Timestamp extracted from the message in a host binary format.
		 * Depending on the messahe type the value comes from different
		 * field of the message.
		 */
		struct net_ptp_time protocol;
		struct net_ptp_time host; // Ingress timestamp on the host side.

	} timestamp;
	int ref;
	struct sockaddr addr;
	sys_slist_t tlvs;
};

/**
 * @brief Function allocating space for a new PTP message.
 *
 * @return Pointer to the new PTP Message.
 */
struct ptp_msg *ptp_msg_alloc(void);

/**
 * @brief Function removing reference to the PTP message.
 *
 * @note If the message is not referenced anywhere, the memory space is cleared.
 *
 * @param[in] msg Pointer to the PTP message.
 */
void ptp_msg_unref(struct ptp_msg *msg);

/**
 * @brief Function duplicating message instance.
 *
 * @note Pointer of a message passed to the function must be in the network byte order.
 *
 * @param[in] msg    Pointer to a message instance.
 * @param[in] lenght Length in bytes of a message.
 *
 * @return Pointer to the duplicated message if successful, NULL otherwise.
 * The message is in the host byte order.
 */
struct ptp_msg *ptp_msg_duplicate(struct ptp_msg *msg, size_t lenght);

/**
 * @brief Function compering content of two PTP Announce messages.
 *
 * @param[in] m1 Pointer to the Announce message to be compared.
 * @param[in] m2 Pointer to the Announce message to be compared.
 *
 * @return Negative if m1 < m2, 0 if equal, else positive
*/
int ptp_msg_announce_cmp(const struct ptp_msg *m1, const struct ptp_msg *m2);

/**
 * @brief Function checking if given message comes from current PTP Port's Master PTP instance.
 *
 * @param[in] port Pointer to the PTP Port instance.
 * @param[in] msg  Pointer to the message.
 *
 * @return True if the message is received from the curent PTP Port's Master, false otherwise.
 */
bool ptp_msg_current_parent_check(const struct ptp_port *port, const struct ptp_msg *msg);

/**
 * @brief Function extracting message type from it.
 *
 * @param[in] msg Pointer to the message.
 *
 * @return Type of the message.
 */
enum ptp_msg_type ptp_msg_type_get(const struct ptp_msg *msg);

/**
 * @brief Function extracting PTP message from network packet.
 *
 * @param[in] pkt Pointer to the network packet.
 *
 * @note Returned message has all data in the network byte order.
 *
 * @return Pointer to a PTP message.
 */
struct ptp_msg *ptp_msg_get_from_pkt(struct net_pkt *pkt);

/**
 * @brief Function preparing message right before transmission.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 * @param[in] msg   Pointer to the prepared PTP message.
 */
void ptp_msg_pre_send(struct ptp_clock *clock, struct ptp_msg *msg);

/**
 * @brief Function preparing message for further processing after reception.
 *
 * @param[in] port Pointer to the PTP Port instance.
 * @param[in] msg  Pointer to the received PTP message.
 * @param[in] cnt  Length of the message in bytes.
 *
 * @return 0 on success, negative otherwise.
 */
int ptp_msg_post_recv(struct ptp_port *port, struct ptp_msg *msg, int cnt);

/**
 * @brief Function adding TLV of specified length to the message.
 *
 * @param[in] msg    Pointer to the message that will have TLV added.
 * @param[in] length Length of the TLV.
 *
 * @return Pointer to the TLV or NULL if there was no space to append TLV to the message.
 */
struct ptp_tlv *ptp_msg_add_tlv(struct ptp_msg *msg, int length);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_MSG_H_ */
