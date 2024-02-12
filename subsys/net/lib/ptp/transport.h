/*
 * Copyright (c)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file transport.h
 *
 * @brief Function and data structures used for state machine of the PTP.
 */

#ifndef ZEPHYR_INCLUDE_PTP_TRANSPORT_H_
#define ZEPHYR_INCLUDE_PTP_TRANSPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief
 */
enum ptp_net_protocol {
	PTP_NET_PROTOCOL_UDP_IPv4 = 1,
	PTP_NET_PROTOCOL_UDP_IPv6,
	PTP_NET_PROTOCOL_IEEE_802_3,
};

/**
 * @brief
 */
struct transport_if {
	enum ptp_net_protocol type;
	int (*open)(void);
	int (*close)(void);
	int (*send)(void);
	int (*receive)(void);
	int (*release)(void);
	int (*protocol_addr)(void);
	int (*physical_addr)(void);
};

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_TRANSPORT_H_ */
