/*
 * Copyright (c)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file transport.h
 * @brief Function and data structures used for state machine of the PTP.
 */

#ifndef ZEPHYR_INCLUDE_PTP_TRANSPORT_H_
#define ZEPHYR_INCLUDE_PTP_TRANSPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Types of PTP networking protocols.
 */
enum ptp_net_protocol {
	PTP_NET_PROTOCOL_UDP_IPv4 = 1,
	PTP_NET_PROTOCOL_UDP_IPv6,
	PTP_NET_PROTOCOL_IEEE_802_3,
};

/**
 * @brief Transport interface structure.
 */
struct ptp_transport_if {
	enum ptp_net_protocol type;
	int (*open)(void);
	int (*close)(void);
	int (*send)(void);
	int (*recv)(void);
	int (*protocol_addr)(void);
	int (*physical_addr)(void);
};

/**
 * @brief Function handling opening specified transport network connection.
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_open();

/**
 * @brief Function for closing specified transport network connection.
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_close();

/**
 * @brief Function for sending PTP message using a specified transport.
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_send();

/**
 * @brief Function for receiving a PTP message using a specified transport.
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_recv();

/**
 * @brief
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_protocol_addr();

/**
 * @brief
 *
 * @param[in] x
 *
 * @return
 */
int ptp_transport_physical_addr();

#if CONFIG_PTP_IEEE_802_3_PROTOCOL
int ptp_transport_eth_open();
int ptp_transport_eth_close();
int ptp_transport_eth_send();
int ptp_transport_eth_recv();
int ptp_transport_eth_protocol_addr();
int ptp_transport_eth_physical_addr();
#endif

#if CONFIG_PTP_UDP_IPv4_PROTOCOL
int ptp_transport_udp_open();
int ptp_transport_udp_close();
int ptp_transport_udp_send();
int ptp_transport_udp_recv();
int ptp_transport_udp_protocol_addr();
int ptp_transport_udp_physical_addr();
#endif

#if CONFIG_PTP_UDP_IPv6_PROTOCOL
int ptp_transport_udp6_open();
int ptp_transport_udp6_close();
int ptp_transport_udp6_send();
int ptp_transport_udp6_recv();
int ptp_transport_udp6_protocol_addr();
int ptp_transport_udp6_physical_addr();
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_TRANSPORT_H_ */
