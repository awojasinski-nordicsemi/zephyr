/*
 * Copyright (c)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file transport.h
 * @brief Function implementing abstraction over networking protocols.
 */

#ifndef ZEPHYR_INCLUDE_PTP_TRANSPORT_H_
#define ZEPHYR_INCLUDE_PTP_TRANSPORT_H_

#include "port.h"

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
	int sock;
	int (*open)(struct ptp_port *port);
	int (*close)(struct ptp_port *port);
	int (*send)(struct ptp_port *port);
	int (*recv)(struct ptp_port *port);
	int (*protocol_addr)(struct ptp_port *port);
	int (*physical_addr)(struct ptp_port *port);
};

/**
 * @brief Function handling opening specified transport network connection.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_open(struct ptp_port *port);

/**
 * @brief Function for closing specified transport network connection.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_close(struct ptp_port *port);

/**
 * @brief Function for sending PTP message using a specified transport.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_send(struct ptp_port *port);

/**
 * @brief Function for receiving a PTP message using a specified transport.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_recv(struct ptp_port *port);

/**
 * @brief
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_protocol_addr(struct ptp_port *port);

/**
 * @brief
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_physical_addr(struct ptp_port *port);

/* Transport specific function declarations */

#if CONFIG_PTP_IEEE_802_3_PROTOCOL
int ptp_transport_raw_open(struct ptp_port *port);
int ptp_transport_raw_close(struct ptp_port *port);
int ptp_transport_raw_send(struct ptp_port *port);
int ptp_transport_raw_recv(struct ptp_port *port);
int ptp_transport_raw_protocol_addr(struct ptp_port *port);
int ptp_transport_raw_physical_addr(struct ptp_port *port);
#endif

#if CONFIG_PTP_UDP_IPv4_PROTOCOL
int ptp_transport_udp_open(struct ptp_port *port);
int ptp_transport_udp_close(struct ptp_port *port);
int ptp_transport_udp_send(struct ptp_port *port);
int ptp_transport_udp_recv(struct ptp_port *port);
int ptp_transport_udp_protocol_addr(struct ptp_port *port);
int ptp_transport_udp_physical_addr(struct ptp_port *port);
#endif

#if CONFIG_PTP_UDP_IPv6_PROTOCOL
int ptp_transport_udp6_open(struct ptp_port *port);
int ptp_transport_udp6_close(struct ptp_port *port);
int ptp_transport_udp6_send(struct ptp_port *port);
int ptp_transport_udp6_recv(struct ptp_port *port);
int ptp_transport_udp6_protocol_addr(struct ptp_port *port);
int ptp_transport_udp6_physical_addr(struct ptp_port *port);
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_TRANSPORT_H_ */
