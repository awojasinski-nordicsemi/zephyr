/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file transport.h
 * @brief Function implementing abstraction over networking protocols.
 */

#ifndef ZEPHYR_INCLUDE_PTP_TRANSPORT_H_
#define ZEPHYR_INCLUDE_PTP_TRANSPORT_H_

#include <zephyr/net/net_ip.h>
#include <zephyr/net/ethernet.h>

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
 * @brief Function for sending PTP message using a specified transport. The message is sent
 * to the default multicast address.
 *
 * @note Address specified in the message is ignored.
 *
 * @param[in] port Pointer to the PTP Port structure
 * @param[in] msg  Pointer to the messge to be send.
 *
 * @return
 */
int ptp_transport_send(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function for sending PTP message using a specified transport. The message is sent
 * to the address provided with @ref ptp_msg message structure.
 *
 * @param[in] port Pointer to the PTP Port structure
 * @param[in] msg  Pointer to the messge to be send.
 *
 * @return
 */
int ptp_transport_sendto(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function for sending PTP message using a specified transport. The message is sent
 * to the address used for p2p delay measurement.
 *
 * @note Address specified in the message is ignored.
 *
 * @param[in] port Pointer to the PTP Port structure
 * @param[in] msg  Pointer to the messge to be send.
 *
 * @return
 */
int ptp_transport_send_peer(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function for receiving a PTP message using a specified transport.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_recv(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function for getting transport's protocol address.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_protocol_addr(struct ptp_port *port);

/**
 * @brief Function for getting transport's physical address.
 *
 * @param[in] port Pointer to the PTP Port structure
 *
 * @return
 */
int ptp_transport_physical_addr(struct ptp_port *port);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_TRANSPORT_H_ */
