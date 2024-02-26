/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_transport, CONFIG_PTP_LOG_LEVEL);

#include "transport.h"

const struct ptp_transport_if iface = {
#if CONFIG_PTP_IEEE_802_3_PROTOCOL
	.type  = PTP_NET_PROTOCOL_IEEE_802_3,
	.open = ptp_transport_eth_open,
	.close = ptp_transport_eth_close,
	.send = ptp_transport_eth_send,
	.recv = ptp_transport_eth_recv,
	.protocol_addr = ptp_transport_eth_protocol_addr,
	.physical_addr = ptp_transport_eth_physical_addr,
#endif
#if CONFIG_PTP_UDP_IPv4_PROTOCOL
	.type  = PTP_NET_PROTOCOL_UDP_IPv4,
	.open = ptp_transport_udp_open,
	.close = ptp_transport_udp_close,
	.send = ptp_transport_udp_send,
	.recv = ptp_transport_udp_recv,
	.protocol_addr = ptp_transport_udp_protocol_addr,
	.physical_addr = ptp_transport_udp_physical_addr,
#endif
#if CONFIG_PTP_UDP_IPv6_PROTOCOL
	.type  = PTP_NET_PROTOCOL_UDP_IPv6,
	.open = ptp_transport_udp6_open,
	.close = ptp_transport_udp6_close,
	.send = ptp_transport_udp6_send,
	.recv = ptp_transport_udp6_recv,
	.protocol_addr = ptp_transport_udp6_protocol_addr,
	.physical_addr = ptp_transport_udp6_physical_addr,
#endif
};

int ptp_transport_open(struct ptp_port *port)
{
	int socket = iface.open(port, 0);

	if (socket < 0) {
		return -1;
	}

	port->transport.sock = socket;
	return 0;
}

int ptp_transport_close(struct ptp_port *port)
{
	return iface.close(port);
}

int ptp_transport_send(struct ptp_port *port, struct ptp_msg *msg)
{
	int length = ntohs(msg->header.msg_length);

	return iface.send(port, msg, len, NULL);
}

int ptp_transport_sendto(struct ptp_port *port, struct ptp_msg *msg)
{
	int length = ntohs(msg->header.msg_length);

	return iface.send(port, msg, len, msg->addr);
}

int ptp_transport_send_peer(struct ptp_port *port, struct ptp_msg *msg)
{

}

int ptp_transport_recv(struct ptp_port *port)
{
	return iface.recv(port, );
}

int ptp_transport_protocol_addr(struct ptp_port *port)
{
	return iface.protocol_addr(port, );
}

int ptp_transport_physical_addr(struct ptp_port *port)
{
	return iface.physical_addr(port, );
}

int ptp_transport_create(struct ptp_port *port)
{
	port->transport = iface;
}
