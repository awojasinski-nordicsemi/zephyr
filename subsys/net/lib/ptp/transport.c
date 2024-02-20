/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
	.type  = PTP_NET_PROTOCOL_IEEE_802_3,
	.open = ptp_transport_udp_open,
	.close = ptp_transport_udp_close,
	.send = ptp_transport_udp_send,
	.recv = ptp_transport_udp_recv,
	.protocol_addr = ptp_transport_udp_protocol_addr,
	.physical_addr = ptp_transport_udp_physical_addr,
#endif
#if CONFIG_PTP_UDP_IPv6_PROTOCOL
	.type  = PTP_NET_PROTOCOL_IEEE_802_3,
	.open = ptp_transport_udp6_open,
	.close = ptp_transport_udp6_close,
	.send = ptp_transport_udp6_send,
	.recv = ptp_transport_udp6_recv,
	.protocol_addr = ptp_transport_udp6_protocol_addr,
	.physical_addr = ptp_transport_udp6_physical_addr,
#endif
};

int ptp_transport_open()
{
	return iface.open();
}

int ptp_transport_close()
{
	return iface.close();
}

int ptp_transport_send()
{
	return iface.send();
}

int ptp_transport_recv()
{
	return iface.recv();
}

int ptp_transport_protocol_addr()
{
	return iface.protocol_addr();
}

int ptp_transport_physical_addr()
{
	return iface.physical_addr();
}
