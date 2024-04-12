/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_transport_udp, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/net/socket.h>

#include "transport.h"

int ptp_transport_udp_open(struct ptp_port *port, int ttl)
{
	int socket, index, on=1;
	struct sockaddr_in addr;
	struct net_eth_addr mac;

	socket = zsock_socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(socket < 0) {
		LOG_ERR("Failed to open socket on PTP Port %d", port->port_ds.id.port_number);
		return -1;
	}

	index = net_if_get_by_iface(port->iface);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htons(INADDR_ANY);
	addr.sin_port = htons(port->port_ds.id.port_number);

	port->transport.addr = (struct sockaddr)addr;
	net_eth_ipv4_mcast_to_mac_addr(&addr.sin_addr, &mac);

	if (zsock_setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		LOG_ERR("Failed to set reuseaddr socket option");
		goto error;
	}

	if (zsock_bind(socket, (struct sockaddr *)&addr, sizeof(addr))) {
		LOG_ERR("Faild to bind socket");
		goto error;
	}

	if (zsock_setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		LOG_ERR("Failed to set socket binding to an interface");
		goto error;
	}

	if (socket_priority > 0 &&
	    zsock_setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) {
		LOG_ERR("Failed to set ip multicast ttl socket option");
		goto error;
	}

	return socket;

error:
	zsock_close(socket);
	return -1;
}

int ptp_transport_udp_close(struct ptp_port *port)
{
	if (port->transport.sock >= 0) {
		if (zsock_close(port->transport.sock)) {
			LOG_ERR("Failed to close socket on PTP Port %d",
				port->port_ds.id.port_number);
			return -1;
		}
	}

	port->transport.sock = -1;
	return 0;
}

int ptp_transport_udp_send(struct ptp_port *port, )
{

}

int ptp_transport_udp_recv(struct ptp_port *port, )
{

}

int ptp_transport_udp_protocol_addr(struct ptp_port *port, uint8_t *addr)
{

}

int ptp_transport_udp_physical_addr(struct ptp_port *port, uint8_t *addr)
{

}
