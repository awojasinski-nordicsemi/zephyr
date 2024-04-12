/*
 * Copyright (c) 2024 BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_transport_raw, CONFIG_PTP_LOG_LEVEL);

#include <zephyr/net/socket.h>
#include <zephyr/net/ethernet.h>

#include "transport.h"


int ptp_transport_raw_open(struct ptp_port *port, int socket_priority)
{
	int socket, index;
	struct sockaddr_ll addr;

	socket = zsock_socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(socket < 0) {
		LOG_ERR("Failed to open socket on PTP Port %d", port->port_ds.id.port_number);
		return -1;
	}

	index = net_if_get_by_iface(port->iface);

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);

	port->transport.addr = (struct sockaddr)addr;

	if (zsock_bind(socket, (struct sockaddr *)&addr, sizeof(addr))) {
		LOG_ERR("Faild to bind socket");
		goto error;
	}

	if (zsock_setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		LOG_ERR("Failed to set socket binding to an interface");
		goto error;
	}

	if (socket_priority > 0 &&
	    zsock_setsockopt(socket, SOL_SOCKET, SO_PRIORITY, &socket_priority,
			     sizeof(socket_priority))) {
		LOG_ERR("Failed to set socket priority");
		goto error;
	}

	return socket;

error:
	zsock_close(socket);
	return -1;
}

int ptp_transport_raw_close(struct ptp_port *port)
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

int ptp_transport_raw_send(struct ptp_port *port, struct ptp_msg *msg, size_t len)
{

}

int ptp_transport_raw_recv(struct ptp_port *port, struct ptp_msg *msg, size_t max_len)
{

}

int ptp_transport_raw_protocol_addr(struct ptp_port *port, )
{

}

int ptp_transport_raw_physical_addr(struct ptp_port *port, )
{

}
