/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_transport_raw, CONFIG_PTP_LOG_LEVEL);

#include "transport.h"


int ptp_transport_raw_open(struct ptp_port *port, )
{
	int sock;

	sock = zsock_socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(sock < 0) {
		LOG_ERR("Failed to open socket on PTP Port %d", port->port_ds.id.port_number);
		return -1;
	}

	if (zsock_setsockopt(sock, )) {

	}

	port->transport.sock = sock;

	return 0;

error:
	zsock_close(sock);
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
