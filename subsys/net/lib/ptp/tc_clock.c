/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_ptp_tc_clock, CONFIG_PTP_LOG_LEVEL);

#include "tc_clock.h"

int ptp_tc_clock_fwd(struct ptp_port *port, struct ptp_msg *msg)
{
	return 0;
}

int ptp_tc_clock_fwd_follow_up(struct ptp_port *port, struct ptp_msg *msg)
{
	return 0;
}

int ptp_tc_clock_fwd_req(struct ptp_port *port, struct ptp_msg *msg)
{
	return 0;
}

int ptp_tc_clock_fwd_resp(struct ptp_port *port, struct ptp_msg *msg)
{
	return 0;
}

int ptp_tc_clock_fw_sync(struct ptp_port *port, struct ptp_msg *msg)
{
	return 0;
}
