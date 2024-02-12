/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file tc_clock.h
 * @brief PTP Transparent Clock logic
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_CLOCK_H_
#define ZEPHYR_INCLUDE_PTP_CLOCK_H_

#include "port.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function forwarding general message to all other ports.
 *
 * @param[in] port Pointer to the PTP Port structure of incomming message.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Zero on success or (negative) error code on failure.
 */
int ptp_tc_clock_fwd(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function forwarding Follow Up message to all other ports.
 *
 * @param[in] port Pointer to the PTP Port structure of incomming message.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Zero on success or (negative) error code on failure.
 */
int ptp_tc_clock_fwd_follow_up(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function forwarding Request message to all other ports.
 *
 * @param[in] port Pointer to the PTP Port structure of incomming message.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Zero on success or (negative) error code on failure.
 */
int ptp_tc_clock_fwd_req(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function forwarding Response message to all other ports.
 *
 * @param[in] port Pointer to the PTP Port structure of incomming message.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Zero on success or (negative) error code on failure.
 */
int ptp_tc_clock_fwd_resp(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function forwarding Sync message to all other ports.
 *
 * @param[in] port Pointer to the PTP Port structure of incomming message.
 * @param[in] msg  Pointer to the received PTP message.
 *
 * @return Zero on success or (negative) error code on failure.
 */
int ptp_tc_clock_fw_sync(struct ptp_port *port, struct ptp_msg *msg);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_CLOCK_H_ */
