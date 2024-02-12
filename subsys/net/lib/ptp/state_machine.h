/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file state_machine.h
 * @brief Function and data structures used for state machine of the PTP Port.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_STATE_MACHINE_H_
#define ZEPHYR_INCLUDE_PTP_STATE_MACHINE_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration of PTP Port States.
 */
enum ptp_port_state {
	PTP_PS_INITIALIZING = 1,
	PTP_PS_FAULTY,
	PTP_PS_DISABLED,
	PTP_PS_LISTENING,
	PTP_PS_PRE_MASTER,
	PTP_PS_MASTER,
	PTP_PS_GRAND_MASTER,
	PTP_PS_PASSIVE,
	PTP_PS_UNCALIBRATED,
	PTP_PS_SLAVE,
};

/**
 * @brief Enumeration of PTP events.
 */
enum ptp_port_event {
	PTP_EVT_NONE,
	PTP_EVT_POWERUP,
	PTP_EVT_INITIALIZE,
	PTP_EVT_INIT_COMPLETE,
	PTP_EVT_FAULT_DETECTED,
	PTP_EVT_FAULT_CLEARED,
	PTP_EVT_STATE_DECISION,
	PTP_EVT_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES,
	PTP_EVT_QUALIFICATION_TIMEOUT_EXPIRES,
	PTP_EVT_DESIGNATED_ENABLED,
	PTP_EVT_DESIGNATED_DISABLED,
	PTP_EVT_MASTER_CLOCK_SELECTED,
	PTP_EVT_SYNCHRONIZATION_FAULT,
	PTP_EVT_RS_MASTER,
	PTP_EVT_RS_SLAVE,
	PTP_EVT_RS_PASSIVE,
};

/** @brief Finite State Machine for PTP Port.
 *
 * @param[in] state	  A current state of the Port
 * @param[in] event 	  An event that occured for the port
 * @param[in] master_diff
 *
 * @return A new PTP Port state
*/
enum ptp_port_state ptp_state_machine(enum ptp_port_state state,
				      enum ptp_port_event event,
				      bool master_diff);

/** @brief Finite State Machine for PTP Port that is configured as Slave-Only instance.
 *
 * @param[in] state	  A current state of the Port
 * @param[in] event 	  An event that occured for the port
 * @param[in] master_diff
 *
 * @return A new PTP Port state
*/
enum ptp_port_state ptp_so_state_machine(enum ptp_port_state state,
					 enum ptp_port_event event,
					 bool master_diff);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_STATE_MACHINE_H_ */
