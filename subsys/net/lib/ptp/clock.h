/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file clock.h
 * @brief
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_CLOCK_H_
#define ZEPHYR_INCLUDE_PTP_CLOCK_H_

#include "ds.h"
#include "port.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief PTP Clock structure.
 */
struct ptp_clock {
	enum ptp_clock_type	type;
	struct ptp_default_ds	default_ds;
	struct ptp_current_ds	current_ds;
	struct ptp_parent_ds	parent_ds;
	struct ptp_time_prop_ds time_prop_ds;
	struct ptp_dataset	dataset;
	bool			state_decision_event;
	struct ptp_foreign_master_clock *best;
	struct ptp_port		ports[CONFIG_PTP_NUM_PORTS];
};

/**
 * @brief
 */
struct ptp_foreign_master_clock {
	struct ptp_port_id      port_id;
	uint16_t	        messages_count;
	struct ptp_announce_msg recent_msg;
	struct ptp_dataset      dataset;
	struct ptp_port         *port;
};

/**
 * @brief Types of PTP Clocks
 */
enum ptp_clock_type {
	PTP_CLOCK_TYPE_ORDINARY,
	PTP_CLOCK_TYPE_BOUNDARY,
	PTP_CLOCK_TYPE_P2P,
	PTP_CLOCK_TYPE_E2E,
	PTP_CLOCK_TYPE_MANAGEMENT,
};

/**
 * @brief
 */
struct ptp_clock *ptp_clock_init(enum ptp_clock_type type, struct ptp_config *config);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_CLOCK_H_ */
