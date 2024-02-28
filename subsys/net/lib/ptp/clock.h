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
	struct device			*phc;
	struct ptp_default_ds		default_ds;
	struct ptp_current_ds		current_ds;
	struct ptp_parent_ds		parent_ds;
	struct ptp_time_prop_ds		time_prop_ds;
	struct ptp_dataset		dataset;
	bool				state_decision_event;
	struct ptp_foreign_master_clock *best;
	sys_slist_t			subs_list;
	sys_slist_t			ports_list;
	enum ptp_time_src		time_src;
};

/**
 * @brief
 */
struct ptp_foreign_master_clock {
	sys_snode_t		node;
	struct ptp_port_id	port_id;
	uint16_t		messages_count;
	struct ptp_announce_msg recent_msg;
	struct ptp_dataset	dataset;
	struct ptp_port		*port;
};

/**
 * @brief Types of PTP Clocks.
 */
enum ptp_clock_type {
	PTP_CLOCK_TYPE_ORDINARY,
	PTP_CLOCK_TYPE_BOUNDARY,
	PTP_CLOCK_TYPE_P2P,
	PTP_CLOCK_TYPE_E2E,
	PTP_CLOCK_TYPE_MANAGEMENT,
};

/**
 * @brief PTP Clock time source.
 */
enum ptp_time_src {
	PTP_TIME_SRC_ATOMIC_CLK = 0x10,
	PTP_TIME_SRC_GNSS = 0x20,
	PTP_TIME_SRC_TERRESTRIAL_RADIO = 0x30,
	PTP_TIME_SRC_SERIAL_TIME_CODE = 0x39,
	PTP_TIME_SRC_PTP = 0x40,
	PTP_TIME_SRC_NTP = 0x50,
	PTP_TIME_SRC_HAND_SET = 0x60,
	PTP_TIME_SRC_OTHER = 0x90,
	PTP_TIME_SRC_INTERNAL_OSC = 0xA0,
};

/**
 * @brief Function returning @ref ptp_clock_id variable as a string.
 *
 * @return Pointer to the string.
 */
char *ptp_clock_sprint_clk_id();

/**
 * @brief Function updating Data Set storing Grandmaster information with the clock information.
 *
 * @note Based on Table 30 from section 9.3.5 of the IEEE 1588 - Updates for state decision
 * code M1 and M2.
 *
 * @param[in] clock Pointer to the PTP Clock structure.
 */
void ptp_clock_update_grandmaster(struct ptp_clock *clock);

/**
 * @brief
 *
 * @note Based on Table 33 from section 9.3.5 of the IEEE 1588 - Updates for state decision code S1.
 *
 * @param[in] clock Pointer to the PTP Clock structure.
 */
void ptp_clock_update_slave(struct ptp_clock *clock);

/**
 * @brief
 */
struct ptp_clock *ptp_clock_init();

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_CLOCK_H_ */
