/*
 * Copyright (c) 2024 BayLibre SAS
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

/** @brief Threshold value for accepting PTP Instance for consideration in BMCA */
#define FOREIGN_MASTER_THRESHOLD 2

/** @brief Multiplication factor of message intervals to create time window for announce messages */
#define FOREIGN_MASTER_TIME_WINDOW_MUL 4

/**
 * @brief PTP Clock structure.
 */
struct ptp_clock {
	const struct device		*phc;
	struct ptp_default_ds		default_ds;
	struct ptp_current_ds		current_ds;
	struct ptp_parent_ds		parent_ds;
	struct ptp_time_prop_ds		time_prop_ds;
	struct ptp_dataset		dataset;
	bool				state_decision_event;
	struct ptp_foreign_master_clock *best;
	sys_slist_t			subs_list;
	sys_slist_t			ports_list;
	struct zsock_pollfd		*pollfd;
	bool				pollfd_valid;
	uint8_t				time_src;
};

/**
 * @brief
 */
struct ptp_foreign_master_clock {
	sys_snode_t		node; /* object list */
	struct ptp_port_id	port_id;
	struct k_fifo		messages;
	uint16_t		messages_count; /* received within a FOREIGN_MASTER_TIME_WINDOW. */
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
 * @param[in] clock Pointer to the PTP Clock instance.
 *
 * @return Pointer to the string.
 */
char *ptp_clock_sprint_clk_id(struct ptp_clock *clock);

/**
 * @brief Function checking status of the file descriptors array. The array is updated
 * if has obsolite data.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 */
void ptp_clock_check_pollfd(struct ptp_clock *clock);

/**
 * @brief Function invalidating status of the file descriptors array.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 */
void ptp_clock_pollfd_invalidate(struct ptp_clock *clock);

/**
 * @brief Function resizing file descriptors array holding all sockets related to PTP Ports.
 *
 * @param[in] clock   Pointer to the PTP Clock instance.
 * @param[in] n_ports PTP Ports count.
 *
 * @return returns 0 if succesfull, negative otherwise.
 */
int ptp_clock_realloc_pollfd(struct ptp_clock *clock, int n_ports);

/**
 * @brief Get PTP Port from network interface.
 *
 * @param[in] iface Pointer to the network interface.
 *
 * @return Pointer to the PTP Port binded with given interface. If no PTP Port assigned
 * to the interface NULL is returned.
 */
struct ptp_port *ptp_clock_get_port_from_iface(struct net_if *iface);

/**
 * @brief Function updating Data Set storing Grandmaster information with the clock information.
 *
 * @note Based on Table 30 from section 9.3.5 of the IEEE 1588 - Updates for state decision
 * code M1 and M2.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 */
void ptp_clock_update_grandmaster(struct ptp_clock *clock);

/**
 * @brief
 *
 * @note Based on Table 33 from section 9.3.5 of the IEEE 1588 - Updates for state decision code S1.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 */
void ptp_clock_update_slave(struct ptp_clock *clock);

/**
 * @brief Function for extracting data from default dataset to a structure allowing to compare
 * common across all datasets data.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 *
 * @return Pointer to the ptp_dataset containging data from ptp_default_ds structure
 */
struct ptp_dataset *ptp_clock_default_ds(struct ptp_clock *clock);

/**
 * @brief Function for getting a common dataset for the clock's best foreign master clock.
 *
 * @param[in] clock Pointer to the PTP Clock instance.
 *
 * @return NULL if the clock doesn't have best foreign master clock of pointer to the ptp_dataset
 * of the best foreign master clock.
 */
struct ptp_dataset *ptp_clock_best_foreign_ds(struct ptp_clock *clock);

/**
 * @brief Function initializing PTP Clock instance.
 *
 * @return Pointer to the structure representing PTP Clock instance.
 */
struct ptp_clock *ptp_clock_init(void);

/**
 * @brief Function checking if given PTP Clock IDs are the same.
 *
 * @param[in] c1 Pointer to the PTP Clock ID.
 * @param[in] c2 Pointer to the PTP Clock ID.
 *
 * @return True if the same, false otherwise.
 */
bool ptp_clock_id_eq(ptp_clk_id *c1, ptp_clk_id *c2);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_CLOCK_H_ */
