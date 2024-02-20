/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file port.h
 * @brief Primitive PTP data types.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_PORT_H_
#define ZEPHYR_INCLUDE_PTP_PORT_H_

#include <zephyr/net/net_core.h>

#include "msg.h"
#include "state_machine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure describing PTP Port.
 */
struct ptp_port {
	struct ptp_clock	        *clock;
	struct ptp_port_ds	        port_ds;
	struct net_if		        *iface;
	enum ptp_port_state		(*state_machine)(struct ptp_port *port,
							 enum ptp_port_event event,
							 bool master_diff);
	struct ptp_foreign_master_clock *best;
	struct ptp_foreign_master_clock foreigns[CONFIG_PTP_FOREIGN_MASTER_LIST_SIZE];
};

/**
 * @brief Function initializing PTP Port.
 *
 * @param[in] iface Pointer to current network interface.
 * @param[in] user_data Pointer to @ref ptp_clock structure.
*/
void ptp_port_open(struct net_if *iface, void *user_data);

/**
 * @brief Function returning PTP Port's current state.
 *
 * @param[in] port Pointer to the PTP Port structure.
 *
 * @return Current state of the PTP Port.
 */
enum ptp_port_state ptp_port_state(struct ptp_port *port);

/**
 * @brief Function chcecking whether PTP Port is enabled.
 *
 * @param[in] port Pointer to the PTP Port structure.
 *
 * @return True if PTP Port is enabled, False otherwise.
 */
bool ptp_port_enabled(struct ptp_port *port);

/**
 * @brief Function checking if two port identities are equal.
 *
 * @param[in] p1 Pointer to the port identity structure.
 * @param[in] p2 Pointer to the port identity structure.
 *
 * @return True if port identities are equal, False otherwise.
 */
bool ptp_port_id_eq(const struct ptp_port_id *p1, const struct ptp_port_id *p2);

/**
 * @brief Function generating PTP Port events based on PTP Port activity.
 *
 * @param[in] port Pointer to the PTP Port structure.
 *
 * @return PTP Port event.
 */
enum ptp_port_event ptp_port_event_gen(struct ptp_port *port);

/**
 * @brief Function handling PTP Port event.
 *
 * @param[in] port	  Pointer to the PTP Port structure.
 * @param[in] event	  PTP Port Event to be processed.
 * @param[in] master_diff Flag indicating whether PTP Master has changed.
 */
void ptp_port_event_handle(struct ptp_port *port, enum ptp_port_event event, bool master_diff);

/**
 * @brief Function updating PTP Port state based on given event.
 *
 * @param[in] port	  Pointer to the PTP Port structure.
 * @param[in] event	  PTP Port Event to be processed.
 * @param[in] master_diff Flag indicating whether PTP Master has changed.
 *
 * @return 1 if PTP Port state has changed, 0 otherwise.
 */
int ptp_port_state_update(struct ptp_port *port, enum ptp_port_event event, bool master_diff);

/**
 * @brief Function updating current PTP Master Clock of the PTP Port based on specified message.
 *
 * @param[in] port Pointer to the PTP Port.
 * @param[in] msg  Pointer to the announce message containg PTP Master data.
 *
 * @return Non-zero if the announce message is different than the last.
 */
int ptp_port_add_foreign_master(struct ptp_port *port, struct ptp_msg *msg);

/**
 * @brief Function updating current PTP Master Clock of the PTP Port based on specified message.
 *
 * @param[in] port Pointer to the PTP Port.
 * @param[in] msg  Pointer to the announce message containg PTP Master data.
 *
 * @return Non-zero if the announce message is different than the last.
 */
int ptp_port_update_current_master(struct ptp_port *port, struct ptp_msg *msg);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_PORT_H_ */
