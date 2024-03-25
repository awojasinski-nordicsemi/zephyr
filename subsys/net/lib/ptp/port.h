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

#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>

#include "ds.h"
#include "msg.h"
#include "state_machine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure describing PTP Port.
 */
struct ptp_port {
	sys_snode_t			node; /* object list */
	struct ptp_clock		*clock;
	struct ptp_port_ds		port_ds;
	struct net_if			*iface;
	int				socket;
	struct k_timer			announce_timer;
	struct k_timer			delay_timer;
	struct k_timer			sync_rx_timer;
	struct k_timer			sync_tx_timer;
	struct k_timer			qualification_timer;
	bool				announce_t_expierd;
	bool				delay_t_expierd;
	bool				sync_rx_t_expierd;
	bool				sync_tx_t_expierd;
	bool				qualification_t_expierd;
	struct {
		uint16_t		announce;
		uint16_t		delay;
		uint16_t		signaling;
		uint16_t		sync;
	}				seq_id;
	enum ptp_port_state		(*state_machine)(enum ptp_port_state state,
							 enum ptp_port_event event,
							 bool master_diff);
	struct ptp_foreign_master_clock *best;
	sys_slist_t			foreign_list;
	struct net_pkt			*last_sync_fup;
	net_if_timestamp_callback_t	sync_ts_cb;
	net_if_timestamp_callback_t	pdelay_resp_ts_cb;
	bool				sync_ts_cb_registered;
	bool				pdelay_resp_ts_cb_registered;
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
 * @brief Function comparing port identities.
 *
 * @param[in] p1 Pointer to the port identity structure.
 * @param[in] p2 Pointer to the port identity structure.
 *
 * @return 0 if identities are the same, positive if they are from the same PTP Instance,
 * negative otherwise.
 */
int ptp_port_id_cmp(const struct ptp_port_id *p1, const struct ptp_port_id *p2);

/**
 * @brief Function for getting a common dataset for the port's best foreign master clock.
 *
 * @param[in] port Pointer to the PTP Port structure.
 *
 * @return NULL if the port doesn't have best foreign master clock of pointer to the ptp_dataset
 * of the best foreign master clock.
 */
struct ptp_dataset *ptp_port_best_foreign_ds(struct ptp_port *port);

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
