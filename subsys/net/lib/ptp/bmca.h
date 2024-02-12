/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file bmca.c
 * @brief Interface for Best Master Clock Algorithm.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_BMCA_H_
#define ZEPHYR_INCLUDE_PTP_BMCA_H_

#include "ds.h"
#include "port.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function comparing two PTP Port Identities.
 *
 * @param[in] p1 Pointer to the first PTP Port Identity
 * @param[in] p2 Pointer to the second PTP Port Identity
 *
 * @return
 */
int ptp_bmca_port_id_cmp(const struct ptp_port_id *p1, const struct ptp_port_id *p2);

/**
 * @brief Function comparing two datasets.
 *
 * @param[in] a Pointer to the first dataset.
 * @param[in] b Pointer to the second dataset.
 *
 * @return negative if b is better than a, 0 if a == b, else positive
 */
int ptp_bmca_ds_cmp(const struct ptp_dataset *a, const struct ptp_dataset *b);

/**
 * @brief Function performing Best Master Clock state decission algorithm.
 *
 * @param[in] port Pointer to a PTP Port.
 *
 * @return
 */
enum ptp_port_state ptp_bmca_state_decision(struct ptp_port *port);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_BCMA_H_ */
