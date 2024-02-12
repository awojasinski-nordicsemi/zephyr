/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file dm.h
 * @brief Delay mechanism.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_DM_H_
#define ZEPHYR_INCLUDE_PTP_DM_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration for types of delay mechanisms for PTP Clock.
 */
enum ptp_delay_mechanism {
	PTP_DM_E2E = 1,
	PTP_DM_P2P,
	PTP_DM_COMMON_P2P,
	PTP_DM_SPECIAL,
	PTP_DM_NO_MECHANISM = 0xFE,
};

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_DM_H_ */
