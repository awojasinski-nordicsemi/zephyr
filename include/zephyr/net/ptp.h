/*
 * Copyright (c) 2024 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public functions for the Precision Time Protocol.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_NET_PTP_H_
#define ZEPHYR_INCLUDE_NET_PTP_H_

#include <zephyr/net/net_core.h>
#include <zephyr/net/ptp_time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version definition for IEEE 1588-2019 */
#define PTP_MAJOR_VERSION 2
#define PTP_MINOR_VERSION 1
#define PTP_VERSION	  (PTP_MINOR_VERSION << 4 | PTP_MAJOR_VERSION)



enum ptp_time_src {
	PTP_TIME_SRC_ATOMIC_CLK = 0x10,
	PTP_TIME_SRC_GNSS = 0x20,
	PTP_TIME_SRC_TERRESTRIAL_RADIO = 0x30,
	PTP_TIME_SRC_SERIAL_TIME_CODE = 0x39,
	PTP_TIME_SRC_PTP = 0x40,
	PTP_TIME_SRC_NTP = 0x50
	PTP_TIME_SRC_HAND_SET = 0x60,
	PTP_TIME_SRC_OTHER = 0x90,
	PTP_TIME_SRC_INTERNAL_OSC = 0xA0,
};




#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_NET_PTP_H_ */
