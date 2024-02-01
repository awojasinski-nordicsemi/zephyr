/*
 * Copyright (c) 2024 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Derived data types.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_DDT_H_
#define ZEPHYR_INCLUDE_PTP_DDT_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 5.3 Derived data type */

/* 5.3.2 - time interval expressed in nanoseconds multiplied by 2^16 */
typedef int64_t ptp_timeinterval;

/* 5.3.3 - timestamp with respect to epoch */
struct ptp_timestamp {
	/** Seconds encoded on 48 bits. */
	union {
		struct {
#ifdef CONFIG_LITTLE_ENDIAN
			uint32_t low;
			uint16_t high;
			uint16_t unused;
#else
			uint16_t unused;
			uint16_t high;
			uint32_t low;
#endif
		} _sec;
		uint64_t second;
	};

	/** Nanoseconds. */
	uint32_t nanosecond;
};

/* 5.3.4 - identifies unique entities within a PTP network */
typedef uint8_t ptp_clk_identity[8];

/* 5.3.5 - identifies a PTP port or a Link port */
struct ptp_port_identity {
	ptp_clk_identity clk_identity;
	uint16_t port_number;
};

/* 5.3.6 - represents the protocol address of a PTP port */
struct ptp_port_addr {
	uint16_t protocol; /* 2 bytes enum */
	uint16_t addr_len; /* range from 1-16 */
	uint8_t  address[0];
};

/* 5.3.7 - quality of a clock */
struct ptp_clk_quality {
	uint8_t  clk_class;
	uint8_t clk_accuracy; /* byte enum */
	uint16_t offset_scaled_log_variance;
};

/* 5.3.8 - TLV (type, length, value) extension fields */
struct ptp_tlv {
	uint16_t type; /* 2 bytes enum */
	uint16_t length;
	uint8_t value[0];
};

/* 5.3.9 - holds textual content in PTP messages */
struct ptp_text {
	uint8_t lenght; /* might be larger than number of symbols due to UTF-8 encoding */
	uint8_t text[0]; /* encoded as UTF-8, single symbol can be 1-4 bytes long */
};

/* 5.3.10 - fault log datatype */
struct ptp_fault_record {
	uint16_t length;
	struct ptp_timestamp time;
	uint8_t code; /* byte enum */
	struct ptp_text name;
	struct ptp_text value;
	struct ptp_text desc;
};

/* 5.3.11 - relative difference between two numeric values.
 * It's a dimensionless frcation and multiplied by 2^62. */
typedef int64_t ptp_relative_diff;

/* 5.3.12 - list communication modes in which a PTP port can operate */
struct ptp_comm_modes {
	bool multicast;
	bool unicast;
	bool unicast_negotiation;
	bool unicast_negotiation_req;
};

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_PDT_H_ */
