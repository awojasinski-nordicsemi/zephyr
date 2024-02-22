/*
 * Copyright (c) 2024
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file ds.h
 * @brief Datasets types.
 *
 * References are to version 2019 of IEEE 1588, ("PTP")
 */

#ifndef ZEPHYR_INCLUDE_PTP_DS_H_
#define ZEPHYR_INCLUDE_PTP_DS_H_

#include "ddt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief PTP Default Dataset.
 * @note 8.2.1 - defaultDS data set member specification
 */
struct ptp_default_ds {
	/* static */
	ptp_clk_id	       clk_id;
	uint16_t	       n_ports;
	/* dynamic */
	struct ptp_clk_quality clk_quality;
	uint8_t		       priority1;
	uint8_t		       priority2;
	uint8_t		       domain;
	uint16_t	       sdo_id: 12;
	bool		       slave_only;
	/* optional */
	struct ptp_timestamp   current_time;
	bool		       enable;
	bool		       external_port_conf_en;
	uint8_t		       max_steps_rm;
	enum ptp_clock_type    type;
};

/**
 * @brief PTP Current Dataset.
 * @note 8.2.2 - currentDS data set member specification
 */
struct ptp_current_ds {
	uint16_t	 steps_rm;
	ptp_timeinterval offset_from_master;
	ptp_timeinterval mean_delay;
	/* optional */
	bool		 sync_uncertain;
};

/**
 * @brief PTP Parent Dataset.
 * @note 8.2.3 - parentDS data set member specification
 */
struct ptp_parent_ds {
	struct ptp_port_id     port_id;
	bool		       stats;
	uint16_t	       obsreved_parent_offset_scaled_log_variance;
	int32_t		       obsreved_parent_clk_phase_change_rate;
	ptp_clk_id	       gm_id;
	struct ptp_clk_quality gm_clk_quality;
	uint8_t		       gm_priority1;
	uint8_t		       gm_priotity2;
	struct ptp_port_addr   protocol_addr;
	bool		       sync_uncertain;
};

/**
 * @brief PTP Time Properties Dataset.
 * @note 8.2.4 - timePropertiesDS data set member specification
 */
struct ptp_time_prop_ds {
	int16_t		  current_utc_offset;
	bool		  current_utc_offset_valid;
	bool		  leap59;
	bool		  leap61;
	bool		  time_traceable;
	bool		  freq_traceable;
	bool		  ptp_timescale;
	enum ptp_time_src time_src;
};

/**
 * @brief PTP Description Dataset.
 * @note 8.2.5 - descriptionDS
 */
struct ptp_desc_ds {
	union manufacturer_id {
		struct {
			uint8_t byte[3];
		};
		uint32_t id: 24;
	};
	struct ptp_text product_desc;
	struct ptp_text product_rev;
	struct ptp_text usr_desc;
};

/**
 * @brief PTP Fault Log Dataset.
 * @note 8.2.6 - faultLogDS
 */
struct ptp_fault_log_ds {
	uint16_t no_foult_records;
	fault_record_list; /* single-linked list of struct ptp_fault_record */
	bool reset;
};

/**
 * @brief PTP Non-volatile Storage Dataset.
 * @note 8.2.7 - nonvolatileStorageDS
 */
struct ptp_nvs_ds {
	bool reset;
	bool save;
};

/* optional path trace mechanism */
struct ptp_path_trace_ds {
	ptp_clk_id list[0];
	bool	   enable;
};

/* optional alternate timescale offsets mechanism. */
struct ptp_alt_timescale_offset_ds {
	uint8_t max_key;
	list; /* single-lindek list of ptp_alt_timescale entries */
};

/* optional holdover upgrade mechanism */
struct ptp_holdover_upgrade_ds {
	bool enable;
};

/* optional grandmaster cluster mechanism */
struct ptp_gm_cluster_ds {
	uint8_t		     max_tab_size;
	int8_t		     log_query_interval;
	uint8_t		     tab_size;
	struct ptp_port_addr port_addr[0];
};

/* optional acceptable master table mechanism */
struct ptp_acceptable_master_tab_ds {
	uint16_t max_tab_size;
	uint16_t tab_size;
	list; /* list of ptp_acceptable_master elements */
};

/* optionl performance monitoring feature */
struct ptp_perf_monitor_ds {
	bool enable;
	record_list /* 99 records of type ptp_clk_perf_monitor_record */
};

/* optional enhanced synchronization accuracy metrics feature */
struct ptp_enhandec_sync_accuracy_metrics_ds {
	bool enable;
};

/**
 * @brief PTP Port Dataset
 * @note 8.2.15 - portDS data set member specification
 */
struct ptp_port_ds {
	/* static */
	struct ptp_port_id	 id;
	/* dynamic */
	enum ptp_port_state	 state;
	int8_t			 log_min_delay_req_interval;
	ptp_timeinterval	 mean_link_delay;
	/* configurable */
	int8_t			 log_announce_interval;
	uint8_t			 announce_receipt_timeout;
	int8_t			 log_sync_interval;
	enum ptp_delay_mechanism dalay_mechanism;
	int8_t			 log_min_pdelay_req_interval;
	uint8_t			 version;
	ptp_timeinterval	 delay_asymmetry;
	/* optional */
	bool			 enable;
	bool			 master_only;
};

/* optional timestamp correction port feature */
struct ptp_timestamp_correction_port_ds {
	ptp_timeinterval egress_latency;
	ptp_timeinterval ingress_latency;
};

/* optional asymmetry correction port feature */
struct ptp_x_ds {
	ptp_timeinterval  const_asymmetry;
	ptp_relative_diff scaled_delay_coef;
	bool		  enable;
};

/**
 * @brief PTP Description Port Dataset.
 * @note 8.2.18 - descriptionPortDS
 */
struct ptp_dest_port_ds {
	union profile_id {
		struct {
			uint8_t byte[6];
		};
		uint64_t id: 48;
	};
	struct ptp_port_addr protocol_addr;
};

/**
 * @brief
 * @note 8.2.19 - unicastNegotiationPortDS
 */
struct ptp_unicast_negotiaion_port_ds {
	bool enable;
};

/**
 * @brief Generic Data set type used for dataset comparison algorithm.
 */
struct ptp_dataset {
	uint8_t		       priority1;
	ptp_clk_id	       clk_id;
	struct ptp_clk_quality clk_quality;
	uint8_t		       priority2;
	uint16_t	       steps_rm;
	struct ptp_port_id     sender;
	struct ptp_port_id     receiver;
};

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_PTP_DS_H_ */
