
zephyr_library()

zephyr_library_include_directories(. ${ZEPHYR_BASE}/subsys/net/ip)

zephyr_library_sources(
  bmca.c
  clock.c
  msg.c
  port.c
  ptp.c
  state_machine.c
  tc_clock.c
  transport.c
)

zephyr_library_sources_ifdef(CONFIG_PTP_IEEE_802_3_PROTOCOL
  transport_raw.c
)

zephyr_library_sources_ifdef(CONFIG_PTP_UDP_IPv4_PROTOCOL
  transport_udp.c
)

zephyr_library_sources_ifdef(CONFIG_PTP_UDP_IPv6_PROTOCOL
  transport_udp6.c
)
