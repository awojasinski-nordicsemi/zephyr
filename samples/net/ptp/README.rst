.. zephyr:code-sample:: ptp
   :name: PTP
   :relevant-api: ptp ptp_time

   Enable PTP support and monitor functionality using net-shell.

Overview
********

The PTP sample application for Zephyr will enable PTP support.
The net-shell is also enabled so that user can monitor PTP functionality.

The source code for this sample application can be found at:
:zephyr_file:`samples/net/ptp`.

Requirements
************

For generic host connectivity, that can be used for debugging purposes, see
:ref:`networking_with_native_sim` for details.

Building and Running
********************

A good way to run this sample is to run this PTP application inside
native_sim board as described in :ref:`networking_with_native_sim` or with
embedded device like Nucleo-H743-ZI, Nucleo-H745ZI-Q, or Nucleo-H563ZI.
Note that PTP is only supported for boards that have an Ethernet port and
which has support for collecting timestamps for sent and received Ethernet frames.

Follow these steps to build the PTP sample application:

.. zephyr-app-commands::
   :zephyr-app: samples/net/ptp
   :board: <board to use>
   :goals: build
   :compact:

The net-shell command "**net ptp**" will print out general PTP information.
For port 1, the command "**net ptp 1**" will print detailed information about
port 1 statistics etc. Note that executing the shell command could affect
the timing of the sent or received PTP packets and the grandmaster might
mark the device as non AS capable and disable it.

Setting up Linux Host
=====================

If you need VLAN support in your network, then the
:zephyr_file:`samples/net/vlan/vlan-setup-linux.sh` provides a script that can be
executed on the Linux host. It creates two VLANs on the Linux host and creates
routes to Zephyr. If you are using native_sim board, then
the ``net-setup.sh`` will create VLAN setup automatically with this command:

.. code-block:: console

   ./net-setup.sh -c zeth-vlan.conf

For native_sim board, use ``linuxptp`` project as that supports
software timestamping.

Get linuxptp project sources

.. code-block:: console

    git clone git://git.code.sf.net/p/linuxptp/code

Compile the ``ptp4l`` daemon and start it like this:

.. code-block:: console

    sudo ./ptp4l -2 -f PTP-zephyr.cfg -i zeth -m -q -l 6 -S

Use the ``default.cfg`` as a base, copy it to ``PTP-zephyr.cfg``, and modify
it according to your needs.

Multiport Setup
===============

If you set :kconfig:option:`CONFIG_NET_PTP_NUM_PORTS` larger than 1, then PTP sample
will create multiple PTP Ports. This configuration is currently only supported
in native_sim board.

You need to enable the ports in the net-tools. If the number of ports is set
to 2, then give following commands to create the network interfaces in host
side:

.. code-block:: console

    sudo ./net-setup.sh -c zeth0-ptp.conf -i zeth0 start
    sudo ./net-setup.sh -c zeth1-ptp.conf -i zeth1 start

After that you can start ptp4l daemon for both interfaces. Please use two
terminals when starting ptp4l daemon.

.. code-block:: console

    cd <ptp4l directory>
    sudo ./ptp4l -2 -f PTP-zephyr.cfg -m -q -l 6 -S -i zeth0
    sudo ./ptp4l -2 -f PTP-zephyr.cfg -m -q -l 6 -S -i zeth1

Compile Zephyr application.

.. zephyr-app-commands::
   :zephyr-app: samples/net/gptp
   :board: native_sim
   :goals: build
   :compact:

When the Zephyr image is build, you can start it like this:

.. code-block:: console

    build/zephyr/zephyr.exe -attach_uart
