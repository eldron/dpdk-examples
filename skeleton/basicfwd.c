/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

// device driver, allocate hugepages

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	// configure number of receive queues and transmit queues 
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	// configure the number of receive and transmit descriptors
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		// configure each receive queue
		// allocate and setup a receive queue for a device
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		// configure each transmit queue
		// allocate and setup a transmit queue for a device
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */

	// In non-promiscuous mode, when a NIC receives a frame, 
	// it drops it unless the frame is addressed to that NIC's MAC address or is a broadcast or multicast addressed frame.
	// In promiscuous mode, however, the NIC allows all frames through, 
	// thus allowing the computer to read frames intended for other machines or network devices. 
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			// port_id, queue_id on the device, bufs, max number of packets
			// return the number of packets received
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			// do something with the received packets
			// display packet mac, ip, port
			printf("received %u packets from port %u\n", nb_rx, port);
			uint16_t i;
			for(i = 0;i < nb_rx;i++){
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *)/* A macro that points to the start of the data in the mbuf.*/);
				struct ether_hdr * eth = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
				printf("DST MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					eth->d_addr.addr_bytes[0], eth->d_addr.addr_bytes[1],
					eth->d_addr.addr_bytes[2], eth->d_addr.addr_bytes[3],
					eth->d_addr.addr_bytes[4], eth->d_addr.addr_bytes[5]);
				printf("SRC MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					eth->s_addr.addr_bytes[0], eth->s_addr.addr_bytes[1],
					eth->s_addr.addr_bytes[2], eth->s_addr.addr_bytes[3],
					eth->s_addr.addr_bytes[4], eth->s_addr.addr_bytes[5]);
				printf("ether type is %u\n", eth->ether_type);

				/**
				 * A macro that points to an offset into the data in the mbuf.
				 *
				 * The returned pointer is cast to type t. Before using this
				 * function, the user must ensure that the first segment is large
				 * enough to accommodate its data.
				 *
				 * @param m
				 *   The packet mbuf.
				 * @param o
				 *   The offset into the mbuf data.
				 * @param t
				 *   The type to cast the result into.
				 */
				struct ipv4_hdr * ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct ipv4_hdr *, sizeof(struct ether_hdr));
				uint32_t dstip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
				printf("dst ip is: %u %u %u %u\n", (dstip >> 24) & 0xff, (dstip >> 16) & 0xff, (dstip >> 8) & 0xff, dstip & 0xff);
				uint32_t srcip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
				printf("src ip is: %u %u %u %u\n", (srcip >> 24) & 0xff, (srcip >> 16) & 0xff, (srcip >> 8) & 0xff, srcip & 0xff);
				printf("next proto id is %u\n", ipv4_hdr->next_proto_id);
				uint8_t iphdr_len = (ipv4_hdr->version_ihl & 0x0f) * 4;
				printf("ip header length is %u\n", iphdr_len);
				if(ipv4_hdr->next_proto_id == 6){
					struct tcp_hdr * tcphdr = rte_pktmbuf_mtod_offset(bufs[i], struct tcp_hdr *, sizeof(struct ether_hdr) + iphdr_len);
					uint16_t src_port = rte_be_to_cpu_16(tcphdr->src_port);
					uint16_t dst_port = rte_be_to_cpu_16(tcphdr->dst_port);
					printf("tcp src_port is %u, tcp dst_port is %u\n", src_port, dst_port);
				}
			}


			/* Send burst of TX packets, to second port of pair. */
			// port id, queue id on the device, bufs, number of packets to send
			// return the number of packets sent
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					// free a packet mbuf back to its mempool
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	// create a mbuf pool, set the first two parameters, name of the mbuf pool, 
	// and the number of elements in the mbuf pool
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	// macro to iterate over all enabled and ownerless ether device ports
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
