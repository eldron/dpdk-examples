/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

// allocate mbuf pool
// initialize ports
// allocate lcores

#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_prefetch.h>
#include <rte_distributor.h>
#include <rte_pause.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS ((64*1024)-1)
#define MBUF_CACHE_SIZE 128
#define BURST_SIZE 64
#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 65536
#define BURST_SIZE_TX 32

#define RTE_LOGTYPE_DISTRAPP RTE_LOGTYPE_USER1

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// maximum number of lcores
#define MAX_NUM_LCORES 32
// maximum number of middleboxes per flow, each middlebox is identified by a uint64_t 
#define MAX_MIDDLEBOXES_PER_FLOW 10

// the middlebox deployment platform's IP address
// 202.197.15.66
unsigned platform_ip = 0xCAC50F42;

struct middlebox_chain_configure {
	// flow information
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;

	uint8_t number_of_middleboxces;
	// middlebox chain specification
	uint64_t middleboxes[MAX_MIDDLEBOXES_PER_FLOW];// each middlebox is identified by an id
};

struct middlebox_service;

/*
	middlebox manufacturers implement the following 4 functions
*/
typedef int middlebox_service_id_function();

// initialize the middlebox service structure
// use rte_malloc() to allocate memory for private data
// return 1 if succeed, 0 failed
typedef int middlebox_service_init_function(struct middlebox_service * ms);

// return 0: drop packet, if 1: forward to the next middlebox service
typedef int middlebox_service_handle_packet_function(struct middlebox_service * ms, struct rte_mbuf * m);

// free middlebox allocated resource 
// use rte_free to free memory of private data
// return 1 if succeeded, 0 if failed
typedef int middlebox_service_free_resource_function(struct middlebox_service * ms);

struct middlebox_service {
	// the middlebox can store additional private data 
	void * private_data;
	uint64_t id;// the middlebox id

	middlebox_service_id_function * middlebox_id;
	middlebox_service_init_function * init_middlebox;
	middlebox_service_handle_packet_function * handle_packet;
	middlebox_service_free_resource_function * free_resource;
};

struct middlebox_service_chain {
	uint8_t number_of_middleboxces;
	struct middlebox_service middleboxes[MAX_MIDDLEBOXES_PER_FLOW];
};

struct middlebox_service_functions {
	middlebox_service_id_function * middlebox_id;
	middlebox_service_init_function * init_middlebox;
	middlebox_service_handle_packet_function * handle_packet;
	middlebox_service_free_resource_function * free_resource;
};

// initialized at system initialization
// used by worker lcores to dynamically create middlebox service instance at run time
struct rte_hash * middlebox_service_functions_table;

// implementation of a dummy middlebox
int dummy_middlebox_id(){
	return 0;
}

int dummy_middlebox_init(struct middlebox_service * ms){
	ms->private_data = NULL;
	ms->id = 0;
	return 1;
}

int dummy_middlebox_handle_pkt(struct middlebox_service * ms, struct rte_mbuf * m){
	return 1;
}

int dummy_middlebox_free(struct middlebox_service * ms){
	return 1;
}

struct rte_mempool * mcconfig_pool;

// add manufacturers' middlebox implementation to this array
// during system initialization, add the middleboxes to middlebox service functions table for fast access
struct middlebox_service_functions ms_functions[] = {
	{	
		.middlebox_id = dummy_middlebox_id,
		.init_middlebox = dummy_middlebox_init,
		.handle_packet = dummy_middlebox_handle_pkt,
		.free_resource = dummy_middlebox_free
	}

	// other middleboxes
};

/* mask of enabled ports */
static uint32_t enabled_port_mask;
volatile uint8_t quit_signal;
volatile uint8_t quit_signal_rx;
volatile uint8_t quit_signal_dist;
volatile uint8_t quit_signal_work;

static volatile struct app_stats {
	struct {
		uint64_t rx_pkts;
		uint64_t returned_pkts;
		uint64_t enqueued_pkts;
		uint64_t enqdrop_pkts;
	} rx __rte_cache_aligned;
	int pad1 __rte_cache_aligned;

	struct {
		uint64_t in_pkts;
		uint64_t ret_pkts;
		uint64_t sent_pkts;
		uint64_t enqdrop_pkts;
	} dist __rte_cache_aligned;
	int pad2 __rte_cache_aligned;

	struct {
		uint64_t dequeue_pkts;
		uint64_t tx_pkts;
		uint64_t enqdrop_pkts;
	} tx __rte_cache_aligned;
	int pad3 __rte_cache_aligned;

	uint64_t worker_pkts[64] __rte_cache_aligned;

	int pad4 __rte_cache_aligned;

	uint64_t worker_bursts[64][8] __rte_cache_aligned;

	int pad5 __rte_cache_aligned;

	uint64_t port_rx_pkts[64] __rte_cache_aligned;
	uint64_t port_tx_pkts[64] __rte_cache_aligned;
} app_stats;

struct app_stats prev_app_stats;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
				ETH_RSS_TCP | ETH_RSS_SCTP,
		}
	},
};

struct output_buffer {
	unsigned count;
	struct rte_mbuf *mbufs[BURST_SIZE];
};

static void print_stats(void);

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
// configure the number of receive and transmit queues on each port
// configure descriptors on each receive and transmit queue
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rxRings = 1, txRings = 1;
	int retval;
	uint16_t q;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	port_conf.rx_adv_conf.rss_conf.rss_hf &=
		dev_info.flow_type_rss_offloads;

	printf("dev_info.flow_type_rss_offloads = %lu\n", dev_info.flow_type_rss_offloads);

	if (port_conf.rx_adv_conf.rss_conf.rss_hf !=
			port_conf_default.rx_adv_conf.rss_conf.rss_hf) {
		printf("Port %u modified RSS hash function based on hardware support,"
			"requested:%#"PRIx64" configured:%#"PRIx64"\n",
			port,
			port_conf_default.rx_adv_conf.rss_conf.rss_hf,
			port_conf.rx_adv_conf.rss_conf.rss_hf);
	}

	retval = rte_eth_dev_configure(port, rxRings, txRings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rxRings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
						rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < txRings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
						rte_eth_dev_socket_id(port),
						&txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_eth_link link;
	rte_eth_link_get_nowait(port, &link);
	while (!link.link_status) {
		printf("Waiting for Link up on port %"PRIu16"\n", port);
		sleep(1);
		rte_eth_link_get_nowait(port, &link);
	}

	if (!link.link_status) {
		printf("Link down on port %"PRIu16"\n", port);
		return 0;
	}

	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);

	return 0;
}

struct lcore_params {
	unsigned worker_id;
	struct rte_distributor *d;
	struct rte_ring *rx_dist_ring;
	struct rte_ring *dist_tx_ring;
	struct rte_mempool *mem_pool;
	struct rte_ring ** worker_rings; // indexed by the worker lcore id
};

static int
lcore_rx(struct lcore_params *p)
{
	const uint16_t nb_ports = rte_eth_dev_count_avail();
	const int socket_id = rte_socket_id();
	uint16_t port;
	struct rte_mbuf *bufs[BURST_SIZE*2];
	//struct middlebox_chain_configure * 

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"RX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet RX.\n", rte_lcore_id());
	port = 0;
	while (!quit_signal_rx) {

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs,
				BURST_SIZE);
		if (unlikely(nb_rx == 0)) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}
		app_stats.rx.rx_pkts += nb_rx;

/*
 * You can run the distributor on the rx core with this code. Returned
 * packets are then send straight to the tx core.
 */
#if 0
	rte_distributor_process(d, bufs, nb_rx);
	const uint16_t nb_ret = rte_distributor_returned_pktsd,
			bufs, BURST_SIZE*2);

		app_stats.rx.returned_pkts += nb_ret;
		if (unlikely(nb_ret == 0)) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}

		struct rte_ring *tx_ring = p->dist_tx_ring;
		uint16_t sent = rte_ring_enqueue_burst(tx_ring,
				(void *)bufs, nb_ret, NULL);
#else
		uint16_t nb_ret = nb_rx;
		/*
		 * Swap the following two lines if you want the rx traffic
		 * to go directly to tx, no distribution.
		 */
		struct rte_ring *out_ring = p->rx_dist_ring;
		/* struct rte_ring *out_ring = p->dist_tx_ring; */

		/**
		 * Enqueue several objects on a ring.
		 *
		 * This function calls the multi-producer or the single-producer
		 * version depending on the default behavior that was specified at
		 * ring creation time (see flags).
		 *
		 * @param r
		 *   A pointer to the ring structure.
		 * @param obj_table
		 *   A pointer to a table of void * pointers (objects).
		 * @param n
		 *   The number of objects to add in the ring from the obj_table.
		 * @param free_space
		 *   if non-NULL, returns the amount of space in the ring after the
		 *   enqueue operation has finished.
		 * @return
		 *   - n: Actual number of objects enqueued.
		 */
		uint16_t sent = rte_ring_enqueue_burst(out_ring,
				(void *)bufs, nb_ret, NULL);
#endif

		app_stats.rx.enqueued_pkts += sent;
		if (unlikely(sent < nb_ret)) {
			app_stats.rx.enqdrop_pkts +=  nb_ret - sent;
			RTE_LOG_DP(DEBUG, DISTRAPP,
				"%s:Packet loss due to full ring\n", __func__);
			while (sent < nb_ret)
				rte_pktmbuf_free(bufs[sent++]);
		}
		if (++port == nb_ports)
			port = 0;
	}
	/* set worker & tx threads quit flag */
	printf("\nCore %u exiting rx task.\n", rte_lcore_id());
	quit_signal = 1;
	return 0;
}

static inline void
flush_one_port(struct output_buffer *outbuf, uint8_t outp)
{
	unsigned int nb_tx = rte_eth_tx_burst(outp, 0,
			outbuf->mbufs, outbuf->count);
	app_stats.tx.tx_pkts += outbuf->count;

	if (unlikely(nb_tx < outbuf->count)) {
		app_stats.tx.enqdrop_pkts +=  outbuf->count - nb_tx;
		do {
			rte_pktmbuf_free(outbuf->mbufs[nb_tx]);
		} while (++nb_tx < outbuf->count);
	}
	outbuf->count = 0;
}

static inline void
flush_all_ports(struct output_buffer *tx_buffers)
{
	uint16_t outp;

	RTE_ETH_FOREACH_DEV(outp) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << outp)) == 0)
			continue;

		if (tx_buffers[outp].count == 0)
			continue;

		flush_one_port(&tx_buffers[outp], outp);
	}
}



static int
lcore_distributor(struct lcore_params *p)
{
	struct rte_ring *in_r = p->rx_dist_ring;
	struct rte_ring *out_r = p->dist_tx_ring;
	struct rte_mbuf *bufs[BURST_SIZE * 4];
	struct rte_distributor *d = p->d;

	printf("\nCore %u acting as distributor core.\n", rte_lcore_id());
	while (!quit_signal_dist) {
		/**
		 * Dequeue multiple objects from a ring up to a maximum number.
		 *
		 * This function calls the multi-consumers or the single-consumer
		 * version, depending on the default behaviour that was specified at
		 * ring creation time (see flags).
		 *
		 * @param r
		 *   A pointer to the ring structure.
		 * @param obj_table
		 *   A pointer to a table of void * pointers (objects) that will be filled.
		 * @param n
		 *   The number of objects to dequeue from the ring to the obj_table.
		 * @param available
		 *   If non-NULL, returns the number of remaining ring entries after the
		 *   dequeue has finished.
		 * @return
		 *   - Number of objects dequeued
		 */
		const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
				(void *)bufs, BURST_SIZE*1, NULL);
		if (nb_rx) {
			app_stats.dist.in_pkts += nb_rx;

			// set user tag so that the distributor can use the tag to distribute flows to different lcores
			int i;
			for(i = 0;i < nb_rx;i++){
				//printf("packet user tag is %u\n", bufs[i]->hash.usr);
				struct ipv4_hdr * ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct ipv4_hdr *, sizeof(struct ether_hdr));
				uint8_t iphdr_len = (ipv4_hdr->version_ihl & 0x0f) * 4;
				struct tcp_hdr * tcphdr = rte_pktmbuf_mtod_offset(bufs[i], struct tcp_hdr *, sizeof(struct ether_hdr) + iphdr_len);
				bufs[i]->hash.usr = ipv4_hdr->dst_addr + ipv4_hdr->src_addr + tcphdr->dst_port + tcphdr->src_port;
			}
			/* Distribute the packets */
			/**
			 * Process a set of packets by distributing them among workers that request
			 * packets. The distributor will ensure that no two packets that have the
			 * same flow id, or tag, in the mbuf will be processed on different cores at
			 * the same time.
			 *
			 * The user is advocated to set tag for each mbuf before calling this function.
			 * If user doesn't set the tag, the tag value can be various values depending on
			 * driver implementation and configuration.
			 *
			 * This is not multi-thread safe and should only be called on a single lcore.
			 *
			 * @param d
			 *   The distributor instance to be used
			 * @param mbufs
			 *   The mbufs to be distributed
			 * @param num_mbufs
			 *   The number of mbufs in the mbufs array
			 * @return
			 *   The number of mbufs processed.
			 */
			rte_distributor_process(d, bufs, nb_rx);
			/* Handle Returns */
			/**
			 * Get a set of mbufs that have been returned to the distributor by workers
			 *
			 * This should only be called on the same lcore as rte_distributor_process()
			 *
			 * @param d
			 *   The distributor instance to be used
			 * @param mbufs
			 *   The mbufs pointer array to be filled in
			 * @param max_mbufs
			 *   The size of the mbufs array
			 * @return
			 *   The number of mbufs returned in the mbufs array.
			 */
			const uint16_t nb_ret =
				rte_distributor_returned_pkts(d,
					bufs, BURST_SIZE*2);

			if (unlikely(nb_ret == 0))
				continue;
			app_stats.dist.ret_pkts += nb_ret;

			uint16_t sent = rte_ring_enqueue_burst(out_r,
					(void *)bufs, nb_ret, NULL);
			app_stats.dist.sent_pkts += sent;
			if (unlikely(sent < nb_ret)) {
				app_stats.dist.enqdrop_pkts += nb_ret - sent;
				RTE_LOG(DEBUG, DISTRAPP,
					"%s:Packet loss due to full out ring\n",
					__func__);
				while (sent < nb_ret)
					rte_pktmbuf_free(bufs[sent++]);
			}
		}
	}
	printf("\nCore %u exiting distributor task.\n", rte_lcore_id());
	quit_signal_work = 1;

	/**
	 * Flush the distributor component, so that there are no in-flight or
	 * backlogged packets awaiting processing
	 *
	 * This should only be called on the same lcore as rte_distributor_process()
	 *
	 * @param d
	 *   The distributor instance to be used
	 * @return
	 *   The number of queued/in-flight packets that were completed by this call.
	 */
	rte_distributor_flush(d);
	/* Unblock any returns so workers can exit */
	/**
	 * Clears the array of returned packets used as the source for the
	 * rte_distributor_returned_pkts() API call.
	 *
	 * This should only be called on the same lcore as rte_distributor_process()
	 *
	 * @param d
	 *   The distributor instance to be used
	 */
	rte_distributor_clear_returns(d);
	quit_signal_rx = 1;
	return 0;
}


static int
lcore_tx(struct rte_ring *in_r)
{
	static struct output_buffer tx_buffers[RTE_MAX_ETHPORTS];
	const int socket_id = rte_socket_id();
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"TX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet TX.\n", rte_lcore_id());
	while (!quit_signal) {

		RTE_ETH_FOREACH_DEV(port) {
			/* skip ports that are not enabled */
			if ((enabled_port_mask & (1 << port)) == 0)
				continue;

			struct rte_mbuf *bufs[BURST_SIZE_TX];
			const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
					(void *)bufs, BURST_SIZE_TX, NULL);
			app_stats.tx.dequeue_pkts += nb_rx;

			/* if we get no traffic, flush anything we have */
			if (unlikely(nb_rx == 0)) {
				flush_all_ports(tx_buffers);
				continue;
			}

			/* for traffic we receive, queue it up for transmit */
			uint16_t i;
			/**
			 * Prefetch a cache line into all cache levels (non-temporal/transient version)
			 *
			 * The non-temporal prefetch is intended as a prefetch hint that processor will
			 * use the prefetched data only once or short period, unlike the
			 * rte_prefetch0() function which imply that prefetched data to use repeatedly.
			 *
			 * @param p
			 *   Address to prefetch
			 */
			rte_prefetch_non_temporal((void *)bufs[0]);
			rte_prefetch_non_temporal((void *)bufs[1]);
			rte_prefetch_non_temporal((void *)bufs[2]);
			for (i = 0; i < nb_rx; i++) {
				struct output_buffer *outbuf;
				uint8_t outp;
				rte_prefetch_non_temporal((void *)bufs[i + 3]);
				/*
				 * workers should update in_port to hold the
				 * output port value
				 */
				outp = bufs[i]->port;
				/* skip ports that are not enabled */
				if ((enabled_port_mask & (1 << outp)) == 0)
					continue;

				outbuf = &tx_buffers[outp];
				outbuf->mbufs[outbuf->count++] = bufs[i];
				if (outbuf->count == BURST_SIZE_TX)
					flush_one_port(outbuf, outp);
			}
		}
	}
	printf("\nCore %u exiting tx task.\n", rte_lcore_id());
	return 0;
}

static void
int_handler(int sig_num)
{
	printf("Exiting on signal %d\n", sig_num);
	/* set quit flag for rx thread to exit */
	quit_signal_dist = 1;
}

static void
print_stats(void)
{
	struct rte_eth_stats eth_stats;
	unsigned int i, j;
	const unsigned int num_workers = rte_lcore_count() - 4;

	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_stats_get(i, &eth_stats);
		app_stats.port_rx_pkts[i] = eth_stats.ipackets;
		app_stats.port_tx_pkts[i] = eth_stats.opackets;
	}

	printf("\n\nRX Thread:\n");
	RTE_ETH_FOREACH_DEV(i) {
		printf("Port %u Pktsin : %5.2f\n", i,
				(app_stats.port_rx_pkts[i] -
				prev_app_stats.port_rx_pkts[i])/1000000.0);
		prev_app_stats.port_rx_pkts[i] = app_stats.port_rx_pkts[i];
	}
	printf(" - Received:    %5.2f\n",
			(app_stats.rx.rx_pkts -
			prev_app_stats.rx.rx_pkts)/1000000.0);
	printf(" - Returned:    %5.2f\n",
			(app_stats.rx.returned_pkts -
			prev_app_stats.rx.returned_pkts)/1000000.0);
	printf(" - Enqueued:    %5.2f\n",
			(app_stats.rx.enqueued_pkts -
			prev_app_stats.rx.enqueued_pkts)/1000000.0);
	printf(" - Dropped:     %s%5.2f%s\n", ANSI_COLOR_RED,
			(app_stats.rx.enqdrop_pkts -
			prev_app_stats.rx.enqdrop_pkts)/1000000.0,
			ANSI_COLOR_RESET);

	printf("Distributor thread:\n");
	printf(" - In:          %5.2f\n",
			(app_stats.dist.in_pkts -
			prev_app_stats.dist.in_pkts)/1000000.0);
	printf(" - Returned:    %5.2f\n",
			(app_stats.dist.ret_pkts -
			prev_app_stats.dist.ret_pkts)/1000000.0);
	printf(" - Sent:        %5.2f\n",
			(app_stats.dist.sent_pkts -
			prev_app_stats.dist.sent_pkts)/1000000.0);
	printf(" - Dropped      %s%5.2f%s\n", ANSI_COLOR_RED,
			(app_stats.dist.enqdrop_pkts -
			prev_app_stats.dist.enqdrop_pkts)/1000000.0,
			ANSI_COLOR_RESET);

	printf("TX thread:\n");
	printf(" - Dequeued:    %5.2f\n",
			(app_stats.tx.dequeue_pkts -
			prev_app_stats.tx.dequeue_pkts)/1000000.0);
	RTE_ETH_FOREACH_DEV(i) {
		printf("Port %u Pktsout: %5.2f\n",
				i, (app_stats.port_tx_pkts[i] -
				prev_app_stats.port_tx_pkts[i])/1000000.0);
		prev_app_stats.port_tx_pkts[i] = app_stats.port_tx_pkts[i];
	}
	printf(" - Transmitted: %5.2f\n",
			(app_stats.tx.tx_pkts -
			prev_app_stats.tx.tx_pkts)/1000000.0);
	printf(" - Dropped:     %s%5.2f%s\n", ANSI_COLOR_RED,
			(app_stats.tx.enqdrop_pkts -
			prev_app_stats.tx.enqdrop_pkts)/1000000.0,
			ANSI_COLOR_RESET);

	prev_app_stats.rx.rx_pkts = app_stats.rx.rx_pkts;
	prev_app_stats.rx.returned_pkts = app_stats.rx.returned_pkts;
	prev_app_stats.rx.enqueued_pkts = app_stats.rx.enqueued_pkts;
	prev_app_stats.rx.enqdrop_pkts = app_stats.rx.enqdrop_pkts;
	prev_app_stats.dist.in_pkts = app_stats.dist.in_pkts;
	prev_app_stats.dist.ret_pkts = app_stats.dist.ret_pkts;
	prev_app_stats.dist.sent_pkts = app_stats.dist.sent_pkts;
	prev_app_stats.dist.enqdrop_pkts = app_stats.dist.enqdrop_pkts;
	prev_app_stats.tx.dequeue_pkts = app_stats.tx.dequeue_pkts;
	prev_app_stats.tx.tx_pkts = app_stats.tx.tx_pkts;
	prev_app_stats.tx.enqdrop_pkts = app_stats.tx.enqdrop_pkts;

	for (i = 0; i < num_workers; i++) {
		printf("Worker %02u Pkts: %5.2f. Bursts(1-8): ", i,
				(app_stats.worker_pkts[i] -
				prev_app_stats.worker_pkts[i])/1000000.0);
		for (j = 0; j < 8; j++) {
			printf("%"PRIu64" ", app_stats.worker_bursts[i][j]);
			app_stats.worker_bursts[i][j] = 0;
		}
		printf("\n");
		prev_app_stats.worker_pkts[i] = app_stats.worker_pkts[i];
	}
}

static int
lcore_worker(struct lcore_params *p)
{
	struct rte_distributor *d = p->d;
	const unsigned id = p->worker_id;
	unsigned int num = 0;
	unsigned int i;

	struct middlebox_chain_configure * mcbuf[BURST_SIZE * 4];
	struct rte_ring * workerring = (p->worker_rings)[rte_lcore_id()];

	struct rte_hash_parameters mbchain_table_params = {
		.name = NULL, 
		.entries = 1024,
		.reserved = 0,
		.key_len = 16,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};
	struct rte_hash * mbchain_table = rte_hash_create(&mbchain_table_params);

	/*
	 * for single port, xor_val will be zero so we won't modify the output
	 * port, otherwise we send traffic from 0 to 1, 2 to 3, and vice versa
	 */
	const unsigned xor_val = (rte_eth_dev_count_avail() > 1);
	struct rte_mbuf *buf[8] __rte_cache_aligned;

	for (i = 0; i < 8; i++){
		buf[i] = NULL;
		mcbuf[i] = NULL;
	}

	app_stats.worker_pkts[p->worker_id] = 1;

	printf("\nCore %u acting as worker core.\n", rte_lcore_id());
	while (!quit_signal_work) {
		// read worker ring to receive control messages
		uint16_t nb_rx = rte_ring_dequeue_burst(workerring,
				(void *)mcbuf, BURST_SIZE*1, NULL);
		for(i = 0;i < nb_rx;i++){
			struct middlebox_chain_configure * mcc = mcbuf[i];
			struct middlebox_service_chain * mb_chain = rte_malloc(NULL, sizeof(struct middlebox_service_chain), 0);
			mb_chain->number_of_middleboxces = mcc->number_of_middleboxces;
			int j;
			for(j = 0;j < mcc->number_of_middleboxces;j++){
				//mb_chain[j] = rte_malloc(NULL, sizeof(struct middlebox_service), 0);
				struct middlebox_service_functions * mb_functions = NULL;
				rte_hash_lookup_data(middlebox_service_functions_table, &(mcc->middleboxes[j]), &mb_functions);
				mb_chain->middleboxes[j].id = mb_functions->middlebox_id();
				mb_chain->middleboxes[j].middlebox_id = mb_functions->middlebox_id;
				mb_chain->middleboxes[j].init_middlebox = mb_functions->init_middlebox;
				mb_chain->middleboxes[j].handle_packet = mb_functions->handle_packet;
				mb_chain->middleboxes[j].free_resource = mb_functions->free_resource;

				mb_chain->middleboxes[j].init_middlebox(&(mb_chain->middleboxes[j]));// initialize the middlebox service
			}

			// insert the middlebox chain into hash table 
			uint8_t key[16];
			memset(key, 0, 16);
			memcpy(key, &(mcc->src_ip), 4);
			memcpy(key + 4, &(mcc->dst_ip), 4);
			memcpy(key + 8, &(mcc->src_port), 2);
			memcpy(key + 10, &(mcc->dst_port), 2);
			memcpy(key + 12, &(mcc->proto), 1);
			int rv = rte_hash_add_key_data(mbchain_table, key, mb_chain);
			if(rv){
				rte_exit(EXIT_FAILURE, "insert middlebox chain to mbchain_table failed\n");
			}
		}

		num = rte_distributor_get_pkt(d, id, buf, buf, num);
		/* Do a little bit of work for each packet */
		for (i = 0; i < num; i++) {
			uint8_t key[16];
			memset(key, 0, 16);
			struct ipv4_hdr * ipv4_hdr = rte_pktmbuf_mtod_offset(buf[i], struct ipv4_hdr *, sizeof(struct ether_hdr));
			uint8_t iphdr_len = (ipv4_hdr->version_ihl & 0x0f) * 4;
			struct tcp_hdr * tcphdr = rte_pktmbuf_mtod_offset(buf[i], struct tcp_hdr *, sizeof(struct ether_hdr) + iphdr_len);
			memcpy(key, &(ipv4_hdr->src_addr), 4);
			memcpy(key + 4, &(ipv4_hdr->dst_addr), 4);
			memcpy(key + 8, &(tcphdr->src_port), 2);
			memcpy(key + 10, &(tcphdr->dst_port), 2);
			memcpy(key + 12, &(ipv4_hdr->next_proto_id), 1);

			struct middlebox_service_chain * mb_chain = NULL;
			rte_hash_lookup_data(mbchain_table, key, &mb_chain);
			int j;
			for(j = 0;j < mb_chain->number_of_middleboxces;j++){
				int action = mb_chain->middleboxes[j].handle_packet(&(mb_chain->middleboxes[j]), buf[i]);
				if(action == 0){
					// the packet is dropped by the middlebox
					break;
				}
				// else forward packet to the next middlebox for processing
			}
		}

		app_stats.worker_pkts[p->worker_id] += num;
		if (num > 0)
			app_stats.worker_bursts[p->worker_id][num-1]++;
	}
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK\n"
			"  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
			prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:",
			lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind <= 1) {
		print_usage(prgname);
		return -1;
	}

	argv[optind-1] = prgname;

	optind = 1; /* reset getopt lib */
	return 0;
}

/* Main function, does initialization and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rte_distributor *d;
	struct rte_ring *dist_tx_ring;
	struct rte_ring *rx_dist_ring;
	unsigned lcore_id, worker_id = 0;
	unsigned nb_ports;
	uint16_t portid;
	uint16_t nb_ports_available;
	uint64_t t, freq;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid distributor parameters\n");

	if (rte_lcore_count() < 5)
		rte_exit(EXIT_FAILURE, "Error, This application needs at "
				"least 5 logical cores to run:\n"
				"1 lcore for stats (can be core 0)\n"
				"1 lcore for packet RX\n"
				"1 lcore for distribution\n"
				"1 lcore for packet TX\n"
				"and at least 1 lcore for worker threads\n");

	if(rte_lcore_count() > MAX_NUM_LCORES){
		rte_exit(EXIT_FAILURE, "too many lcores specified, this application needs less than 32 lcores\n");
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");
	if (nb_ports != 1 && (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even, except "
				"when using a single port\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	nb_ports_available = nb_ports;

	mcconfig_pool = rte_mempool_create("mcconfig_pool", 1023, sizeof(struct middlebox_chain_configure),
		   0, 0,
		   NULL, NULL,
		   NULL, NULL,
		   rte_socket_id(), 0);
	if(mcconfig_pool == NULL){
		rte_exit(EXIT_FAILURE, "cannot create mcconfig_pool\n");
	}

	// initialize the middlebox function table
	struct rte_hash_parameters middlebox_function_table_parameters = {
		.name = "middlebox_service_functions_table", 
		.entries = 1024,
		.reserved = 0,
		.key_len = 8,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};
	middlebox_service_functions_table = rte_hash_create(&middlebox_function_table_parameters);
	unsigned ms_functions_len = sizeof(ms_functions) / sizeof(struct middlebox_service_functions);
	int i = 0;
	int rv;
	for(i = 0;i < ms_functions_len;i++){
		uint64_t middlebox_id = ms_functions[i].middlebox_id();
		rv = rte_hash_add_key_data(middlebox_service_functions_table, &middlebox_id, &(ms_functions[i]));
		if(rv != 0){
			rte_exit(EXIT_FAILURE, "can not add key data into middlebox_service_functions_table\n");
		}
	}

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... done\n", portid);

		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialize port %u\n",
					portid);
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
				"All available ports are disabled. Please set portmask.\n");
	}

	// Function to create a new distributor instance
	// Reserves the memory needed for the distributor operation and 
	// initializes the distributor to work with the configured number of workers.
	d = rte_distributor_create("PKT_DIST", rte_socket_id(),
			rte_lcore_count() - 4,
			RTE_DIST_ALG_BURST);
	if (d == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create distributor\n");

	/*
	 * scheduler ring is read by the transmitter core, and written to
	 * by scheduler core
	 */
	// create a single-consumer and single-producer ring
	dist_tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (dist_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	// receive core write, scheduler core read
	// thus a single-consumer, single-producer ring
	rx_dist_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_dist_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	// create a ring for each worker thread
	// used by the rx thread to transmit control messages to the work threads
	unsigned worker_lcore_ids[MAX_NUM_LCORES]; // should be enough in most cases
	// index by the work lcore id
	struct rte_ring * worker_rings[MAX_NUM_LCORES];
	for(i = 0;i < MAX_NUM_LCORES;i++){
		worker_rings[i] = NULL;
	}

	unsigned number_of_worker_lcores = 0;
	unsigned rx_lcore_id;
	unsigned tx_lcore_id;
	unsigned distributor_lcore_id;

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (worker_id == rte_lcore_count() - 3) {
			printf("Starting distributor on lcore_id %d\n",
					lcore_id);
			distributor_lcore_id = lcore_id;
		} else if (worker_id == rte_lcore_count() - 4) {
			printf("Starting tx  on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			/* tx core */
			// rte_eal_remote_launch((lcore_function_t *)lcore_tx,
			// 		dist_tx_ring, lcore_id);
			tx_lcore_id = lcore_id;
		} else if (worker_id == rte_lcore_count() - 2) {
			printf("Starting rx on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			rx_lcore_id = lcore_id;
		} else {
			printf("Starting worker on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			worker_lcore_ids[number_of_worker_lcores] = lcore_id;
			number_of_worker_lcores++;
		}
		worker_id++;
	}

	for(i = 0;i < number_of_worker_lcores;i++){
		char name[50];
		sprintf(name, "workerring%u", i);
		worker_rings[worker_lcore_ids[i]] = rte_ring_create(name, SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
		if (worker_rings[worker_lcore_ids[i]] == NULL) {
			rte_exit(EXIT_FAILURE, "Cannot create worker ring\n");
		}
	}

	worker_id = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (worker_id == rte_lcore_count() - 3) {
			printf("Starting distributor on lcore_id %d\n",
					lcore_id);
			/* distributor core */
			struct lcore_params *p =
					rte_malloc(NULL, sizeof(*p), 0);
			if (!p)
				rte_panic("malloc failure\n");
			*p = (struct lcore_params){worker_id, d,
				rx_dist_ring, dist_tx_ring, mbuf_pool, worker_rings};

			rte_eal_remote_launch(
				(lcore_function_t *)lcore_distributor,
				p, lcore_id);
		} else if (worker_id == rte_lcore_count() - 4) {
			printf("Starting tx  on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			/* tx core */
			rte_eal_remote_launch((lcore_function_t *)lcore_tx,
					dist_tx_ring, lcore_id);
		} else if (worker_id == rte_lcore_count() - 2) {
			printf("Starting rx on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			/* rx core */
			struct lcore_params *p =
					rte_malloc(NULL, sizeof(*p), 0);
			if (!p)
				rte_panic("malloc failure\n");
			*p = (struct lcore_params){worker_id, d, rx_dist_ring,
					dist_tx_ring, mbuf_pool, worker_rings};
			rte_eal_remote_launch((lcore_function_t *)lcore_rx,
					p, lcore_id);
		} else {
			printf("Starting worker on worker_id %d, lcore_id %d\n",
					worker_id, lcore_id);
			struct lcore_params *p =
					rte_malloc(NULL, sizeof(*p), 0);
			if (!p)
				rte_panic("malloc failure\n");
			*p = (struct lcore_params){worker_id, d, rx_dist_ring,
					dist_tx_ring, mbuf_pool, worker_rings};

			rte_eal_remote_launch((lcore_function_t *)lcore_worker,
					p, lcore_id);
		}
		worker_id++;
	}

	freq = rte_get_timer_hz();
	t = rte_rdtsc() + freq;
	while (!quit_signal_dist) {
		if (t < rte_rdtsc()) {
			print_stats();
			t = rte_rdtsc() + freq;
		}
		usleep(1000);
	}

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	print_stats();
	return 0;
}
