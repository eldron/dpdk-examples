/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mempool.h>

struct flow_configure{
	uint32_t srcip;
	uint32_t dstip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
};

struct rte_mempool * flow_config_pool;

static int
lcore_hello(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("hello from core %u\n", lcore_id);

	struct flow_config * config = NULL;
	rte_mempool_get(flow_config_pool, &config);
	if(config){
		printf("lcore %u get one flow config, there are %u in use\n", lcore_id, rte_mempool_in_use_count(flow_config_pool));
	}
	rte_mempool_put(flow_config_pool, config);
	printf("lcore %u put one flow config, there are %u in use\n", lcore_id, rte_mempool_in_use_count(flow_config_pool));
	return 0;
}



int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	flow_config_pool =  rte_mempool_create("flow_config_pool", 63, sizeof(struct flow_configure),
		   0, 0,
		   NULL, NULL,
		   NULL, NULL,
		   rte_socket_id(), 0);
	if(!flow_config_pool){
		printf("rte_mempool_create failed\n");
	} else {
		printf("rte_mempool_create succeeded\n");
	}

	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* call it on master lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();
	return 0;
}
