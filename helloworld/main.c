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
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

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


	uint64_t * a = rte_malloc(NULL, sizeof(uint64_t), 0);
	*a = lcore_id;
	printf("a = %lu\n", *a);
	rte_free(a);

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

	// uint8_t key[16];
	// memset(key, 0, 16);
	// uint32_t hash_value = rte_jhash(key, 16, 0);
	// printf("hash value is %u\n", hash_value);

// 	struct rte_hash_parameters {
// 	const char *name;		/**< Name of the hash. */
// 	uint32_t entries;		/**< Total hash table entries. */
// 	uint32_t reserved;		/**< Unused field. Should be set to 0 */
// 	uint32_t key_len;		/**< Length of hash key. */
// 	rte_hash_function hash_func;	/**< Primary Hash function used to calculate hash. */
// 	uint32_t hash_func_init_val;	/**< Init value used by hash_func. */
// 	int socket_id;			/**< NUMA Socket ID for memory. */
// 	uint8_t extra_flag;		/**< Indicate if additional parameters are present. */
// };
	struct rte_hash_parameters hash_parameters = {
		.name = NULL, 
		.entries = 1024,
		.reserved = 0,
		.key_len = 16,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};

	struct rte_hash * hash_table = rte_hash_create(&hash_parameters);
	printf("created a hash table\n");

	uint8_t key[16];
	memset(key, 0, 16);

	char * s1 = "hello world\n";
	char * s2 = "hello beautiful\n";

	int rv = rte_hash_add_key_data(hash_table, key, s1);
	if(rv == 0){
		printf("added s1 to hash table\n");
	} else {
		printf("add s1 to hash table failed\n");
	}

	key[0] = 1;
	rv = rte_hash_add_key_data(hash_table, key, s2);
	if(rv == 0){
		printf("added s2 to hash table\n");
	} else {
		printf("add s2 to hash table failed\n");
	}

	void * result;
	rv = rte_hash_lookup_data(hash_table, key, &result);
	printf("lookup result is %s", (char *) result);

	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}


	/* call it on master lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();
	return 0;
}
