/*
 * (C) 2025 - ntop 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <doca_flow.h>
#include <doca_flow_ct.h>

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <doca_dpdk.h>

/**********************************************************/

#define STATS_FREQ_SEC 1
#define EXPORT_FREQ_SEC  5
#define DEFAULT_IDLE_TIMEOUT 60

#define FLOW_CT_DEVARGS "dv_flow_en=2,dv_xmeta_en=4,representor=pf[0-1],repr_matching_en=0,fdb_def_rule_en=0,vport_match=1"
#define ENTRIES_PROCESS_TIMEOUT_USEC 10000
#define DUP_FILTER_CONN_NUM 512

#define MAX_PORTS	2
#define MAX_NUM_FLOWS	(2*1024*1024) /* max working: 2M */
#define PACKET_BURST	128
#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024
#define NUM_MBUFS	(8*1024)
#define MBUF_CACHE_SIZE	250
#define RSS_KEY_LEN	40

//#define DEBUG

//#define PROFILING
#define PROFILING_N 2000000

/**********************************************************/

/* Software flow table entry */
struct sw_ct_entry {
	struct doca_flow_ct_match key; /* Flow Key */
	struct doca_flow_pipe_entry *pipe_entry; /* CT entry pointer */
};

/* User context to be used in entries process callback */
struct pipe_entries_status {
	bool failure;            /* true if some entry status fails */
	u_int32_t num_allocated; /* number of allocated entries */
	u_int32_t num_deleted;   /* number of deleted entries */
	u_int32_t num_updated;   /* number of updated entries */
	u_int32_t num_active;    /* number of active entries */
	u_int32_t num_expired;   /* number of expired entries */
	u_int32_t num_mem_fail;  /* number of entry allocation failures */
	bool export_on_delete;   /* true to print flows on expiration */
	struct doca_flow_pipe *pipe; /* pointer to the pipe */
	struct rte_hash *sw_ct;  /* software flow table */
};

/* DPDK configuration */
struct dpdk_config {
	int num_ports;
	u_int16_t num_queues;
	u_int16_t mbuf_size;
	struct rte_mempool *mbuf_pool;
	u_int8_t enable_mbuf_metadata;
	u_int8_t rss_support;
	u_int8_t isolated_mode;
	u_int8_t switch_mode;
};

/* Application context */
struct app_context {
	/* Configuration */
	int num_ports;    /* number of configured ports */
	u_int16_t num_rss_queues; /* number of RSS queues */
	int idle_timeout; /* flow idle timeout */
	int verbosity;    /* verbosity level */
	bool enable_fwd;
	bool enable_sw_ct;
	bool enable_export;
	char dev_pci_addr[MAX_PORTS][DOCA_DEVINFO_PCI_ADDR_SIZE];
	/* Runtime */
	u_int64_t num_total_packets; /* total number of captured packets */
	bool do_shutdown;
	struct pipe_entries_status *ct_status;
};

DOCA_LOG_REGISTER(KRYPTONITE);

static struct app_context app_ctx = {0};

/**********************************************************/

doca_error_t init_doca_flow(int num_queues, const char *mode, doca_flow_entry_process_cb callback);
doca_error_t start_doca_flow_port(int port_id, struct doca_dev *dev, enum doca_flow_port_operation_state state, struct doca_flow_port **port);
doca_error_t stop_doca_flow_ports(int num_ports, struct doca_flow_port *ports[]);
doca_error_t check_aged_flows(struct doca_flow_port *port, u_int16_t ct_queue, struct pipe_entries_status *ct_status);
doca_error_t set_flow_pipe_cfg(struct doca_flow_pipe_cfg *cfg, const char *name, enum doca_flow_pipe_type type, bool is_root);
doca_error_t create_root_pipe(struct doca_flow_port *port, struct doca_flow_pipe *fwd_pipe, struct pipe_entries_status *status, struct doca_flow_pipe **pipe);
void cleanup_dpdk_ports(struct dpdk_config *dpdk_config, u_int16_t num_ports);
void dump_port_stats(struct app_context *app_context, u_int16_t port_id);

/**********************************************************/

#define SEC2NSEC(s) ((u_int64_t) s * 1000000000)

/**********************************************************/

/*
 * Create port forwarding pipe
 *
 * @port: Pipe port
 * @enable_fwd: Enable packet forwarding
 * @fwd_port_id: Forward port ID
 * @status: User context for adding entry
 * @pipe: Created pipe
 */
doca_error_t create_port_fwd_pipe(struct doca_flow_port *port,
				  bool enable_fwd,
				  int fwd_port_id,
				  struct pipe_entries_status *status,
				  struct doca_flow_pipe **pipe /* out */) {
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_match match = { 0 };
	struct doca_flow_fwd fwd = { 0 };
	doca_error_t rc;

	rc = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = set_flow_pipe_cfg(pipe_cfg, "PORT_FWD_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	rc = doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg domain: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	rc = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg match: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	if (enable_fwd) {
		fwd.type = DOCA_FLOW_FWD_PORT;
		fwd.port_id = fwd_port_id;
	} else {
		fwd.type = DOCA_FLOW_FWD_DROP;
	}

	rc = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating fwd pipe: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	doca_flow_pipe_cfg_destroy(pipe_cfg);

	rc = doca_flow_pipe_add_entry(0, *pipe, &match, 
		NULL, NULL, NULL, 0, status, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure adding fwd pipe entry: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_entries_process(port, 0, ENTRIES_PROCESS_TIMEOUT_USEC, 0);
	if (rc != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failure processing entry: %s", doca_error_get_descr(rc));

	return rc;

destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return rc;
}

/*
 * Create RSS pipe
 *
 * @port: Pipe port
 * @num_rss_queues: Number of RSS queues
 * @status: User context for adding entry
 * @pipe: Created pipe
 */
doca_error_t create_rss_pipe(struct doca_flow_port *port,
			     u_int16_t num_rss_queues,
			     struct pipe_entries_status *status,
			     struct doca_flow_pipe **pipe /* out */) {
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_match match = { 0 };
	struct doca_flow_fwd fwd = { 0 };
	u_int16_t rss_queues[num_rss_queues];
	int i;
	doca_error_t rc;

	rc = doca_flow_pipe_cfg_create(&cfg, port);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = set_flow_pipe_cfg(cfg, "RSS_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	rc = doca_flow_pipe_cfg_set_match(cfg, &match, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg match: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	/* RSS queue (send matched traffic to queue 0) */
	for (i = 0; i < num_rss_queues; i++)
		rss_queues[i] = i;
	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss_queues = rss_queues;
	fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP | DOCA_FLOW_RSS_TCP;
	fwd.num_of_queues = num_rss_queues;

	rc = doca_flow_pipe_create(cfg, &fwd, NULL, pipe);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating RSS pipe: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	doca_flow_pipe_cfg_destroy(cfg);

	/* Match on any packet */
	rc = doca_flow_pipe_add_entry(0, *pipe, &match, NULL, NULL, &fwd, 0, status, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure adding RSS pipe entry: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_entries_process(port, 0, ENTRIES_PROCESS_TIMEOUT_USEC, 0);
	if (rc != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failure process RSS entry: %s", doca_error_get_descr(rc));

	return rc;

destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(cfg);
	return rc;
}

/*
 * Create Flow CT pipe
 *
 * @port: Pipe port
 * @port_fwd_pipe: Forward pipe
 * @count_miss_pipe: Forward miss pipe
 * @pipe: Created pipe
 */
doca_error_t create_flow_ct_pipe(struct doca_flow_port *port,
				 struct doca_flow_pipe *port_fwd_pipe,
				 struct doca_flow_pipe *count_miss_pipe,
				 struct doca_flow_pipe **pipe /* out */) {
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_match match = { 0 };
	struct doca_flow_match mask = { 0 };
	struct doca_flow_fwd fwd = { 0 };
	struct doca_flow_fwd fwd_miss = { 0 };
	doca_error_t rc;

	rc = doca_flow_pipe_cfg_create(&cfg, port);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = set_flow_pipe_cfg(cfg, "CT_PIPE", DOCA_FLOW_PIPE_CT, false);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}
	rc = doca_flow_pipe_cfg_set_match(cfg, &match, &mask);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg match: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = port_fwd_pipe;

	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = count_miss_pipe;

	rc = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, pipe);
	if (rc != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failure adding CT pipe: %s", doca_error_get_descr(rc));
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(cfg);
	return rc;
}

/*
 * Print IPv4 packet headers
 */
void print_ipv4_hdr(const struct rte_ipv4_hdr *ipv4_hdr) {
	u_int8_t version = (ipv4_hdr->version_ihl >> 4) & 0xF;
	struct in_addr src_addr, dst_addr;

	printf("IPv%u", version);
	printf(" Protocol: %u", ipv4_hdr->next_proto_id);
	src_addr.s_addr = ipv4_hdr->src_addr;
	dst_addr.s_addr = ipv4_hdr->dst_addr;
	printf("  Source Address: %s", inet_ntoa(src_addr));
	printf("  Destination Address: %s", inet_ntoa(dst_addr));
}

/*
 * Print flow key
 */
void print_flow_key(const struct doca_flow_ct_match *key) {
	struct in_addr src_addr, dst_addr;
	src_addr.s_addr = key->ipv4.src_ip;
	dst_addr.s_addr = key->ipv4.dst_ip;
	printf("src=%s:%u ", inet_ntoa(src_addr), ntohs(key->ipv4.l4_port.src_port));
	printf("dst=%s:%u ", inet_ntoa(dst_addr), ntohs(key->ipv4.l4_port.dst_port));
	printf("proto=%u ", key->ipv4.next_proto);
}

/*
 * Print flow with counters
 */
void print_flow(struct pipe_entries_status *ct_status,
		u_int16_t ct_queue,
		struct doca_flow_pipe_entry *entry,
		const struct doca_flow_ct_match *key) {
	struct doca_flow_resource_query query_o;
	struct doca_flow_resource_query query_r;
	u_int64_t last_seen_epoch = 0;
	doca_error_t rc;

	rc = doca_flow_ct_query_entry(ct_queue,
		ct_status->pipe,
		DOCA_FLOW_CT_ENTRY_FLAGS_NO_WAIT,
		entry,
		&query_o,
		&query_r,
		&last_seen_epoch);
	if (rc == DOCA_SUCCESS) {
		printf("Flow ");
		print_flow_key(key);
		printf( "out-bytes=%ld "
			"out-packets=%ld "
			"in-bytes=%ld "
			"in-packets=%ld "
			"last-seen=%ld\n", 
			query_o.counter.total_bytes,
			query_o.counter.total_pkts,
			query_r.counter.total_bytes,
			query_r.counter.total_pkts,
			last_seen_epoch);
	}
}

/*
 * Print active flows with counters
 */
void export_flows(struct app_context *app_context,
		  u_int16_t ct_queue) {
	const struct doca_flow_ct_match *key;
	struct sw_ct_entry *sw_entry;
	uint32_t next = 0;

	if (!app_context->ct_status->sw_ct)
		return;

	while (rte_hash_iterate(app_context->ct_status->sw_ct,
				(const void **) &key,
				(void **) &sw_entry,
				&next) >= 0) {
		print_flow(app_context->ct_status, ct_queue, sw_entry->pipe_entry, key);
	}
}

/*
 * Parse UDP packet to update CT tables
 *
 * @packet: Packet to parse
 * @match_o: Origin match struct to fill
 * @match_r: Reply match struct to fill
 * @tcp_state: TCP flags to fill
 */
int parse_packet(struct rte_mbuf *packet,
		 struct doca_flow_ct_match *match_o, /* out */
		 struct doca_flow_ct_match *match_r, /* out */
		 u_int8_t *tcp_state /* out */) {
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	u_int8_t *l4_hdr;

	eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);

	if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
#ifdef DEBUG
		DOCA_LOG_INFO("Unhandled protocol (not IPv4)");
#endif
		return -1;
	}

	ipv4_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

#ifdef DEBUG
	print_ipv4_hdr(ipv4_hdr);
#endif

	match_o->ipv4.src_ip = ipv4_hdr->src_addr;
	match_o->ipv4.dst_ip = ipv4_hdr->dst_addr;
	match_r->ipv4.src_ip = match_o->ipv4.dst_ip;
	match_r->ipv4.dst_ip = match_o->ipv4.src_ip;

	*tcp_state = 0;

	l4_hdr = (typeof(l4_hdr))ipv4_hdr + rte_ipv4_hdr_len(ipv4_hdr);
	if (ipv4_hdr->next_proto_id == DOCA_FLOW_PROTO_UDP) {
		const struct rte_udp_hdr *udp_hdr;
		udp_hdr = (typeof(udp_hdr))l4_hdr;

		match_o->ipv4.l4_port.src_port = udp_hdr->src_port;
		match_o->ipv4.l4_port.dst_port = udp_hdr->dst_port;
		match_r->ipv4.l4_port.src_port = match_o->ipv4.l4_port.dst_port;
		match_r->ipv4.l4_port.dst_port = match_o->ipv4.l4_port.src_port;

		match_o->ipv4.next_proto = DOCA_FLOW_PROTO_UDP;
		match_r->ipv4.next_proto = DOCA_FLOW_PROTO_UDP;
	} else if (ipv4_hdr->next_proto_id == DOCA_FLOW_PROTO_TCP) {
		const struct rte_tcp_hdr *tcp_hdr;
		tcp_hdr = (typeof(tcp_hdr))l4_hdr;

		match_o->ipv4.l4_port.src_port = tcp_hdr->src_port;
		match_o->ipv4.l4_port.dst_port = tcp_hdr->dst_port;
		match_r->ipv4.l4_port.src_port = match_o->ipv4.l4_port.dst_port;
		match_r->ipv4.l4_port.dst_port = match_o->ipv4.l4_port.src_port;

		match_o->ipv4.next_proto = DOCA_FLOW_PROTO_TCP;
		match_r->ipv4.next_proto = DOCA_FLOW_PROTO_TCP;

		*tcp_state = tcp_hdr->tcp_flags;
	} else {
#ifdef DEBUG
		DOCA_LOG_INFO("Unhandled L4 protocol (%u)", ipv4_hdr->next_proto_id);
#endif
		return -1;
	}

	return 0;
}

/*
 * Capture packets, parse them, add flows to CT
 *
 * @app_context: Application configuration and context
 * @port: Port to which an entry should be inserted
 * @ct_queue: DOCA Flow CT queue number
 * @port_id: Port ID
 */
doca_error_t run_capture(struct app_context *app_context,
			 struct doca_flow_port *port,
			 u_int16_t ct_queue,
			 int port_id) {
	struct rte_mbuf *packets[PACKET_BURST];
	struct doca_flow_ct_match match_o = { 0 };
	struct doca_flow_ct_match match_r = { 0 };
	struct doca_flow_pipe_entry *entry;
	struct sw_ct_entry *sw_entry;
	u_int32_t flags;
	u_int16_t num_packets;
	bool conn_found = false;
	u_int8_t tcp_state;
	struct timespec now;
	u_int64_t now_ns;
	u_int64_t last_export_ns = 0;
	doca_error_t rc;
	int ret;
	int i;
#ifdef PROFILING
	u_int64_t profiling_start_ns = 0;
	u_int64_t profiling_elaps_ns = 0;
#endif

	DOCA_LOG_INFO("Running...");

	while (!app_context->do_shutdown) {

		/*** Capture packets from RSS ***/

		num_packets = rte_eth_rx_burst(0, 0, packets, PACKET_BURST);
		if (num_packets == 0) {
			usleep(1);

			if (app_context->enable_export) {
				clock_gettime(CLOCK_MONOTONIC_RAW, &now);
				now_ns = SEC2NSEC(now.tv_sec) + now.tv_nsec;
				if (now_ns > last_export_ns + SEC2NSEC(EXPORT_FREQ_SEC)) {
					export_flows(app_context, ct_queue);
					last_export_ns = now_ns;
				}
			}

		} else for (i = 0; i < PACKET_BURST && i < num_packets; i++) {
#ifdef DEBUG
			printf("#%u ", app_context->num_total_packets);
#endif
			app_context->num_total_packets++;
			u_int32_t max_room = 0;
			doca_flow_ct_entries_process(port, ct_queue, 0, 0, &max_room);

			/*** Parse packet ***/

			if (max_room < 2) {
				// No room
				DOCA_LOG_ERR("No room to add new entries");
			} else if (parse_packet(packets[i], &match_o, &match_r, &tcp_state) == 0) {
#ifdef DEBUG
				printf("\n");
#endif
				ret = -1;
				if (app_context->ct_status->sw_ct) {
					/* Check in the (shadow) software flow table if already set */
					ret = rte_hash_lookup_data(app_context->ct_status->sw_ct, &match_o, (void **) &sw_entry);
				}
				if (ret >= 0) {
					/* Already present: nothing to do */
				} else {
					/*** Add flow entry to CT ***/

#ifdef PROFILING
					if (app_context->num_total_packets == 1) {
						clock_gettime(CLOCK_MONOTONIC_RAW, &now);
						now_ns = SEC2NSEC(now.tv_sec) + now.tv_nsec;
						profiling_start_ns = now_ns;
					}
#endif

					flags = DOCA_FLOW_CT_ENTRY_FLAGS_ALLOC_ON_MISS
						| DOCA_FLOW_CT_ENTRY_FLAGS_DUP_FILTER_ORIGIN
						| DOCA_FLOW_CT_ENTRY_FLAGS_DUP_FILTER_REPLY;
					/* Allocate CT entry */
					rc = doca_flow_ct_entry_prepare(ct_queue,
						NULL,
						flags,
						&match_o,
						packets[i]->hash.rss,
						&match_r,
						packets[i]->hash.rss,
						&entry,
						&conn_found);
					if (rc != DOCA_SUCCESS) {
						app_context->ct_status->num_mem_fail++;
					} else if (!conn_found) {
						app_context->ct_status->num_allocated++;

						flags = DOCA_FLOW_CT_ENTRY_FLAGS_NO_WAIT
						      | DOCA_FLOW_CT_ENTRY_FLAGS_DIR_ORIGIN
						      | DOCA_FLOW_CT_ENTRY_FLAGS_DIR_REPLY;

						if (app_context->enable_export) {
							flags |= DOCA_FLOW_CT_ENTRY_FLAGS_COUNTER_ORIGIN
							       | DOCA_FLOW_CT_ENTRY_FLAGS_COUNTER_REPLY;
						}

						rc = doca_flow_ct_add_entry(ct_queue,
							NULL,
							flags,
							&match_o,
							&match_r,
							NULL,
							NULL,
							0,
							0,
							app_context->idle_timeout,
							app_context->ct_status, /* note: a global ref is passed, a per-entry ref can be used */
							entry);
						if (rc != DOCA_SUCCESS) {
							DOCA_LOG_ERR("Failure adding entry to CT pipe: %s", doca_error_get_descr(rc));
							/* Do we need to call doca_flow_ct_entry_prepare_rollback here? */
							return rc;
						} else {
							if (app_context->ct_status->sw_ct) {
								/* Add to the (shadow) software flow table */
								struct sw_ct_entry *sw_entry = (struct sw_ct_entry *) malloc(sizeof(struct sw_ct_entry));
								if (sw_entry == NULL) {
									DOCA_LOG_ERR("Failure allocating software flow table entry");
								} else {
									memcpy(&sw_entry->key, &match_o, sizeof(struct doca_flow_ct_match));
									sw_entry->pipe_entry = entry;

									ret = rte_hash_add_key_data(app_context->ct_status->sw_ct, &match_o, (void *) sw_entry);
									if (ret < 0) {
										DOCA_LOG_ERR("Failure adding entry to software flow table (%u entries)",
											     app_context->ct_status->num_allocated);
									}
								}
							}

#ifdef PROFILING
							if (app_context->num_total_packets == PROFILING_N) {
								clock_gettime(CLOCK_MONOTONIC_RAW, &now);
								now_ns = SEC2NSEC(now.tv_sec) + now.tv_nsec;
								profiling_elaps_ns = now_ns - profiling_start_ns;
								DOCA_LOG_ERR("%u records created in %.1f usec (%.0f K/s)",
									     PROFILING_N,
									     (double) profiling_elaps_ns/1000,
									     ((double) PROFILING_N/profiling_elaps_ns)*1000000);
							}
#endif

						}
					} else {
						DOCA_LOG_INFO("Already present?");
					}
				}
			}

			if (app_context->enable_fwd) {
				rte_eth_tx_burst(0, 0, &packets[i], 1);
			} else {
		 		rte_pktmbuf_free(packets[i]);
			}
		}

		/*** Process flow entries to CT ***/

		rc = doca_flow_ct_entries_process(port, ct_queue, 0, 0, NULL);
		if (rc != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failure processing Flow CT entries: %s", doca_error_get_descr(rc));
			return rc;
		}

		if (app_context->ct_status->failure) {
			DOCA_LOG_ERR("Failure processing Flow CT entries");
			return DOCA_ERROR_BAD_STATE;
		}

		if (app_context->idle_timeout > 0) {
			/*** Scan expired flows in CT ***/
			rc = check_aged_flows(port, ct_queue, app_context->ct_status);
			if (rc != DOCA_SUCCESS)
				break;
		}
	}

	DOCA_LOG_INFO("Stopping packet processing...");
	sleep(2);

	return DOCA_SUCCESS;
}

/*
 * Handle all aged flow in a port
 *
 * @port: port to remove the aged flow from
 * @ct_queue: Pipe of the entries
 * @ct_status: user context
 */
doca_error_t check_aged_flows(struct doca_flow_port *port,
			      u_int16_t ct_queue,
			      struct pipe_entries_status *ct_status) {
	int num_of_aged_entries;
	doca_error_t rc;
	u_int32_t max_room = 0;

	num_of_aged_entries = doca_flow_aging_handle(port, ct_queue, 0, 64);

	if (num_of_aged_entries > 0) {
		while (max_room < 256) {
			rc = doca_flow_ct_entries_process(port, ct_queue, 0, 0, &max_room);
			if (rc != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failure processing CT entries: %s", doca_error_get_descr(rc));
				return rc;
			}
			if (ct_status->failure) {
				DOCA_LOG_ERR("Failure processing Flow CT entries");
				return DOCA_ERROR_BAD_STATE;
			}
		}
	}

	return DOCA_SUCCESS;
}

/*
 * Entry status update callback
 *
 * @entry: DOCA Flow entry
 * @pipe_queue: Queue identifier
 * @status: Entry status
 * @op: Entry operation
 * @user_ctx: User context
 */
void entry_status_callback(struct doca_flow_pipe_entry *entry,
			   u_int16_t pipe_queue,
			   enum doca_flow_entry_status status,
			   enum doca_flow_entry_op op,
			   void *user_ctx) {
	struct pipe_entries_status *entries_status = (struct pipe_entries_status *) user_ctx;
	struct sw_ct_entry *sw_entry;
	struct doca_flow_ct_match match_o;
	struct doca_flow_ct_match match_r;
	uint64_t entry_flags;
	doca_error_t rc;
	int ret;

	if (entries_status == NULL) {
		DOCA_LOG_ERR("Failure in entry_status_callback: NULL user context");
		return;
	}
	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("Failure in entry_status_callback: status != success");
		entries_status->failure = true; /* set failure to true if processing failed */
	}

	switch (op) {
	case DOCA_FLOW_ENTRY_OP_ADD:
		entries_status->num_active++;
		break;

	case DOCA_FLOW_ENTRY_OP_DEL:
		entries_status->num_active--;
		entries_status->num_allocated--;
		entries_status->num_deleted++;

		if (entries_status->export_on_delete || entries_status->sw_ct) {
			/* Read entry key */
			rc = doca_flow_ct_get_entry(pipe_queue, entries_status->pipe, 0 /* flags */, entry, &match_o, &match_r, &entry_flags);
			if (rc == DOCA_SUCCESS) {

				if (entries_status->export_on_delete) {
					/* Export expired flow */
					print_flow(entries_status, pipe_queue, entry, &match_o);
				}

				if (entries_status->sw_ct) {
					/* Get sw entry */
					sw_entry = NULL;
					ret = rte_hash_lookup_data(entries_status->sw_ct, &match_o, (void **) &sw_entry);
					if (ret >= 0) {
						/* Free sw entry */
						free(sw_entry);
						ret = rte_hash_del_key(entries_status->sw_ct, &match_o);
						if (ret < 0) {
							DOCA_LOG_ERR("Failure deleting entry from software flow table");
						}
					} else {
						DOCA_LOG_ERR("Expired entry not found in software flow table");
					}
				}
			} else {
				DOCA_LOG_INFO("Failure getting entry key");
			}
		}
		break;

	case DOCA_FLOW_ENTRY_OP_UPD:
		entries_status->num_updated++;
		break;

	case DOCA_FLOW_ENTRY_OP_AGED:
		rc = doca_flow_ct_rm_entry(pipe_queue, NULL, DOCA_FLOW_CT_ENTRY_FLAGS_NO_WAIT, entry);
		if (rc == DOCA_SUCCESS) {
			entries_status->num_expired++;
		} else {
			DOCA_LOG_INFO("Failure removing entry");
		}
		break;
	default:
		DOCA_LOG_INFO("Unhandled op code %u", op);
		break;
	}
}

/*
 * Create root pipe
 *
 * @port: Pipe port
 * @fwd_pipe: Next pipe
 * @status: User context for adding entry
 * @pipe: Created pipe
 */
doca_error_t create_root_pipe(struct doca_flow_port *port,
			      struct doca_flow_pipe *fwd_pipe,
			      struct pipe_entries_status *status,
			      struct doca_flow_pipe **pipe /* out */) {
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_match match = { 0 };
	struct doca_flow_fwd fwd = { 0 };
	doca_error_t rc;

	rc = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = set_flow_pipe_cfg(pipe_cfg, "root", DOCA_FLOW_PIPE_CONTROL, true);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}

	rc = doca_flow_pipe_create(pipe_cfg, NULL, NULL, pipe);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating root pipe: %s", doca_error_get_descr(rc));
		goto destroy_pipe_cfg;
	}
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = fwd_pipe;

	memset(&match, 0, sizeof(match));
	rc = doca_flow_pipe_control_add_entry(0, 1, *pipe, &match, NULL, NULL, NULL, NULL, NULL, NULL, &fwd, status, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure adding root pipe IPv4 entry: %s", doca_error_get_descr(rc));
		return rc;
	}

	/* Drop non matching packets (none) */
	fwd.type = DOCA_FLOW_FWD_DROP;
	memset(&match, 0, sizeof(match));
	rc = doca_flow_pipe_control_add_entry(0, 2, *pipe, &match, NULL, NULL, NULL, NULL, NULL, NULL, &fwd, status, NULL);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure adding root pipe drop entry: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_entries_process(port, 0, ENTRIES_PROCESS_TIMEOUT_USEC, 0);
	if (rc != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failure processing root entry: %s", doca_error_get_descr(rc));

	return rc;

destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return rc;
}

/*
 * Run pipeline
 *
 * @app_context: Application configuration
 * @num_queues: Number of queues
 * @dev: Flow CT device
 */
doca_error_t run_flow_ct(struct app_context *app_context,
			 u_int16_t num_queues,
			 struct doca_dev *dev) {
	struct doca_flow_ct_cfg ct_cfg = { 0 };
	struct doca_flow_meta o_zone_mask = { 0 };
	struct doca_flow_meta o_modify_mask = { 0 };
	struct doca_flow_meta r_zone_mask = { 0 };
	struct doca_flow_meta r_modify_mask = { 0 };
	struct doca_flow_pipe *rss_pipe = NULL;
	struct doca_flow_pipe *port_fwd_pipe = NULL;
	struct doca_flow_pipe *ct_pipe = NULL;
	struct doca_flow_pipe *root_pipe = NULL;
	struct doca_flow_port *ports[MAX_PORTS];
	struct doca_dev *dev_arr[MAX_PORTS];
	struct pipe_entries_status ctrl_status = { 0 };
	u_int32_t nb_arm_queues = 1;
	u_int32_t nb_ctrl_queues = 1;
	u_int32_t nb_user_actions = 0;
	u_int16_t ct_queue = num_queues;
	int num_ports = 2;
	int num_entries = 0;
	int port_id;
	doca_error_t rc;

	rc = init_doca_flow(num_queues, "switch,hws", entry_status_callback);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure initializing DOCA Flow: %s", doca_error_get_descr(rc));
		return rc;
	}

	/* Initialize DOCA Flow CT */

	ct_cfg.flags = DOCA_FLOW_CT_FLAG_MANAGED;

	ct_cfg.nb_arm_queues = nb_arm_queues;
	ct_cfg.nb_ctrl_queues = nb_ctrl_queues;
	ct_cfg.nb_user_actions = nb_user_actions;
	ct_cfg.aging_core = nb_arm_queues + 1;
	ct_cfg.flow_log_cb = NULL;
	ct_cfg.nb_arm_sessions[DOCA_FLOW_CT_SESSION_IPV4] = MAX_NUM_FLOWS;
	ct_cfg.nb_arm_sessions[DOCA_FLOW_CT_SESSION_IPV6] = 0;
	ct_cfg.dup_filter_sz = 0;

	if (app_context->idle_timeout == 0) {
		ct_cfg.flags |= DOCA_FLOW_CT_FLAG_NO_AGING
			      | DOCA_FLOW_CT_FLAG_NO_COUNTER;
		ct_cfg.dup_filter_sz = DUP_FILTER_CONN_NUM;
	}

	ct_cfg.direction[0].match_inner = false;
	ct_cfg.direction[0].zone_match_mask = &o_zone_mask;
	ct_cfg.direction[0].meta_modify_mask = &o_modify_mask;

	ct_cfg.direction[1].match_inner = false;
	ct_cfg.direction[1].zone_match_mask = &r_zone_mask;
	ct_cfg.direction[1].meta_modify_mask = &r_modify_mask;

	rc = doca_flow_ct_init(&ct_cfg);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure initializing DOCA Flow CT: %s", doca_error_get_name(rc));
		doca_flow_destroy();
		return rc;
	}

	/* Initialize Ports */

	memset(dev_arr, 0, num_ports * sizeof(struct doca_dev *));
	dev_arr[0] = dev;

	for (port_id = 0; port_id < num_ports; port_id++) {
		enum doca_flow_port_operation_state state = DOCA_FLOW_PORT_OPERATION_STATE_ACTIVE;

		/* Create DOCA flow port */
		rc = start_doca_flow_port(port_id, dev_arr[port_id], state, &ports[port_id]);
		if (rc != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failure starting port: %s", doca_error_get_descr(rc));
			if (port_id != 0)
				stop_doca_flow_ports(port_id, ports);
			goto destroy;
		}
	}

	/* Create Pipes */

	rc = create_port_fwd_pipe(ports[0], app_context->enable_fwd, 0 /* port_id */, &ctrl_status, &port_fwd_pipe);
	if (rc != DOCA_SUCCESS)
		goto cleanup;
	num_entries++;

	rc = create_rss_pipe(ports[0], app_context->num_rss_queues, &ctrl_status, &rss_pipe);
	if (rc != DOCA_SUCCESS)
		goto cleanup;
	num_entries++;

	rc = create_flow_ct_pipe(ports[0], port_fwd_pipe, rss_pipe, &ct_pipe);
	if (rc != DOCA_SUCCESS)
		goto cleanup;
	num_entries++;

	app_context->ct_status->pipe = ct_pipe;

	rc = create_root_pipe(ports[0], ct_pipe, &ctrl_status, &root_pipe);
	if (rc != DOCA_SUCCESS)
		goto cleanup;
	num_entries++;

	if (ctrl_status.num_active != num_entries) {
		DOCA_LOG_ERR("Failure processing control path entries");
		rc = DOCA_ERROR_BAD_STATE;
		goto cleanup;
	}

	if (ctrl_status.failure) {
		DOCA_LOG_ERR("Failure processing control path entries");
		rc = DOCA_ERROR_BAD_STATE;
		goto cleanup;
	}

	/* Start capture loop */

	rc = run_capture(app_context, ports[0], ct_queue, 0 /* port_id */);
	if (rc != DOCA_SUCCESS)
		goto cleanup;

cleanup:
	if (ct_pipe != NULL)
		doca_flow_pipe_destroy(ct_pipe);

	rc = stop_doca_flow_ports(num_ports, ports);
	if (rc != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failure stopping DOCA Flow ports: %s", doca_error_get_descr(rc));

destroy:
	doca_flow_ct_destroy();
	doca_flow_destroy();

	return rc;
}

/*
 * Initialize DOCA Flow
 *
 * @num_queues: number of queues
 * @mode: DOCA flow mode
 * @callback: entry process callback
 */
doca_error_t init_doca_flow(int num_queues,
			    const char *mode,
			    doca_flow_entry_process_cb callback) {
	struct doca_flow_cfg *flow_cfg;
	u_int16_t queue_id;
	u_int16_t queues[num_queues];
	struct doca_flow_resource_rss_cfg rss = {0};
	doca_error_t rc, tmp_rc;
	int i;

	rc = doca_flow_cfg_create(&flow_cfg);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	for (queue_id = 0; queue_id < num_queues; queue_id++)
		queues[queue_id] = queue_id;

	rss.queues_array = queues;
	rss.nr_queues = num_queues;

	rc = doca_flow_cfg_set_default_rss(flow_cfg, &rss);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg RSS: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_cfg_set_pipe_queues(flow_cfg, num_queues);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg pipe_queues: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_cfg_set_mode_args(flow_cfg, mode);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg mode_args: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_cfg_set_nr_counters(flow_cfg, 1);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg nr_counters: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_cfg_set_nr_meters(flow_cfg, 0);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg nr_meters: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_cfg_set_cb_entry_process(flow_cfg, callback);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_cfg doca_flow_entry_process_cb: %s",
			     doca_error_get_descr(rc));
		goto destroy_cfg;
	}

	rc = doca_flow_init(flow_cfg);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure initializing DOCA Flow: %s", doca_error_get_descr(rc));
		goto destroy_cfg;
	}

destroy_cfg:
	tmp_rc = doca_flow_cfg_destroy(flow_cfg);
	if (tmp_rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure destroying cfg: %s", doca_error_get_descr(tmp_rc));
	}

	return rc;
}

/*
 * Create DOCA Flow port
 *
 * @port_id: port ID
 * @dev: DOCA device to attach
 * @state: port operation initial state
 * @port: port handler on success
 */
doca_error_t start_doca_flow_port(int port_id,
				  struct doca_dev *dev,
				  enum doca_flow_port_operation_state state,
				  struct doca_flow_port **port /* out */) {
	struct doca_flow_port_cfg *port_cfg;
	char port_id_str[128];
	doca_error_t rc;
	doca_error_t tmp_rc;

	rc = doca_flow_port_cfg_create(&port_cfg);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating doca_flow_port_cfg: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_port_cfg_set_dev(port_cfg, dev);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_port_cfg dev: %s", doca_error_get_descr(rc));
		goto destroy_port_cfg;
	}

	snprintf(port_id_str, sizeof(port_id_str), "%d", port_id);
	rc = doca_flow_port_cfg_set_devargs(port_cfg, port_id_str);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_port_cfg devargs: %s", doca_error_get_descr(rc));
		goto destroy_port_cfg;
	}

	rc = doca_flow_port_cfg_set_operation_state(port_cfg, state);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_port_cfg operation state: %s", doca_error_get_descr(rc));
		goto destroy_port_cfg;
	}

	rc = doca_flow_port_start(port_cfg, port);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure starting doca_flow port: %s", doca_error_get_descr(rc));
		goto destroy_port_cfg;
	}

destroy_port_cfg:
	tmp_rc = doca_flow_port_cfg_destroy(port_cfg);
	if (tmp_rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure destroying cfg: %s", doca_error_get_descr(tmp_rc));
	}

	return rc;
}

/*
 * Stop DOCA Flow ports
 */
doca_error_t stop_doca_flow_ports(int num_ports, struct doca_flow_port *ports[]) {
	int port_id;
	doca_error_t rc = DOCA_SUCCESS;
	doca_error_t tmp_rc;

	/* Note: stop port 0 as last (in switch mode port 0 is the proxy port) */
	for (port_id = num_ports-1; port_id >= 0; port_id--) {
		if (ports[port_id] != NULL) {
			tmp_rc = doca_flow_port_stop(ports[port_id]);
			if (tmp_rc != DOCA_SUCCESS) {
				if (rc == DOCA_SUCCESS)
					rc = tmp_rc;
			}
		}
	}
	return rc;
}

/*
 * Set DOCA Flow pipe configurations
 *
 * @cfg: DOCA Flow pipe configurations
 * @name: Pipe name
 * @type: Pipe type
 * @is_root: true if the pipe is a root pipe
 */
doca_error_t set_flow_pipe_cfg(struct doca_flow_pipe_cfg *cfg,
			       const char *name,
			       enum doca_flow_pipe_type type,
			       bool is_root) {
	doca_error_t rc;

	if (cfg == NULL) {
		DOCA_LOG_ERR("Failure setting DOCA Flow pipe configurations, cfg=NULL");
		return DOCA_ERROR_INVALID_VALUE;
	}

	rc = doca_flow_pipe_cfg_set_name(cfg, name);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg name: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_pipe_cfg_set_type(cfg, type);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg type: %s", doca_error_get_descr(rc));
		return rc;
	}

	rc = doca_flow_pipe_cfg_set_is_root(cfg, is_root);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure setting doca_flow_pipe_cfg is_root: %s", doca_error_get_descr(rc));
		return rc;
	}

	return rc;
}

/*
 * Initialize DPDK environment for DOCA Flow CT
 */
doca_error_t init_dpdk_env(int argc, char **dpdk_argv) {
	char *argv[argc + 2];
	int rc;

	memcpy(argv, dpdk_argv, sizeof(argv[0]) * argc);
	argv[argc++] = "-a";
	argv[argc++] = "pci:00:00.0";

	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		DOCA_LOG_ERR("Failure initializing DPDK EAL");
		return DOCA_ERROR_DRIVER;
	}

	return DOCA_SUCCESS;
}

/*
 * Destroy all DPDK ports
 */
void cleanup_dpdk_ports(struct dpdk_config *dpdk_config, u_int16_t num_ports) {
	int port_id;

	for (port_id = 0; port_id < num_ports; port_id++) {
		if (rte_eth_dev_is_valid_port(port_id)) {
			rte_eth_dev_stop(port_id);
			rte_eth_dev_close(port_id);
		}
	}

	if (dpdk_config->mbuf_pool != NULL)
		rte_mempool_free(dpdk_config->mbuf_pool);
}

/*
 * Initialize DPDK port
 */
doca_error_t init_dpdk_port(u_int8_t port_id,
			    struct rte_mempool *mbuf_pool,
			    struct dpdk_config *dpdk_config) {
	u_int16_t rx_rings = dpdk_config->num_queues;
	u_int16_t tx_rings = dpdk_config->num_queues;
	u_int16_t rss_support = !!(dpdk_config->rss_support && (dpdk_config->num_queues > 1));
	bool isolated = !!dpdk_config->isolated_mode;
	u_int16_t queue_id;
	struct rte_ether_addr addr;
	struct rte_eth_dev_info dev_info;
	struct rte_flow_error error;
	doca_error_t rc;
	int ret = 0;
	u_int8_t symmetric_rss_key[] = {
		0x2c, 0xc6, 0x81, 0xd1,
		0x5b, 0xdb, 0xf4, 0xf7,
		0xfc, 0xa2, 0x83, 0x19,
		0xdb, 0x1a, 0x3e, 0x94,
		0x6b, 0x9e, 0x38, 0xd9,
		0x2c, 0x9c, 0x03, 0xd1,
		0xad, 0x99, 0x44, 0xa7,
		0xd9, 0x56, 0x3d, 0x59,
		0x06, 0x3c, 0x25, 0xf3,
		0xfc, 0x1f, 0xdc, 0x2a,
	};
	const struct rte_eth_conf port_conf_default = {
		.lpbk_mode = 0,
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = symmetric_rss_key,
				.rss_key_len = RSS_KEY_LEN,
				.rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP),
			},
		},
	};
	struct rte_eth_conf port_conf = port_conf_default;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0) {
		DOCA_LOG_ERR("Failure getting port %u info: %s", port_id, strerror(-ret));
		return DOCA_ERROR_DRIVER;
	}

	if (*dev_info.dev_flags & RTE_ETH_DEV_REPRESENTOR && dpdk_config->switch_mode) {
		DOCA_LOG_INFO("Skipping representor port %d initialization (switch mode)", port_id);
		return DOCA_SUCCESS;
	}

	port_conf.rxmode.mq_mode = rss_support ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE;

	/* Configure eth device */
	ret = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
	if (ret < 0) {
		DOCA_LOG_ERR("Failure configuring the ethernet device (%d)", ret);
		return DOCA_ERROR_DRIVER;
	}

	/* Enable promiscuous mode */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret < 0) {
		DOCA_LOG_ERR("Failure enabling RX in promiscuous mode (%d)", ret);
		return DOCA_ERROR_DRIVER;
	}

	/* Setup RX queues */
	for (queue_id = 0; queue_id < rx_rings; queue_id++) {
		ret = rte_eth_rx_queue_setup(port_id, queue_id, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
		if (ret < 0) {
			DOCA_LOG_ERR("Failure setting up RX queues (%d)", ret);
			return DOCA_ERROR_DRIVER;
		}
	}

	/* Allocate and set up TX queues according to number of cores per Ethernet port */
	for (queue_id = 0; queue_id < tx_rings; queue_id++) {
		ret = rte_eth_tx_queue_setup(port_id, queue_id, TX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL);
		if (ret < 0) {
			DOCA_LOG_ERR("Failure setting up TX queues (%d)", ret);
			return DOCA_ERROR_DRIVER;
		}
	}

	/* Set isolated mode */
	ret = rte_flow_isolate(port_id, isolated, &error);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to %s isolated mode on port %u: %s",
			     isolated ? "set" : "unset", port_id, error.message);
		return DOCA_ERROR_DRIVER;
	}

	if (isolated)
		DOCA_LOG_INFO("Ingress traffic on port %u is in isolated mode", port_id);

	/* Start port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		DOCA_LOG_ERR("Failure starting port %" PRIu8 " (%d)", port_id, ret);
		return DOCA_ERROR_DRIVER;
	}

	/* Print MAC address */
	rte_eth_macaddr_get(port_id, &addr);
	DOCA_LOG_DBG("Port %u MAC: %02X:%02X:%02X:%02X:%02X:%02X", port_id,
		addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
		addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

	return DOCA_SUCCESS;
}

/*
 * Initialize all DPDK ports
 */
doca_error_t init_dpdk_ports(struct dpdk_config *dpdk_config) {
	u_int32_t mbuf_num;
	u_int32_t mbuf_size;
	u_int16_t port_id;
	u_int16_t n;
	doca_error_t rc;
	int ret;

	/* Check for available ports */
	n = rte_eth_dev_count_avail();
	if (n < dpdk_config->num_ports) {
		DOCA_LOG_ERR("Not enough ports. %u ports required, %d ports found.",
			     dpdk_config->num_ports, n);
		return DOCA_ERROR_DRIVER;
	}

	/* Check for available cores */
	n = rte_lcore_count();
	if (n < dpdk_config->num_queues) {
		DOCA_LOG_ERR("Not enough cores. %u cores required, %d cores available.",
			     dpdk_config->num_queues, n);
		return DOCA_ERROR_DRIVER;
	}
	dpdk_config->num_queues = n;

	/* Initialize mbufs mempool */
	mbuf_size = dpdk_config->mbuf_size ? dpdk_config->mbuf_size : RTE_MBUF_DEFAULT_BUF_SIZE;
	mbuf_num = dpdk_config->num_ports * dpdk_config->num_queues * NUM_MBUFS;
	dpdk_config->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", mbuf_num, MBUF_CACHE_SIZE, 0, mbuf_size, rte_socket_id());
	if (dpdk_config->mbuf_pool == NULL) {
		DOCA_LOG_ERR("Failure allocating mbuf pool");
		goto cleanup_ports;
	}

	/* Enable metadata to be delivered to application in the packets mbuf */
	if (dpdk_config->enable_mbuf_metadata) {
		ret = rte_flow_dynf_metadata_register();
		if (ret < 0) {
			DOCA_LOG_ERR("Failure registering metadata (%d)", ret);
			goto cleanup_ports;
		}
	}

	for (port_id = 0, n = 0; port_id < RTE_MAX_ETHPORTS && n < dpdk_config->num_ports; port_id++) {
		if (rte_eth_dev_is_valid_port(port_id)) {
			rc = init_dpdk_port(port_id, dpdk_config->mbuf_pool, dpdk_config);
			if (rc != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failure initializing port %u", port_id);
				cleanup_dpdk_ports(dpdk_config, port_id);
				return rc;
			}
			n++;
		}
	}

	return DOCA_SUCCESS;

cleanup_ports:
	cleanup_dpdk_ports(dpdk_config, RTE_MAX_ETHPORTS);
	return rc;
}

/*
 * Open a DOCA device according to a given PCI address
 */
doca_error_t open_doca_device_with_pci(const char *pci_addr,
				       struct doca_dev **retval /* out */) {
	struct doca_devinfo **dev_list;
	u_int32_t num_devs;
	u_int16_t i;
	u_int8_t is_equal = 0;
	int res;

	*retval = NULL;

	res = doca_devinfo_create_list(&dev_list, &num_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure loading DOCA devices list: %s", doca_error_get_descr(res));
		return res;
	}

	/* Device lookup */
	for (i = 0; i < num_devs; i++) {
		res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr, &is_equal);
		if (res == DOCA_SUCCESS && is_equal) {
			/* Check capabilities */
			if (doca_flow_ct_cap_is_dev_supported(dev_list[i]) != DOCA_SUCCESS) {
				char pci_addr_i[DOCA_DEVINFO_PCI_ADDR_SIZE];
				doca_devinfo_get_pci_addr_str(dev_list[i], pci_addr_i);
				DOCA_LOG_WARN("Required capabilities not available on %s", pci_addr_i);
				res = DOCA_ERROR_INVALID_VALUE;
				goto destroy_list;
			}

			/* Open device */
			res = doca_dev_open(dev_list[i], retval);

			goto destroy_list;
		}
	}

	DOCA_LOG_WARN("Unable to find device. Available devices:");

	for (i = 0; i < num_devs; i++) {
		char pci_addr_i[DOCA_DEVINFO_PCI_ADDR_SIZE];
		uint8_t mac_i[24];
		char name_i[256];

		doca_devinfo_get_pci_addr_str(dev_list[i], pci_addr_i);
		doca_devinfo_get_mac_addr(dev_list[i], mac_i, sizeof(mac_i));
		doca_devinfo_get_iface_name(dev_list[i], name_i, sizeof(name_i));

		DOCA_LOG_WARN("#%u addr=%s mac=%02X:%02X:%02X:%02X:%02X:%02X name=%s",
			i, pci_addr_i,
			mac_i[0], mac_i[1], mac_i[2], mac_i[3], mac_i[4], mac_i[5], 
			name_i);
	}

	res = DOCA_ERROR_NOT_FOUND;

destroy_list:
	doca_devinfo_destroy_list(dev_list);

	return res;
}

/*
 * Compute avg
 */
double avg_ns(u_int64_t counter_diff, u_int64_t ns_diff) {
	if (ns_diff == 0)
		return 0;

	return (double) counter_diff / ns_diff * 1000000000;
}

u_int64_t counter_diff(u_int64_t counter_now, u_int64_t counter_prev) {
	if (counter_now <= counter_prev)
		return 0;

	return counter_now - counter_prev;
}

/*
 * Dump port stats
 */
void dump_port_stats(struct app_context *app_context, u_int16_t port_id) {
	static u_int64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static u_int64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static u_int64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static u_int64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static u_int64_t prev_ns[RTE_MAX_ETHPORTS];
	u_int64_t diff_pkts_rx;
	u_int64_t diff_pkts_tx;
	u_int64_t diff_bytes_rx;
	u_int64_t diff_bytes_tx;
	u_int64_t diff_ns;
	u_int64_t mpps_rx;
	u_int64_t mpps_tx;
	u_int64_t mbps_rx;
	u_int64_t mbps_tx;
	struct rte_eth_stats port_stats;
	struct rte_eth_dev_info dev_info;
	u_int32_t num_rx_queues = RTE_ETHDEV_QUEUE_STAT_CNTRS;
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char top_left[] = { 27, '[', '1', ';', '1', 'H', '\0' };
	struct timespec now;
	u_int64_t now_ns;
	u_int32_t i;
	int rc;

	/* Clear screen */
	printf("%s%s", clr, top_left);

	rc = rte_eth_stats_get(port_id, &port_stats);
	if (rc != 0)
		return;

	rc = rte_eth_dev_info_get(port_id, &dev_info);
	if (rc != 0)
		return;

	if (dev_info.nb_rx_queues < RTE_ETHDEV_QUEUE_STAT_CNTRS)
		num_rx_queues = dev_info.nb_rx_queues;

	printf("\nPort %-2d abs stats:\n"
		"RX-packets:\t%12" PRIu64 "\n"
		"RX-missed:\t%12" PRIu64 "\n"
		"RX-bytes:\t%12" PRIu64 "\n"
		"RX-errors:\t%12" PRIu64 "\n"
		"RX-nombuf:\t%12" PRIu64 "\n"
		"TX-packets:\t%12" PRIu64 "\n"
		"TX-errors:\t%12" PRIu64 "\n"
		"TX-bytes:\t%12" PRIu64 "\n",
		port_id,
		port_stats.ipackets,
		port_stats.imissed,
		port_stats.ibytes,
		port_stats.ierrors,
		port_stats.rx_nombuf,
		port_stats.opackets,
		port_stats.oerrors,
		port_stats.obytes);

	if (app_context->verbosity > 2) {
		for (i = 0; i < num_rx_queues; i++) {
			printf("Queue %2d RX-packets: %" PRIu64 "  "
				"RX-errors: %" PRIu64 " "
				"RX-bytes: %" PRIu64 " "
				"TX-packets: %" PRIu64 " "
				"TX-bytes: %" PRIu64 "\n",
				i,
				port_stats.q_ipackets[i],
				port_stats.q_errors[i],
				port_stats.q_ibytes[i],
				port_stats.q_opackets[i],
				port_stats.q_obytes[i]);
		}
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	now_ns = SEC2NSEC(now.tv_sec) + now.tv_nsec;

	diff_ns = 0;
	if (prev_ns[port_id] != 0)
		diff_ns = now_ns - prev_ns[port_id];

	prev_ns[port_id] = now_ns;

	diff_pkts_rx = counter_diff(port_stats.ipackets, prev_pkts_rx[port_id]);
	diff_pkts_tx = counter_diff(port_stats.opackets, prev_pkts_tx[port_id]);
	diff_bytes_rx = counter_diff(port_stats.ibytes, prev_bytes_rx[port_id]);
	diff_bytes_tx = counter_diff(port_stats.obytes, prev_bytes_tx[port_id]);

	prev_pkts_rx[port_id] = port_stats.ipackets;
	prev_pkts_tx[port_id] = port_stats.opackets;
	prev_bytes_rx[port_id] = port_stats.ibytes;
	prev_bytes_tx[port_id] = port_stats.obytes;

	mpps_rx = avg_ns(diff_pkts_rx, diff_ns);
	mpps_tx = avg_ns(diff_pkts_tx, diff_ns);
	mbps_rx = avg_ns(diff_bytes_rx, diff_ns);
	mbps_tx = avg_ns(diff_bytes_tx, diff_ns);

	printf("\nThroughput\n"
		"RX-pps:\t%12" PRIu64 "\n"
		"RX-bps:\t%12" PRIu64 "\n"
		"TX-pps:\t%12" PRIu64 "\n"
		"TX-bps:\t%12" PRIu64 "\n",
		mpps_rx,
		mbps_rx * 8,
		mpps_tx,
		mbps_tx * 8);
}

/*
 * Print stats
 */
void print_stats() {
	struct app_context *app_context = &app_ctx;
	int port_id;
	char sep = ' ';

	if (app_context->verbosity > 1) {
		for (port_id = 0; port_id < app_context->num_ports; port_id++)
			dump_port_stats(app_context, port_id);

		sep = '\n';

		printf("\nFlow Stats\n");
	}

	printf(	"allocated=%d%c"
		"active=%u%c"
		"expired=%d%c"
		"deleted=%d%c"
		"updated=%d%c"
		"failures=%u%c"
		"packets=%" PRIu64 "\n",
		app_context->ct_status->num_allocated, sep,
		app_context->ct_status->num_active, sep,
		app_context->ct_status->num_expired, sep,
		app_context->ct_status->num_deleted, sep,
		app_context->ct_status->num_updated, sep,
		app_context->ct_status->num_mem_fail, sep,
		app_context->num_total_packets);

	fflush(stdout);
}

/*
 * Sigterm handler
 */
void sigproc_handler(int sig) {
	static int called = 0;
	struct app_context *app_context = &app_ctx;

	fprintf(stderr, "Shutting down...\n");

	if (called)
		return;
	else
		called = 1;

	app_context->do_shutdown = true;

	print_stats();
}

/*
 * Sigalarm handler (stats)
 */
void sigalarm_handler(int sig) {
	struct app_context *app_context = &app_ctx;

	if (app_context->do_shutdown)
		return;

	print_stats();

	signal(SIGALRM, sigalarm_handler);
	alarm(STATS_FREQ_SEC);
}

/*
 * Set DOCA Flow CT device PCI address parameter
 */
doca_error_t set_pci_addr(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;
	const char *pci_addr = (char *) param;
	int len;

	len = strnlen(pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE);
	if (len >= DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d",
			     DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strncpy(app_context->dev_pci_addr[app_context->num_ports++], pci_addr, len + 1);

	return DOCA_SUCCESS;
}

/*
 * Set number of RSS queues
 */
doca_error_t set_rss_queues(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;
	int *rss_queues_ptr = (int *) param;

	app_context->num_rss_queues = *rss_queues_ptr;
	if (app_context->num_rss_queues < 1)
		app_context->num_rss_queues = 1;

	return DOCA_SUCCESS;
}

/*
 * Set flow idle timeout
 */
doca_error_t set_idle_timeout(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;
	int *idle_timeout_ptr = (int *) param;

	app_context->idle_timeout = *idle_timeout_ptr;

	return DOCA_SUCCESS;
}

/*
 * Set packet forwarding
 */
doca_error_t set_fwd(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;

	app_context->enable_fwd = true;

	return DOCA_SUCCESS;
}

/*
 * Set software flow table
 */
doca_error_t set_sw_ct(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;

	app_context->enable_sw_ct = true;

	return DOCA_SUCCESS;
}

/*
 * Set flow export
 */
doca_error_t set_flow_export(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;

	app_context->enable_export = true;

	return DOCA_SUCCESS;
}

/*
 * Set flow idle timeout
 */
doca_error_t set_verbosity(void *param, void *config) {
	struct app_context *app_context = (struct app_context *) config;
	int *verbose_ptr = (int *) param;

	app_context->verbosity = *verbose_ptr;

	return DOCA_SUCCESS;
}

/*
 * Create/register single argument
 */
doca_error_t register_doca_param(const char *short_name,
				 const char *long_name,
				 const char *description,
				 doca_argp_param_cb_t callback,
				 enum doca_argp_type type,
				 u_int8_t mandatory,
				 u_int8_t multiplicity) {
	struct doca_argp_param *param;
	doca_error_t rc;

	/* PCI addr */

	rc = doca_argp_param_create(&param);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure creating param: %s", doca_error_get_descr(rc));
		return rc;
	}

	doca_argp_param_set_short_name(param, short_name);
	doca_argp_param_set_long_name(param, long_name);
	doca_argp_param_set_description(param, description);
	doca_argp_param_set_callback(param, callback);
	doca_argp_param_set_type(param, type);

	if (mandatory)
		doca_argp_param_set_mandatory(param);

	if (multiplicity)
		doca_argp_param_set_multiplicity(param);

	rc = doca_argp_register_param(param);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure registering param -%s|--%s: %s",
			short_name, long_name, doca_error_get_descr(rc));
		return rc;
	}

	return rc;
}

/*
 * Create/register application arguments
 */
doca_error_t register_doca_params() {
	struct doca_argp_param *param;
	doca_error_t rc;

	/* PCI addr */
	register_doca_param("p", "pci-addr", "DOCA Flow CT device PCI address",
		set_pci_addr, DOCA_ARGP_TYPE_STRING, 1, 1);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* RSS queues */
	register_doca_param("r", "rss-queues", "Number of RSS queues (default: 1)",
		set_rss_queues, DOCA_ARGP_TYPE_INT, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* Idle timeout */
	register_doca_param("d", "idle-timeout", "Maximum (seconds) flow idle lifetime (default: 60)",
		set_idle_timeout, DOCA_ARGP_TYPE_INT, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* Enable fwd */
	register_doca_param("w", "enable-fwd", "Enable packet forwarding",
		set_fwd, DOCA_ARGP_TYPE_BOOLEAN, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* Enable sw flow table */
	register_doca_param("s", "enable-sw-ct", "Enable software (shadow) flow table",
		set_sw_ct, DOCA_ARGP_TYPE_BOOLEAN, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* Enable flow export */
	register_doca_param("e", "enable-flow-export", "Print flow updates periodically (requires -s) and at flow expiration",
		set_flow_export, DOCA_ARGP_TYPE_BOOLEAN, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	/* Verbosity */
	register_doca_param("t", "verbose", "Trace verbosity level (0..3) (default: 1)",
		set_verbosity, DOCA_ARGP_TYPE_INT, 0, 0);
	if (rc != DOCA_SUCCESS)
		return rc;

	return DOCA_SUCCESS;
}

/*
 * Main
 */
int main(int argc, char **argv) {
	struct doca_log_backend *sdk_log;
	struct doca_dev *dev = NULL;
	struct pipe_entries_status ct_status = { 0 };
	doca_error_t rc;
	int return_code = EXIT_FAILURE;
	struct app_context *app_context = &app_ctx;
	struct rte_hash_parameters sw_ct_params = {
		.name = "sw_ct",
		.entries = MAX_NUM_FLOWS*2,
		.key_len = sizeof(struct doca_flow_ct_match),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = SOCKET_ID_ANY
	};
	struct dpdk_config dpdk_config = {
		.num_ports = 2,
		.num_queues = 2,
		.isolated_mode = 1,
		.switch_mode = 1
	};

	app_context->idle_timeout = DEFAULT_IDLE_TIMEOUT;
	app_context->ct_status = &ct_status;
	app_context->verbosity = 1;
	app_context->num_rss_queues = 1;

	/* Read parameters */

	rc = doca_argp_init("kryptonite", app_context);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure initializing ARGP resources: %s", doca_error_get_descr(rc));
		goto exit;
	}

	doca_argp_set_dpdk_program(init_dpdk_env);

	rc = register_doca_params();
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure registering parameters: %s", doca_error_get_descr(rc));
		goto cleanup_dpdk;
	}

	rc = doca_argp_start(argc, argv);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure parsing input: %s", doca_error_get_descr(rc));
		goto cleanup_dpdk;
	}

	dpdk_config.num_queues = app_context->num_rss_queues + 1;
	ct_status.export_on_delete = app_context->enable_export;

	/* Create logger for DOCA warnings */

	if (app_context->verbosity > 0) {
		rc = doca_log_backend_create_standard();
		if (rc != DOCA_SUCCESS)
			goto cleanup_argp;

		rc = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
		if (rc != DOCA_SUCCESS)
			goto cleanup_argp;

		rc = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
		if (rc != DOCA_SUCCESS)
			goto cleanup_argp;
	}

	if (app_context->num_rss_queues > 1)
		DOCA_LOG_WARN("Multiple RSS queues configured, but only the first one will be polled");

	/* Allocate software flow table */

	if (app_context->enable_sw_ct) {
		ct_status.sw_ct = rte_hash_create(&sw_ct_params);
		if (ct_status.sw_ct == NULL) {
			DOCA_LOG_ERR("Failure allocating software flow table");
			goto cleanup_argp;
		}
	}

	/* Open device */

	rc = open_doca_device_with_pci(app_context->dev_pci_addr[0], &dev);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure opening Flow CT device: %s", doca_error_get_descr(rc));
		goto cleanup_sw_ct;
	}

	rc = doca_dpdk_port_probe(dev, FLOW_CT_DEVARGS);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure opening Flow CT device: %s", doca_error_get_descr(rc));
		goto cleanup_device;
	}

	rc = init_dpdk_ports(&dpdk_config);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure initializing ports");
		goto cleanup_device;
	}

	/* Setup signals */
	signal(SIGINT, sigproc_handler);
	signal(SIGTERM, sigproc_handler);

	signal(SIGALRM, sigalarm_handler);
	alarm(STATS_FREQ_SEC+2);

	/* Run DOCA Flow CT */

	rc = run_flow_ct(app_context, dpdk_config.num_queues, dev);
	if (rc != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failure running pipeline: %s", doca_error_get_descr(rc));
		goto cleanup_ports;
	}

	return_code = EXIT_SUCCESS;

cleanup_ports:
	cleanup_dpdk_ports(&dpdk_config, RTE_MAX_ETHPORTS);
cleanup_device:
	doca_dev_close(dev);
cleanup_sw_ct:
	if (ct_status.sw_ct)
		rte_hash_free(ct_status.sw_ct);
cleanup_argp:
	doca_argp_destroy();
cleanup_dpdk:
	rte_eal_cleanup();
exit:
	return return_code;
}

