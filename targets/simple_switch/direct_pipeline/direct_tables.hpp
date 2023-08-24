#ifndef DIRECT_PIPELINE_DIRECT_TABLES_H_
#define DIRECT_PIPELINE_DIRECT_TABLES_H_

#include <memory>
#include <stdint.h>
#include <unordered_map>
#include <bf_lpm_trie/bf_lpm_trie.h>
#include "direct_packet.hpp"
#include "ubpf_common.hpp"

#define DIRECT_DROP_PORT 511

enum direct_ingress_actions {
  direct_ingress_action_set_dmac,
  direct_ingress_action__drop,
  direct_ingress_action_set_nhop,
};
enum direct_egress_actions {
  direct_egress_action_rewrite_mac,
  direct_egress_action__drop,
};

/* Ingress: table forward */

struct direct_ingress_forward_key {
  uint32_t routing_metadata_nhop_ipv4; /* bit<32> */
};
struct direct_ingress_forward_value {
  enum direct_ingress_actions action;
  union {
    struct {
      uint64_t dmac; /* bit<48> */
    } set_dmac;
    struct {
    } _drop;
  } u;
};
class direct_ingress_forward_table {
public:
  void add_entry(void *key, void *value);
  void apply(std::unique_ptr<DirectPacket> &dir_packet);
private:
  std::unordered_map<uint32_t, direct_ingress_forward_value> exact_routing_metadata_nhop_ipv4;
};

/* Ingress: table ipv4_lpm */

struct direct_ingress_ipv4_lpm_key {
  uint32_t headers_ipv4_dstAddr; /* bit<32> */
  unsigned int headers_ipv4_dstAddr_mask;
};
struct direct_ingress_ipv4_lpm_value {
  enum direct_ingress_actions action;
  union {
    struct {
      uint32_t nhop_ipv4; /* bit<32> */
      uint16_t port; /* bit<9> */
    } set_nhop;
    struct {
    } _drop;
  } u;
};
class direct_ingress_ipv4_lpm_table {
public:
  direct_ingress_ipv4_lpm_table();
  ~direct_ingress_ipv4_lpm_table();
  void add_entry(void *key, void *value);
  void apply(std::unique_ptr<DirectPacket> &dir_packet);
private:
  bf_lpm_trie_t *lpm; // the values of the trie nodes are indices to lpm_values
  std::vector<direct_ingress_ipv4_lpm_value> lpm_values;
};

/* Egress: table send_frame */

struct direct_egress_send_frame_key {
  uint16_t standard_metadata_egress_port;
};
struct direct_egress_send_frame_value {
  enum direct_egress_actions action;
  union {
    struct {
      uint64_t smac; /* bit<48> */
    } rewrite_mac;
    struct {
    } _drop;
  } u;
};
class direct_egress_send_frame_table {
public:
  void add_entry(void *key, void *value);
  void apply(std::unique_ptr<DirectPacket> &dir_packet);
private:
  std::unordered_map<uint16_t, direct_egress_send_frame_value> exact_standard_metadata_egress_port;
};

#endif
