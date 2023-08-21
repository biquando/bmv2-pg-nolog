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
    void add_entry(void *key, void *value) {
        direct_ingress_forward_key *k = (direct_ingress_forward_key *) key;
        direct_ingress_forward_value *v = (direct_ingress_forward_value *) value;

        exact_routing_metadata_nhop_ipv4[k->routing_metadata_nhop_ipv4] = *v;
    }
    void apply(std::unique_ptr<DirectPacket> &dir_packet) {
        direct_ingress_forward_key key = {
            dir_packet->routing_metadata.nhop_ipv4,
        };

        auto it = exact_routing_metadata_nhop_ipv4.find(key.routing_metadata_nhop_ipv4);
        direct_ingress_forward_value value;
        if (it == exact_routing_metadata_nhop_ipv4.end()) { // if no entries match the key
            value.action = direct_ingress_action__drop;  // TODO: allow user to set default action
        } else {
            value = it->second;
        }

        switch (value.action) {
        case direct_ingress_action_set_dmac:
            dir_packet->headers.ethernet.dstAddr = value.u.set_dmac.dmac;
            break;
        case direct_ingress_action__drop:
        default:
            dir_packet->standard_metadata.egress_spec = DIRECT_DROP_PORT;
            break;
        }
    }
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
    direct_ingress_ipv4_lpm_table() {
        lpm = bf_lpm_trie_create(4, false);
    }
    ~direct_ingress_ipv4_lpm_table() {
        bf_lpm_trie_destroy(lpm);
    }
    void add_entry(void *key, void *value) {
        direct_ingress_ipv4_lpm_key *k = (direct_ingress_ipv4_lpm_key *) key;
        direct_ingress_ipv4_lpm_value *v = (direct_ingress_ipv4_lpm_value *) value;

        int idx = lpm_values.size();
        lpm_values.push_back(*v);

        uint32_t prefix = htonl(k->headers_ipv4_dstAddr);
        bf_lpm_trie_insert(lpm, (char *)&prefix, k->headers_ipv4_dstAddr_mask, idx);
    }
    void apply(std::unique_ptr<DirectPacket> &dir_packet) {
        value_t idx = -1;
        uint32_t prefix = htonl(dir_packet->headers.ipv4.dstAddr);
        bf_lpm_trie_lookup(lpm, (char*)(&prefix), &idx);

        direct_ingress_ipv4_lpm_value value;
        if (idx < 0) {
            value.action = direct_ingress_action__drop;
        } else {
            value = lpm_values[idx];
        }

        switch (value.action) {
        case direct_ingress_action_set_nhop:
            dir_packet->routing_metadata.nhop_ipv4 = value.u.set_nhop.nhop_ipv4;
            dir_packet->standard_metadata.egress_spec = value.u.set_nhop.port;
            dir_packet->headers.ipv4.ttl = dir_packet->headers.ipv4.ttl - 1;
            break;
        case direct_ingress_action__drop:
        default:
            dir_packet->standard_metadata.egress_spec = DIRECT_DROP_PORT;
            break;
        }
    }
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
    void add_entry(void *key, void *value) {
        direct_egress_send_frame_key *k = (direct_egress_send_frame_key *) key;
        direct_egress_send_frame_value *v = (direct_egress_send_frame_value *) value;

        exact_standard_metadata_egress_port[k->standard_metadata_egress_port] = *v;
    }
    void apply(std::unique_ptr<DirectPacket> &dir_packet) {
        direct_egress_send_frame_key key = {
            dir_packet->standard_metadata.egress_port,
        };

        auto it = exact_standard_metadata_egress_port.find(key.standard_metadata_egress_port);
        direct_egress_send_frame_value value;
        if (it == exact_standard_metadata_egress_port.end()) { // if no entries match the key
            value.action = direct_egress_action__drop;
        } else {
            value = it->second;
        }

        switch (value.action) {
        case direct_egress_action_rewrite_mac:
            dir_packet->headers.ethernet.srcAddr = value.u.rewrite_mac.smac;
            break;
        case direct_egress_action__drop:
        default:
            dir_packet->standard_metadata.egress_spec = DIRECT_DROP_PORT;
            break;
        }
    }
private:
    std::unordered_map<uint16_t, direct_egress_send_frame_value> exact_standard_metadata_egress_port;
};

#endif
