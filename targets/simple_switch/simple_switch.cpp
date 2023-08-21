/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas
 *
 */

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include "direct_pipeline/direct_tables.hpp"
#include "simple_switch.h"
#include "register_access.h"
#include <bf_lpm_trie/bf_lpm_trie.h>
#include "direct_pipeline/direct_packet.hpp"
#include "direct_pipeline/direct_tables.hpp"
#include "direct_pipeline/ubpf_common.hpp"

// #define DIRECT_PACKET_LOGGING

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives(SimpleSwitch *simple_switch);

packet_id_t SimpleSwitch::packet_id = 0;

class SimpleSwitch::MirroringSessions {
 public:
  bool add_session(mirror_id_t mirror_id,
                   const MirroringSessionConfig &config) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      sessions_map[mirror_id] = config;
      return true;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session added.");
      return false;
    }
  }

  bool delete_session(mirror_id_t mirror_id) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      return sessions_map.erase(mirror_id) == 1;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session deleted.");
      return false;
    }
  }

  bool get_session(mirror_id_t mirror_id,
                   MirroringSessionConfig *config) const {
    Lock lock(mutex);
    auto it = sessions_map.find(mirror_id);
    if (it == sessions_map.end()) return false;
    *config = it->second;
    return true;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable std::mutex mutex;
  std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal packets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class SimpleSwitch::InputBuffer {
 public:
  enum class PacketType {
    NORMAL,
    RESUBMIT,
    RECIRCULATE,
    SENTINEL  // signal for the ingress thread to terminate
  };

  InputBuffer(size_t capacity_hi, size_t capacity_lo)
      : capacity_hi(capacity_hi), capacity_lo(capacity_lo) { }

  int push_front(PacketType packet_type, std::unique_ptr<DirectPacket> &&item) {
    switch (packet_type) {
      case PacketType::NORMAL:
        return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo,
                          std::move(item), true);
      case PacketType::RESUBMIT:
      case PacketType::RECIRCULATE:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), false);
      case PacketType::SENTINEL:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), true);
    }
    _BM_UNREACHABLE("Unreachable statement");
    return 0;
  }

  void pop_back(std::unique_ptr<DirectPacket> *pItem) {
    Lock lock(mutex);
    cvar_can_pop.wait(
        lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
    // give higher priority to resubmit/recirculate queue
    if (queue_hi.size() > 0) {
      *pItem = std::move(queue_hi.back());
      queue_hi.pop_back();
      lock.unlock();
      cvar_can_push_hi.notify_one();
    } else {
      *pItem = std::move(queue_lo.back());
      queue_lo.pop_back();
      lock.unlock();
      cvar_can_push_lo.notify_one();
    }
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;
  using QueueImpl = std::deque<std::unique_ptr<DirectPacket> >;

  int push_front(QueueImpl *queue, size_t capacity,
                 std::condition_variable *cvar,
                 std::unique_ptr<DirectPacket> &&item, bool blocking) {
    Lock lock(mutex);
    while (queue->size() == capacity) {
      if (!blocking) return 0;
      cvar->wait(lock);
    }
    queue->push_front(std::move(item));
    lock.unlock();
    cvar_can_pop.notify_one();
    return 1;
  }

  mutable std::mutex mutex;
  mutable std::condition_variable cvar_can_push_hi;
  mutable std::condition_variable cvar_can_push_lo;
  mutable std::condition_variable cvar_can_pop;
  size_t capacity_hi;
  size_t capacity_lo;
  QueueImpl queue_hi;
  QueueImpl queue_lo;
};

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port,
                           size_t nb_queues_per_port)
  : Switch(enable_swap),
    drop_port(drop_port),
    input_buffer(new InputBuffer(
        1024 /* normal capacity */, 1024 /* resubmit/recirc capacity */)),
    nb_queues_per_port(nb_queues_per_port),
    egress_buffers(nb_egress_threads,
                   64, EgressThreadMapper(nb_egress_threads),
                   nb_queues_per_port),
    output_buffer(128),
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    pre(new McSimplePreLAG()),
    start(clock::now()),
    mirroring_sessions(new MirroringSessions()) {
  add_component<McSimplePreLAG>(pre);

  add_required_field("standard_metadata", "ingress_port");
  add_required_field("standard_metadata", "packet_length");
  add_required_field("standard_metadata", "instance_type");
  add_required_field("standard_metadata", "egress_spec");
  add_required_field("standard_metadata", "egress_port");

  force_arith_header("standard_metadata");
  force_arith_header("queueing_metadata");
  force_arith_header("intrinsic_metadata");

  import_primitives(this);

  /* Initialize tables */

  // Ingress table forward
  direct_ingress_forward_key in_forward_key;
  direct_ingress_forward_value in_forward_value;
  // table_add forward set_dmac 10.0.0.10 => 00:04:00:00:00:00
  in_forward_key = {0x0a00000a};
  in_forward_value = {
    direct_ingress_action_set_dmac,
    {.set_dmac={0x000400000000}}
  };
  ingress_forward.add_entry(&in_forward_key, &in_forward_value);
  // table_add forward set_dmac 10.0.1.10 => 00:04:00:00:00:01
  in_forward_key = {0x0a00010a};
  in_forward_value = {
    direct_ingress_action_set_dmac,
    {.set_dmac={0x000400000001}}
  };
  ingress_forward.add_entry(&in_forward_key, &in_forward_value);

  // Ingress table ipv4_lpm
  direct_ingress_ipv4_lpm_key in_ipv4_lpm_key;
  direct_ingress_ipv4_lpm_value in_ipv4_lpm_value;
  // table_add ipv4_lpm set_nhop 10.0.0.10/32 => 10.0.0.10 1
  in_ipv4_lpm_key = {0x0a00000a, 32};
  in_ipv4_lpm_value = {
    direct_ingress_action_set_nhop,
    {.set_nhop={0x0a00000a, 1}}
  };
  ingress_ipv4_lpm.add_entry(&in_ipv4_lpm_key, &in_ipv4_lpm_value);
  // table_add ipv4_lpm set_nhop 10.0.1.10/32 => 10.0.1.10 2
  in_ipv4_lpm_key = {0x0a00010a, 32};
  in_ipv4_lpm_value = {
    direct_ingress_action_set_nhop,
    {.set_nhop={0x0a00010a, 2}}
  };
  ingress_ipv4_lpm.add_entry(&in_ipv4_lpm_key, &in_ipv4_lpm_value);

  // Egress table send_frame
  direct_egress_send_frame_key eg_send_frame_key;
  direct_egress_send_frame_value eg_send_frame_value;
  // table_add send_frame rewrite_mac 1 => 00:aa:bb:00:00:00
  eg_send_frame_key = {1};
  eg_send_frame_value = {
    direct_egress_action_rewrite_mac,
    {.rewrite_mac={0x00aabb000000}}
  };
  egress_send_frame.add_entry(&eg_send_frame_key, &eg_send_frame_value);
  // table_add send_frame rewrite_mac 2 => 00:aa:bb:00:00:01
  eg_send_frame_key = {2};
  eg_send_frame_value = {
    direct_egress_action_rewrite_mac,
    {.rewrite_mac={0x00aabb000001}}
  };
  egress_send_frame.add_entry(&eg_send_frame_key, &eg_send_frame_value);
}

int
SimpleSwitch::receive_(port_t port_num, const char *buffer, int len) {
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  /*
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();
  RegisterAccess::clear_all(packet.get());

  // setting standard metadata

  phv->get_field("standard_metadata.ingress_port").set(port_num);
  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
  phv->get_field("standard_metadata.packet_length").set(len);
  Field &f_instance_type = phv->get_field("standard_metadata.instance_type");
  f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

  if (phv->has_field("intrinsic_metadata.ingress_global_timestamp")) {
    phv->get_field("intrinsic_metadata.ingress_global_timestamp")
        .set(get_ts().count());
  }

  input_buffer->push_front(
      InputBuffer::PacketType::NORMAL, std::move(packet));

  */

  auto dir_packet = std::unique_ptr<DirectPacket>(new DirectPacket(
    port_num, packet_id++, buffer, len
  ));

#ifdef DIRECT_PACKET_LOGGING
  dir_packet->set_log_file("/tmp/dp.log");
#endif

  input_buffer->push_front(
      InputBuffer::PacketType::NORMAL, std::move(dir_packet));
  return 0;
}

void
SimpleSwitch::start_and_return_() {
  check_queueing_metadata();

  threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
  for (size_t i = 0; i < nb_egress_threads; i++) {
    threads_.push_back(std::thread(&SimpleSwitch::egress_thread, this, i));
  }
  threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
}

void
SimpleSwitch::swap_notify_() {
  bm::Logger::get()->debug(
      "simple_switch target has been notified of a config swap");
  check_queueing_metadata();
}

SimpleSwitch::~SimpleSwitch() {
  input_buffer->push_front(
      InputBuffer::PacketType::SENTINEL, nullptr);
  for (size_t i = 0; i < nb_egress_threads; i++) {
    // The push_front call is called inside a while loop because there is no
    // guarantee that the sentinel was enqueued otherwise. It should not be an
    // issue because at this stage the ingress thread has been sent a signal to
    // stop, and only egress clones can be sent to the buffer.
    while (egress_buffers.push_front(i, 0, nullptr) == 0) continue;
  }
  output_buffer.push_front(nullptr);
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
SimpleSwitch::reset_target_state_() {
  bm::Logger::get()->debug("Resetting simple_switch target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

bool
SimpleSwitch::mirroring_add_session(mirror_id_t mirror_id,
                                    const MirroringSessionConfig &config) {
  return mirroring_sessions->add_session(mirror_id, config);
}

bool
SimpleSwitch::mirroring_delete_session(mirror_id_t mirror_id) {
  return mirroring_sessions->delete_session(mirror_id);
}

bool
SimpleSwitch::mirroring_get_session(mirror_id_t mirror_id,
                                    MirroringSessionConfig *config) const {
  return mirroring_sessions->get_session(mirror_id, config);
}

int
SimpleSwitch::set_egress_priority_queue_depth(size_t port, size_t priority,
                                              const size_t depth_pkts) {
  egress_buffers.set_capacity(port, priority, depth_pkts);
  return 0;
}

int
SimpleSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts) {
  egress_buffers.set_capacity(port, depth_pkts);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_depths(const size_t depth_pkts) {
  egress_buffers.set_capacity_for_all(depth_pkts);
  return 0;
}

int
SimpleSwitch::set_egress_priority_queue_rate(size_t port, size_t priority,
                                             const uint64_t rate_pps) {
  egress_buffers.set_rate(port, priority, rate_pps);
  return 0;
}

int
SimpleSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps) {
  egress_buffers.set_rate(port, rate_pps);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_rates(const uint64_t rate_pps) {
  egress_buffers.set_rate_for_all(rate_pps);
  return 0;
}

uint64_t
SimpleSwitch::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
SimpleSwitch::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
SimpleSwitch::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}

void
SimpleSwitch::transmit_thread() {
  while (1) {
    // std::unique_ptr<Packet> packet;
    // output_buffer.pop_back(&packet);
    // if (packet == nullptr) break;
    // BMELOG(packet_out, *packet);
    // BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
    //                 packet->get_data_size(), packet->get_egress_port());
    // my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
    //                packet->data(), packet->get_data_size());
    std::unique_ptr<DirectPacket> dir_packet;
    output_buffer.pop_back(&dir_packet);
    if (dir_packet == nullptr) break;
    dir_packet->log("before transmission");
    my_transmit_fn(dir_packet->standard_metadata.egress_port,
                   dir_packet->id,
                   dir_packet->bytes.data(),
                   dir_packet->bytes.size());

    dir_packet->log("after transmission");
  }
}

ts_res
SimpleSwitch::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}

void
SimpleSwitch::enqueue(port_t egress_port, std::unique_ptr<DirectPacket> &&dir_packet) {
    // packet->set_egress_port(egress_port);

    // PHV *phv = packet->get_phv();

    // if (with_queueing_metadata) {
    //   phv->get_field("queueing_metadata.enq_timestamp").set(get_ts().count());
    //   phv->get_field("queueing_metadata.enq_qdepth")
    //       .set(egress_buffers.size(egress_port));
    // }

    // size_t priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
    //     phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    // if (priority >= nb_queues_per_port) {
    //   bm::Logger::get()->error("Priority out of range, dropping packet");
    //   return;
    // }
    // egress_buffers.push_front(
    //     egress_port, nb_queues_per_port - 1 - priority,
    //     std::move(packet));

  dir_packet->standard_metadata.egress_port = egress_port;
  egress_buffers.push_front(
      egress_port, nb_queues_per_port - 1 - 0u,
      std::move(dir_packet));
}

// used for ingress cloning, resubmit
void
SimpleSwitch::copy_field_list_and_set_type(
    const std::unique_ptr<DirectPacket> &packet,
    const std::unique_ptr<DirectPacket> &packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id) {
  // PHV *phv_copy = packet_copy->get_phv();
  // phv_copy->reset_metadata();
  // FieldList *field_list = this->get_field_list(field_list_id);
  // field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
  // phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void
SimpleSwitch::check_queueing_metadata() {
  // TODO(antonin): add qid in required fields
  bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
  bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
  bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
  bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
  if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e) {
    if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e) {
      with_queueing_metadata = true;
      return;
    } else {
      bm::Logger::get()->warn(
          "Your JSON input defines some but not all queueing metadata fields");
    }
  }
  with_queueing_metadata = false;
}

void
SimpleSwitch::multicast(DirectPacket *packet, unsigned int mgid) {
  // auto *phv = packet->get_phv();
  // auto &f_rid = phv->get_field("intrinsic_metadata.egress_rid");
  // const auto pre_out = pre->replicate({mgid});
  // auto packet_size =
  //     packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
  // for (const auto &out : pre_out) {
  //   auto egress_port = out.egress_port;
  //   BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
  //   f_rid.set(out.rid);
  //   std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
  //   RegisterAccess::clear_all(packet_copy.get());
  //   packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
  //                             packet_size);
  //   enqueue(egress_port, std::move(packet_copy));
  // }
}

#define BPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((uint8_t*)a) = ((*((uint8_t*)a)) & ~(BPF_MASK(uint8_t, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(uint8_t*)((base) + (offset)) = (v); } while (0)

static uint32_t
bpf_htonl(uint32_t val) {
    return htonl(val);
}
static uint16_t
bpf_htons(uint16_t val) {
    return htons(val);
}
static uint64_t
bpf_htonll(uint64_t val) {
    return htonll(val);
}

static bool direct_parse(std::unique_ptr<DirectPacket> &dir_packet) {
  unsigned char *pkt = (unsigned char*) dir_packet->bytes.data();

  auto &packetOffsetInBits = dir_packet->packetOffsetInBits;
  auto &headers = dir_packet->headers;
  headers = {
    .ethernet = {
      .valid = 0
    },
    .ipv4 = {
      .valid = 0
    }
  };

  headers.ethernet.dstAddr = (uint64_t)((load_dword(pkt, BYTES(packetOffsetInBits)) >> 16) & BPF_MASK(uint64_t, 48));
  packetOffsetInBits += 48;

  headers.ethernet.srcAddr = (uint64_t)((load_dword(pkt, BYTES(packetOffsetInBits)) >> 16) & BPF_MASK(uint64_t, 48));
  packetOffsetInBits += 48;

  headers.ethernet.etherType = (uint16_t)((load_half(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 16;

  headers.ethernet.valid = 1;
  uint16_t select_0;
  select_0 = headers.ethernet.etherType;
  if (select_0 == 0x800)goto ipv4;
  else goto accept;

ipv4:
  headers.ipv4.version = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits)) >> 4) & BPF_MASK(uint8_t, 4));
  packetOffsetInBits += 4;

  headers.ipv4.ihl = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits))) & BPF_MASK(uint8_t, 4));
  packetOffsetInBits += 4;

  headers.ipv4.diffserv = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 8;

  headers.ipv4.totalLen = (uint16_t)((load_half(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 16;

  headers.ipv4.identification = (uint16_t)((load_half(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 16;

  headers.ipv4.flags = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits)) >> 5) & BPF_MASK(uint8_t, 3));
  packetOffsetInBits += 3;

  headers.ipv4.fragOffset = (uint16_t)((load_half(pkt, BYTES(packetOffsetInBits))) & BPF_MASK(uint16_t, 13));
  packetOffsetInBits += 13;

  headers.ipv4.ttl = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 8;

  headers.ipv4.protocol = (uint8_t)((load_byte(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 8;

  headers.ipv4.hdrChecksum = (uint16_t)((load_half(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 16;

  headers.ipv4.srcAddr = (uint32_t)((load_word(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 32;

  headers.ipv4.dstAddr = (uint32_t)((load_word(pkt, BYTES(packetOffsetInBits))));
  packetOffsetInBits += 32;

  headers.ipv4.valid = 1;
  goto accept;

accept:
  return true;
reject:
  return false;
}

static bool direct_deparse(std::unique_ptr<DirectPacket> &dir_packet) {
  unsigned char *pkt = (unsigned char*) dir_packet->bytes.data();
  auto &packetOffsetInBits = dir_packet->packetOffsetInBits;
  auto &headers = dir_packet->headers;
  unsigned char ebpf_byte;

  int outHeaderLength = 0;
  {
    if (headers.ethernet.valid) 
      outHeaderLength += 112;
    if (headers.ipv4.valid) 
      outHeaderLength += 160;
  }
  int outHeaderOffset = BYTES(outHeaderLength) - BYTES(packetOffsetInBits);
  pkt -= outHeaderOffset;
  packetOffsetInBits = 0;

  if (headers.ethernet.valid) {
    headers.ethernet.dstAddr = htonll(headers.ethernet.dstAddr << 16);
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[2];
    write_byte(pkt, BYTES(packetOffsetInBits) + 2, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[3];
    write_byte(pkt, BYTES(packetOffsetInBits) + 3, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[4];
    write_byte(pkt, BYTES(packetOffsetInBits) + 4, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.dstAddr))[5];
    write_byte(pkt, BYTES(packetOffsetInBits) + 5, (ebpf_byte));
    packetOffsetInBits += 48;

    headers.ethernet.srcAddr = htonll(headers.ethernet.srcAddr << 16);
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[2];
    write_byte(pkt, BYTES(packetOffsetInBits) + 2, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[3];
    write_byte(pkt, BYTES(packetOffsetInBits) + 3, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[4];
    write_byte(pkt, BYTES(packetOffsetInBits) + 4, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.srcAddr))[5];
    write_byte(pkt, BYTES(packetOffsetInBits) + 5, (ebpf_byte));
    packetOffsetInBits += 48;

    headers.ethernet.etherType = bpf_htons(headers.ethernet.etherType);
    ebpf_byte = ((char*)(&headers.ethernet.etherType))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ethernet.etherType))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    packetOffsetInBits += 16;
  }
  if (headers.ipv4.valid) {
    ebpf_byte = ((char*)(&headers.ipv4.version))[0];
    write_partial(pkt + BYTES(packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
    packetOffsetInBits += 4;

    ebpf_byte = ((char*)(&headers.ipv4.ihl))[0];
    write_partial(pkt + BYTES(packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
    packetOffsetInBits += 4;

    ebpf_byte = ((char*)(&headers.ipv4.diffserv))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    packetOffsetInBits += 8;

    headers.ipv4.totalLen = bpf_htons(headers.ipv4.totalLen);
    ebpf_byte = ((char*)(&headers.ipv4.totalLen))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.totalLen))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    packetOffsetInBits += 16;

    headers.ipv4.identification = bpf_htons(headers.ipv4.identification);
    ebpf_byte = ((char*)(&headers.ipv4.identification))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.identification))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    packetOffsetInBits += 16;

    ebpf_byte = ((char*)(&headers.ipv4.flags))[0];
    write_partial(pkt + BYTES(packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
    packetOffsetInBits += 3;

    headers.ipv4.fragOffset = bpf_htons(headers.ipv4.fragOffset << 3);
    ebpf_byte = ((char*)(&headers.ipv4.fragOffset))[0];
    write_partial(pkt + BYTES(packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
    write_partial(pkt + BYTES(packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.fragOffset))[1];
    write_partial(pkt + BYTES(packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
    packetOffsetInBits += 13;

    ebpf_byte = ((char*)(&headers.ipv4.ttl))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    packetOffsetInBits += 8;

    ebpf_byte = ((char*)(&headers.ipv4.protocol))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    packetOffsetInBits += 8;

    headers.ipv4.hdrChecksum = bpf_htons(headers.ipv4.hdrChecksum);
    ebpf_byte = ((char*)(&headers.ipv4.hdrChecksum))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.hdrChecksum))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    packetOffsetInBits += 16;

    headers.ipv4.srcAddr = htonl(headers.ipv4.srcAddr);
    ebpf_byte = ((char*)(&headers.ipv4.srcAddr))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.srcAddr))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.srcAddr))[2];
    write_byte(pkt, BYTES(packetOffsetInBits) + 2, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.srcAddr))[3];
    write_byte(pkt, BYTES(packetOffsetInBits) + 3, (ebpf_byte));
    packetOffsetInBits += 32;

    headers.ipv4.dstAddr = htonl(headers.ipv4.dstAddr);
    ebpf_byte = ((char*)(&headers.ipv4.dstAddr))[0];
    write_byte(pkt, BYTES(packetOffsetInBits) + 0, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.dstAddr))[1];
    write_byte(pkt, BYTES(packetOffsetInBits) + 1, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.dstAddr))[2];
    write_byte(pkt, BYTES(packetOffsetInBits) + 2, (ebpf_byte));
    ebpf_byte = ((char*)(&headers.ipv4.dstAddr))[3];
    write_byte(pkt, BYTES(packetOffsetInBits) + 3, (ebpf_byte));
    packetOffsetInBits += 32;
  }

accept:
  return true;
reject:
  return false;
}

void
SimpleSwitch::ingress_thread() {
  PHV *phv;

  while (1) {

    std::unique_ptr<DirectPacket> dir_packet;
    input_buffer->pop_back(&dir_packet);
    if (dir_packet == nullptr) break;

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("before ingress");
#endif

    // parse
    direct_parse(dir_packet);
    dir_packet->verify_checksum();

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("after parsing");
#endif

    // ingress pipeline
    if (dir_packet->headers.ipv4.valid && dir_packet->headers.ipv4.ttl > 0) {
      ingress_ipv4_lpm.apply(dir_packet);
      ingress_forward.apply(dir_packet);
    }

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("after ingress pipeline");
#endif

    port_t egress_port = dir_packet->standard_metadata.egress_spec;

    if (egress_port == drop_port) {  // drop packet
      continue;
    }
    dir_packet->standard_metadata.instance_type = PKT_INSTANCE_TYPE_NORMAL;

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("after ingress");
#endif

    enqueue(egress_port, std::move(dir_packet));

    // OLD STUFF

    // std::unique_ptr<Packet> packet;
    // input_buffer->pop_back(&packet);
    // if (packet == nullptr) break;

    // // TODO(antonin): only update these if swapping actually happened?
    // Parser *parser = this->get_parser("parser");
    // Pipeline *ingress_mau = this->get_pipeline("ingress");

    // phv = packet->get_phv();

    // port_t ingress_port = packet->get_ingress_port();
    // (void) ingress_port;
    // BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
    //                 ingress_port);

    // auto ingress_packet_size =
    //     packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    // /* This looks like it comes out of the blue. However this is needed for
    //    ingress cloning. The parser updates the buffer state (pops the parsed
    //    headers) to make the deparser's job easier (the same buffer is
    //    re-used). But for ingress cloning, the original packet is needed. This
    //    kind of looks hacky though. Maybe a better solution would be to have the
    //    parser leave the buffer unchanged, and move the pop logic to the
    //    deparser. TODO? */
    // const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();
    // parser->parse(packet.get());

    // if (phv->has_field("standard_metadata.parser_error")) {
    //   phv->get_field("standard_metadata.parser_error").set(
    //       packet->get_error_code().get());
    // }

    // if (phv->has_field("standard_metadata.checksum_error")) {
    //   phv->get_field("standard_metadata.checksum_error").set(
    //        packet->get_checksum_error() ? 1 : 0);
    // }

    // ingress_mau->apply(packet.get());

    // packet->reset_exit();

    // Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    // port_t egress_spec = f_egress_spec.get_uint();

    // // Removed: ingress cloning, learning, resubmit, multicast

    // port_t egress_port = egress_spec;
    // BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

    // if (egress_port == drop_port) {  // drop packet
    //   BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
    //   continue;
    // }
    // auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
    // f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    // enqueue(egress_port, std::move(packet));
  }
}

void
SimpleSwitch::egress_thread(size_t worker_id) {
  while (1) {
    size_t port;
    size_t priority;
    std::unique_ptr<DirectPacket> dir_packet;
    egress_buffers.pop_back(worker_id, &port, &priority, &dir_packet);
    if (dir_packet == nullptr) break;

    dir_packet->standard_metadata.egress_port = port;

    // When egress_spec == drop_port the packet will be dropped, thus
    // here we initialize egress_spec to a value different from drop_port.
    dir_packet->standard_metadata.egress_spec = drop_port + 1;

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("before egress");
#endif

    // egress pipeline
    egress_send_frame.apply(dir_packet);

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("after egress pipeline");
#endif

    if (dir_packet->standard_metadata.egress_spec == drop_port) {  // drop packet
      continue;
    }

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("before deparsing");
#endif

    // deparse
    direct_deparse(dir_packet);
    dir_packet->update_checksum();

#ifdef DIRECT_PACKET_LOGGING
    dir_packet->log("after egress");
#endif

    output_buffer.push_front(std::move(dir_packet));

    // OLD STUFF

    // std::unique_ptr<Packet> packet;
    // size_t port;
    // size_t priority;
    // egress_buffers.pop_back(worker_id, &port, &priority, &packet);
    // if (packet == nullptr) break;

    // Deparser *deparser = this->get_deparser("deparser");
    // Pipeline *egress_mau = this->get_pipeline("egress");

    // phv = packet->get_phv();

    // if (phv->has_field("intrinsic_metadata.egress_global_timestamp")) {
    //   phv->get_field("intrinsic_metadata.egress_global_timestamp")
    //       .set(get_ts().count());
    // }

    // if (with_queueing_metadata) {
    //   auto enq_timestamp =
    //       phv->get_field("queueing_metadata.enq_timestamp").get<ts_res::rep>();
    //   phv->get_field("queueing_metadata.deq_timedelta").set(
    //       get_ts().count() - enq_timestamp);
    //   phv->get_field("queueing_metadata.deq_qdepth").set(
    //       egress_buffers.size(port));
    //   if (phv->has_field("queueing_metadata.qid")) {
    //     auto &qid_f = phv->get_field("queueing_metadata.qid");
    //     qid_f.set(nb_queues_per_port - 1 - priority);
    //   }
    // }

    // phv->get_field("standard_metadata.egress_port").set(port);

    // Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    // // When egress_spec == drop_port the packet will be dropped, thus
    // // here we initialize egress_spec to a value different from drop_port.
    // f_egress_spec.set(drop_port + 1);

    // phv->get_field("standard_metadata.packet_length").set(
    //     packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    // egress_mau->apply(packet.get());

    // // Removed: egress cloning

    // // TODO(antonin): should not be done like this in egress pipeline
    // port_t egress_spec = f_egress_spec.get_uint();
    // if (egress_spec == drop_port) {  // drop packet
    //   BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
    //   continue;
    // }

    // deparser->deparse(packet.get());

    // // Removed: recirculate

    // output_buffer.push_front(std::move(packet));
  }
}
