#ifndef DIRECT_PIPELINE_DIRECT_PACKET_H_
#define DIRECT_PIPELINE_DIRECT_PACKET_H_

#include <stdint.h>
#include <vector>
#include <fstream>
#include <string>
#include <iomanip>
#include "ubpf_common.hpp"

struct standard_metadata_t {
  uint16_t ingress_port; /* bit<9> */
  uint32_t packet_length; /* bit<32> */
  uint16_t egress_spec; /* bit<9> */
  uint16_t egress_port; /* bit<9> */
  uint32_t egress_instance; /* bit<32> */
  uint32_t instance_type; /* bit<32> */
  uint32_t clone_spec; /* bit<32> */
  uint8_t padding; /* bit<5> */
};

struct Ethernet_h {
  uint64_t dstAddr; /* EthernetAddress */
  uint64_t srcAddr; /* EthernetAddress */
  uint16_t etherType; /* bit<16> */
  uint8_t valid;
};

struct IPv4_h {
  uint8_t version; /* bit<4> */
  uint8_t ihl; /* bit<4> */
  uint8_t diffserv; /* bit<8> */
  uint16_t totalLen; /* bit<16> */
  uint16_t identification; /* bit<16> */
  uint8_t flags; /* bit<3> */
  uint16_t fragOffset; /* bit<13> */
  uint8_t ttl; /* bit<8> */
  uint8_t protocol; /* bit<8> */
  uint16_t hdrChecksum; /* bit<16> */
  uint32_t srcAddr; /* IPv4Address */
  uint32_t dstAddr; /* IPv4Address */
  uint8_t valid;
};

struct routing_metadata_t {
  uint32_t nhop_ipv4; /* bit<32> */
};

struct Headers_t {
  struct Ethernet_h ethernet; /* Ethernet_h */
  struct IPv4_h ipv4; /* IPv4_h */
};

struct DirectPacket {
  Headers_t headers;
  standard_metadata_t standard_metadata;
  routing_metadata_t routing_metadata;
  std::vector<char> bytes;
  unsigned long id;
  std::ofstream logfile;
  int packetOffsetInBits;

  DirectPacket(uint16_t ingress_port, unsigned long id, const char *buffer, int len)
    : id(id), bytes(buffer, buffer + len), packetOffsetInBits(0),
      headers({0}), standard_metadata({0}), routing_metadata({0})
  {
    standard_metadata.ingress_port = ingress_port;
  }

  ~DirectPacket() {
    if (logfile.is_open()) {
      logfile.close();
    }
  }

  void set_log_file(std::string path) {
    logfile.open(path, std::ofstream::app);
  }

  void log(std::string note) {
    if (!logfile.is_open()) {
      return;
    }

    logfile << "=== PACKET " << id << " (" << note << ") ===\n";
    logfile << "ingress_port = " << standard_metadata.ingress_port << std::endl;
    logfile << "egress_spec  = " << standard_metadata.egress_spec << std::endl;
    logfile << "egress_port  = " << standard_metadata.egress_port << std::endl;

    logfile << std::hex;
    logfile << "ethDst = " << headers.ethernet.dstAddr << std::endl;
    logfile << "ethSrc = " << headers.ethernet.srcAddr << std::endl;
    logfile << "ipDst  = " << headers.ipv4.dstAddr << std::endl;
    logfile << "ipSrc  = " << headers.ipv4.srcAddr << std::endl;

    for (int i = 0; i < bytes.size(); i++) {
      logfile << std::setfill('0') << std::setw(2) << ((int)bytes[i] & 0xff) << ' ';
    }
    logfile << std::dec << std::endl;

  }

  bool verify_checksum() {
    uint16_t *ipv4 = (uint16_t *)(bytes.data() + (48+48+16)/8);
    uint32_t sum = 0;
    for (int i = 0; i < 10; i++) {
      sum += ntohs(ipv4[i]);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (~sum) & 0xffff;

    return sum == 0;
  }

  void update_checksum() {
    uint16_t *ipv4 = (uint16_t *)(bytes.data() + (48+48+16)/8);
    uint32_t sum = 0;
    for (int i = 0; i < 10; i++) {
      sum += ntohs(ipv4[i]) * (i != 5);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (~sum) & 0xffff;

    ipv4[5] = htons((uint16_t)sum);
  }
};

#endif
