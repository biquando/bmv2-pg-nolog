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

  DirectPacket(uint16_t ingress_port, unsigned long id, const char *buffer, int len);
  ~DirectPacket();

  void set_log_file(std::string path);
  void log(std::string note);
  bool verify_checksum();
  void update_checksum();
};

#endif
