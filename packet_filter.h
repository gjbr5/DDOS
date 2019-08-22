#pragma once

#include "include.h"

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define XMAS 0x3f
#define P_20 0x0014
#define P_21 0x0015
#define P_22 0x0016
#define P_53 0x0035
#define P_80 0x0050
#define P_443 0x01bb

enum PacketClass { UNCLASSIFIED, ARP, IP, ICMP, IGMP, TCP, UDP };
enum AttackClass { ACCEPT, BLACKLIST, LAND_ATTACK, PORT_SCAN, ABNORMAL_FLAG, TSUNAMI };
PacketClass packet_classification(const uint8_t *packet);
AttackClass detect_attack(const uint8_t *packet, std::set<in_addr_t> blacklist, in_addr_t my_ip);
