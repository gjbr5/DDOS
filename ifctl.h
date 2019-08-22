#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

in_addr_t get_my_ip(const char *interface);

in_addr_t translate_ip(const char arrIP[4]);
in_addr_t translate_ip(const uint8_t arrIP[4]);
in_addr_t translate_ip(const int8_t arrIP[4]);

void translate_ip(in_addr_t ip, uint8_t arrIP[4]);
