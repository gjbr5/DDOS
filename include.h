#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <net/if.h>
#include <set>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <sys/ioctl.h>

#include "packet_filter.h"
#include "ifctl.h"
#include "protocol_structure.h"
