#include "packet_filter.h"

PacketClass packet_classification(const uint8_t *packet)
{
    /**************Packet Parsing********************/

    const Ethernet *eth_h = reinterpret_cast<const Ethernet *>(packet);

    if (ntohs(eth_h->type) == ETHERTYPE_ARP)
        return PacketClass::ARP;
    if (ntohs(eth_h->type) != ETHERTYPE_IP) {
        std::cout << "Cannot Classify\n";
        return PacketClass::UNCLASSIFIED;
    }

    /************************************************/

    /************Packet Classification***************/

    const Ip *ip_h = reinterpret_cast<const Ip *>(packet + sizeof(Ethernet));

    if (ip_h->protocol == IPPROTO_ICMP) {
        std::cout << "ICMP\n";
        return PacketClass::ICMP;
    } else if (ip_h->protocol == IPPROTO_IGMP) {
        std::cout << "IGMP\n";
        return PacketClass::IGMP;
    } else if (ip_h->protocol == IPPROTO_TCP) {
        std::cout << "TCP\n";
        return PacketClass::TCP;
    } else if (ip_h->protocol == IPPROTO_UDP) {
        std::cout << "UDP\n";
        return PacketClass::UDP;
    } else {
        std::cout << "IP\n";
        return PacketClass::IP;
    }

    /************************************************/
}

AttackClass detect_attack(const uint8_t *packet, std::set<in_addr_t> blacklist, in_addr_t my_ip)
{
    /**************Packet Parsing********************/

    const Ip *ip_h = reinterpret_cast<const Ip *>(packet + sizeof(Ethernet));
    int ip_size = (ip_h->VHL & 0x0F) << 2;
    int total_size = ntohs(ip_h->Total_LEN);

    const Tcp *tcp_h = reinterpret_cast<const Tcp *>(packet + sizeof(Ethernet) + ip_size);
    int tcp_size = (tcp_h->OFF & 0xF0) >> 2;

    const uint8_t *payload = packet + sizeof(Ethernet) + ip_size + tcp_size;
    int payload_len = total_size - ip_size - tcp_size;

    /************Check Ip in Black List**************/

    if (blacklist.find(translate_ip(ip_h->s_ip)) != blacklist.end()) {
        std::cout << "Find Black List\n";
        std::cout << "Drop packet\n";
        return AttackClass::BLACKLIST;
    }

    /************************************************/

    /******************Land Attack*******************/

    if (translate_ip(ip_h->d_ip) == translate_ip(ip_h->s_ip)) {
        std::cout << "Land Attack\n";
        std::cout << "Drop packet\n"; // Cannot Add blacklist!
        return AttackClass::LAND_ATTACK;
    }
    /************************************************/

    uint16_t d_port = ntohs(tcp_h->d_port);
    uint8_t flag = (tcp_h->flag & 0x3F);

    /************************************************/

    /*****************Port Scan*******************/

    // if not 20, 21, 22, 53, 80, 443
    if (d_port != P_20 && d_port != P_21 && d_port != P_22 && d_port != P_53 && d_port != P_80
        && d_port != P_443) {
        blacklist.insert(translate_ip(ip_h->s_ip));
        std::cout << std::ios::hex;
        std::cout << "port : " << ((d_port >> 8) & 0xff) << (d_port & 0xff) << "\n";
        std::cout << "flag : " << flag << "\n";
        std::cout << "AddBlackList\n";
        std::cout << std::ios::dec;
        return AttackClass::PORT_SCAN;
    }

    /*********************************************/

    /***********XMAS or NULL Flag Attack**********/

    if (flag == XMAS || flag == 0) {
        blacklist.insert(translate_ip(ip_h->s_ip));
        std::cout << std::ios::hex;
        std::cout << "flag: " << flag << "\n";
        std::cout << "AddBlackList\n";
        std::cout << std::ios::dec;
        return AttackClass::ABNORMAL_FLAG;
    }

    /*********************************************/

    /*************Tsunami Flood Attack************/

    if (flag != PSH && flag != ACK && flag != PSH + ACK
        && total_size > 80) // PSH, ACK, PSH + ACK, Packet SIZE
    {
        blacklist.insert(translate_ip(ip_h->s_ip));
        std::cout << std::ios::hex;
        std::cout << "flag: " << flag << "\n";
        std::cout << std::ios::dec;
        std::cout << "IP Packet size: " << total_size << "bytes\n";
        std::cout << "AddBlackList\n";
        return AttackClass::TSUNAMI;
    }

    /*********************************************/

    return AttackClass::ACCEPT;
}
