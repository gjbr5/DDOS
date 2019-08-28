#include "packet_filter.h"

PacketClass packet_classification(const uint8_t *packet)
{
    /**************Packet Parsing********************/

    //    const Ethernet *eth_h = reinterpret_cast<const Ethernet *>(packet);

    //    if (ntohs(eth_h->type) == ETHERTYPE_ARP)
    //        return PacketClass::ARP;
    //    if (ntohs(eth_h->type) != ETHERTYPE_IP) {
    //        printf("Cannot Classify\n");
    //        return PacketClass::UNCLASSIFIED;
    //    }

    /************************************************/

    /************Packet Classification***************/

    const Ip *ip_h = reinterpret_cast<const Ip *>(packet);

    if (ip_h->protocol == IPPROTO_ICMP) {
        printf("ICMP\n");
        return PacketClass::ICMP;
    } else if (ip_h->protocol == IPPROTO_IGMP) {
        printf("IGMP\n");
        return PacketClass::IGMP;
    } else if (ip_h->protocol == IPPROTO_TCP) {
        printf("TCP\n");
        return PacketClass::TCP;
    } else if (ip_h->protocol == IPPROTO_UDP) {
        printf("UDP\n");
        return PacketClass::UDP;
    } else {
        printf("IP\n");
        return PacketClass::IP;
    }

    /************************************************/
}

AttackClass detect_tcp_attack(const uint8_t *packet, std::set<in_addr_t> &blacklist, in_addr_t my_ip)
{
    /**************Packet Parsing********************/

    const Ip *ip_h = reinterpret_cast<const Ip *>(packet);
    int ip_size = (ip_h->VHL & 0x0F) << 2;
    int total_size = ntohs(ip_h->Total_LEN);

    const Tcp *tcp_h = reinterpret_cast<const Tcp *>(packet + ip_size);
    int tcp_size = (tcp_h->OFF & 0xF0) >> 2;

    const uint8_t *payload = packet + ip_size + tcp_size;
    int payload_len = total_size - ip_size - tcp_size;

    /************Check Ip in Black List**************/

    in_addr_t sip = translate_ip(ip_h->s_ip);
    printf("sip: %u.%u.%u.%u\n", ip_h->s_ip[0], ip_h->s_ip[1], ip_h->s_ip[2], ip_h->s_ip[3]);

    if (blacklist.find(sip) != blacklist.end()) {
        printf("Find Black List\n");
        printf("Drop packet\n");
        return AttackClass::BLACKLIST;
    }

    /************************************************/

    /******************Land Attack*******************/

    if (sip == my_ip) {
        printf("Land Attack\n");
        printf("Drop packet\n"); // Cannot Add blacklist!
        return AttackClass::LAND_ATTACK;
    }
    /************************************************/

    uint16_t d_port = ntohs(tcp_h->d_port);
    uint8_t flag = (tcp_h->flag & 0x3F);

    printf("port = %04x\n", d_port);

    /************************************************/

    /*****************Port Scan*******************/

    // if not 20, 21, 22, 53, 80, 443
    if (d_port != PORT_FTP_DATA && d_port != PORT_FTP_CONTROL && d_port != PORT_SSH
        && d_port != PORT_DNS && d_port != PORT_HTTP && d_port != PORT_HTTPS) {
        blacklist.insert(sip);
        printf("port : %x%x\n", ((d_port >> 8) & 0xff), (d_port & 0xff));
        printf("flag: %02x \n", flag);
        printf("AddBlackList\n");
        return AttackClass::PORT_SCAN;
    }

    /*********************************************/

    /***********XMAS or NULL Flag Attack**********/

    if (flag == XMAS || flag == 0) {
        blacklist.insert(sip);
        printf("flag: %02x\n", flag);
        printf("AddBlackList\n");
        return AttackClass::ABNORMAL_FLAG;
    }

    /*********************************************/

    /*************Tsunami Flood Attack************/

    if (flag != PSH && flag != ACK && flag != (PSH | ACK)
        && total_size > 80) // PSH, ACK, PSH + ACK, Packet SIZE
    {
        blacklist.insert(sip);
        printf("flag: %02x\n", flag);
        printf("IP Packet size: %dbytes\n", total_size);
        printf("AddBlackList\n");
        return AttackClass::TSUNAMI;
    }

    /*********************************************/

    return AttackClass::ACCEPT;
}

//AttackClass detect_icmp_attack(const uint8_t *packet,
//                               std::set<in_addr_t> &blacklist,
//                               in_addr_t my_ip)
//{
//    /**************Packet Parsing********************/

//    const Ip *ip_h = reinterpret_cast<const Ip *>(packet);
//    int ip_size = (ip_h->VHL & 0x0F) << 2;
//    int total_size = ntohs(ip_h->Total_LEN);

//    const Icmp *icmp_h = reinterpret_cast<const Icmp *>(packet + ip_size);

//    /************Check Ip in Black List**************/

//    in_addr_t sip = translate_ip(ip_h->s_ip);
//    printf("sip: %u.%u.%u.%u\n", ip_h->s_ip[0], ip_h->s_ip[1], ip_h->s_ip[2], ip_h->s_ip[3]);

//    if (blacklist.find(sip) != blacklist.end()) {
//        printf("Find Black List\n");
//        printf("Drop packet\n");
//        return AttackClass::BLACKLIST;
//    }

//    /************************************************/

//    /******************Land Attack*******************/

//    if (sip == my_ip) {
//        printf("Land Attack\n");
//        printf("Drop packet\n"); // Cannot Add blacklist!
//        return AttackClass::LAND_ATTACK;
//    }
//    /************************************************/
//}
