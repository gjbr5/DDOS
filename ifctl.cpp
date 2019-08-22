#include "ifctl.h"

in_addr_t get_my_ip(const char *interface)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, sizeof(interface) - 1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        throw "Invalid Interface";
    close(sock);

    return translate_ip(ifr.ifr_addr.sa_data + 2);
}

in_addr_t translate_ip(const char arrIP[4])
{
    return *(reinterpret_cast<const in_addr_t *>(arrIP));
}

in_addr_t translate_ip(const uint8_t arrIP[4])
{
    return *(reinterpret_cast<const in_addr_t *>(arrIP));
}
in_addr_t translate_ip(const int8_t arrIP[4])
{
    return *(reinterpret_cast<const in_addr_t *>(arrIP));
}

void translate_ip(in_addr_t ip, uint8_t arrIP[4])
{
    *(reinterpret_cast<in_addr_t *>(arrIP)) = ip;
}
