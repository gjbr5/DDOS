#include "include.h"

static char ** global_argv;

static std::set<in_addr_t> blacklist;
static in_addr_t my_ip;

/* returns verdict */
static u_int32_t verdict(struct nfq_data *tb)
{
    // Get Packet Data
    u_char *packet = nullptr;
    nfq_get_payload(tb, &packet);

    printf("\n------------------------------------------\n");

    PacketClass num = packet_classification(packet);
    switch (num) {
    case PacketClass::TCP:
        if (detect_tcp_attack(packet, blacklist, my_ip) != AttackClass::ACCEPT) // if drop packet;
        {
            printf("Drop\n");
            return NF_DROP;
        }
        break;
    case PacketClass::ICMP:
        //        if (detect_icmp_attack(packet, blacklist, my_ip) != AttackClass::ACCEPT) {
        //            printf("Drop\n");
        //            return NF_DROP;
        //        }
        break;
    case PacketClass::UDP:
        break;
    case PacketClass::IGMP:
    case PacketClass::IP:
    case PacketClass::ARP:
    case PacketClass::UNCLASSIFIED:
        break;
    }

    //***********************************************************
    fputc('\n', stdout);

    return NF_ACCEPT;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
        id = ntohl(ph->packet_id);
    u_int32_t NF_VERDICT = verdict(nfa);

    return nfq_set_verdict(qh, id, NF_VERDICT, 0, nullptr);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    if (argc < 2)
        return 0;
    global_argv = argv;

    // Get My IP
    my_ip = get_my_ip(argv[1]);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    for (;;) {
        if ((rv = static_cast<int>(recv(fd, buf, sizeof(buf), 0))) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
