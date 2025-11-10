#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define echoes_error(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

typedef struct
{
    uint8_t t_protocol;
    char *source_ip_addr;
    char *dest_ip_addr;
    uint16_t source_port;
    uint16_t dest_port;
    char *source_if_name;
    char *dest_if_name;
    uint8_t source_mac[6];
    uint8_t dest_mac[6];
    int source_mac_set;
    int dest_mac_set;
} echoes_filter_t;

void echoes_get_mac(const char *if_name, echoes_filter_t *filter, const char *type)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        echoes_error("Echoes couldn't resonate socket");
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(fd);
        echoes_error("Echoes couldn't feel MAC vibrations");
    }
    close(fd);
    if (strcmp(type, "source") == 0)
    {
        memcpy(filter->source_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);
        filter->source_mac_set = 1;
    }
    else
    {
        memcpy(filter->dest_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);
        filter->dest_mac_set = 1;
    }
}

void echoes_eth_header(struct ethhdr *eth, FILE *logfile)
{
    fprintf(logfile, "\n[Echoes Act 1] MAC Resonance Initiated:\n");
    fprintf(logfile, "   Source MAC → %02X-%02X-%02X-%02X-%02X-%02X\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "   Destination MAC → %02X-%02X-%02X-%02X-%02X-%02X\n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, "   Protocol Energy → 0x%04X\n", ntohs(eth->h_proto));
}

void echoes_ip_header(struct iphdr *ip, FILE *logfile)
{
    struct sockaddr_in s, d;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    memset(&s, 0, sizeof(s));
    memset(&d, 0, sizeof(d));
    s.sin_addr.s_addr = ip->saddr;
    d.sin_addr.s_addr = ip->daddr;

    inet_ntop(AF_INET, &s.sin_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &d.sin_addr, dst_ip, INET_ADDRSTRLEN);

    fprintf(logfile, "\n[Echoes Act 2] IP Waves Detected:\n");
    fprintf(logfile, "   Source IP → %s\n", src_ip);
    fprintf(logfile, "   Destination IP → %s\n", dst_ip);
    fprintf(logfile, "   Protocol Type → %d | TTL → %d\n", ip->protocol, ip->ttl);
}

void echoes_tcp(struct tcphdr *tcp, FILE *logfile)
{
    fprintf(logfile, "\n[Echoes Act 3] TCP Pulse!\n");
    fprintf(logfile, "   Source Port → %u\n", ntohs(tcp->source));
    fprintf(logfile, "   Destination Port → %u\n", ntohs(tcp->dest));
    fprintf(logfile, "   Sequence → %u | ACK → %u\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    fprintf(logfile, "   Flags [SYN:%d ACK:%d PSH:%d FIN:%d RST:%d]\n",
            tcp->syn, tcp->ack, tcp->psh, tcp->fin, tcp->rst);
}

void echoes_udp(struct udphdr *udp, FILE *logfile)
{
    fprintf(logfile, "\n[Echoes Act 3] UDP Reverb Detected!\n");
    fprintf(logfile, "   Source Port → %u | Destination Port → %u\n",
            ntohs(udp->source), ntohs(udp->dest));
}

void echoes_payload(uint8_t *buf, int len, int iphdrlen, uint8_t proto, FILE *log, struct tcphdr *tcp)
{
    uint32_t phsize = sizeof(struct udphdr);
    if (proto == IPPROTO_TCP && tcp != NULL)
        phsize = (uint32_t)tcp->doff * 4;
    uint8_t *data = buf + sizeof(struct ethhdr) + iphdrlen + phsize;
    int remain = len - (sizeof(struct ethhdr) + iphdrlen + phsize);
    fprintf(log, "\n[Echoes] Data Resonance → ");
    if (remain > 0)
    {
        for (int i = 0; i < remain; i++)
        {
            if (i && i % 16 == 0)
                fprintf(log, "\n");
            fprintf(log, "%02X ", data[i]);
        }
        fprintf(log, "\n");
    }
    else
        fprintf(log, "No Payload Detected.\n");
}

void echoes_process(uint8_t *buf, int len, echoes_filter_t *f, FILE *log)
{
    if (len < (int)sizeof(struct ethhdr))
        return;
    struct ethhdr *eth = (struct ethhdr *)buf;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;
    if (f->source_mac_set && memcmp(f->source_mac, eth->h_source, 6) != 0)
        return;
    if (f->dest_mac_set && memcmp(f->dest_mac, eth->h_dest, 6) != 0)
        return;

    if (len < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
        return;

    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
    int ihl = ip->ihl * 4;

    if (ihl < 20 || len < (int)(sizeof(struct ethhdr) + ihl))
        return;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;

    src_addr.s_addr = ip->saddr;
    dst_addr.s_addr = ip->daddr;
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    if (f->source_ip_addr && strcmp(f->source_ip_addr, src_ip) != 0)
        return;
    if (f->dest_ip_addr && strcmp(f->dest_ip_addr, dst_ip) != 0)
        return;
    if (f->t_protocol && ip->protocol != f->t_protocol)
        return;

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    uint16_t sp = 0, dp = 0;

    if (ip->protocol == IPPROTO_TCP)
    {
        if (len < (int)(sizeof(struct ethhdr) + ihl + sizeof(struct tcphdr)))
            return;
        tcp = (struct tcphdr *)(buf + sizeof(struct ethhdr) + ihl);
        sp = ntohs(tcp->source);
        dp = ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        if (len < (int)(sizeof(struct ethhdr) + ihl + sizeof(struct udphdr)))
            return;
        udp = (struct udphdr *)(buf + sizeof(struct ethhdr) + ihl);
        sp = ntohs(udp->source);
        dp = ntohs(udp->dest);
    }
    else
        return;

    if (f->source_port && f->source_port != sp)
        return;
    if (f->dest_port && f->dest_port != dp)
        return;

    fprintf(log, "\n\n================ Echoes Vibration =================\n");
    echoes_eth_header(eth, log);
    echoes_ip_header(ip, log);
    if (tcp)
        echoes_tcp(tcp, log);
    if (udp)
        echoes_udp(udp, log);
    echoes_payload(buf, len, ihl, ip->protocol, log, tcp);
    fprintf(log, "================= Echoes End ======================\n");
}

int main(int argc, char **argv)
{
    int c;
    char logfile_path[256] = "echoes_log.txt";
    FILE *logfile = NULL;
    echoes_filter_t f;
    memset(&f, 0, sizeof(f));

    static struct option opts[] = {
        {"sip", required_argument, NULL, 's'},
        {"dip", required_argument, NULL, 'd'},
        {"sport", required_argument, NULL, 'p'},
        {"dport", required_argument, NULL, 'o'},
        {"sif", required_argument, NULL, 'i'},
        {"dif", required_argument, NULL, 'g'},
        {"TCP", no_argument, NULL, 't'},
        {"UDP", no_argument, NULL, 'u'},
        {"logfile", required_argument, NULL, 'f'},
        {0, 0, 0, 0}};

    while ((c = getopt_long(argc, argv, "tus:d:p:o:i:g:f:", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 't':
            f.t_protocol = IPPROTO_TCP;
            break;
        case 'u':
            f.t_protocol = IPPROTO_UDP;
            break;
        case 'p':
            f.source_port = (uint16_t)atoi(optarg);
            break;
        case 'o':
            f.dest_port = (uint16_t)atoi(optarg);
            break;
        case 's':
            f.source_ip_addr = optarg;
            break;
        case 'd':
            f.dest_ip_addr = optarg;
            break;
        case 'i':
            f.source_if_name = optarg;
            break;
        case 'g':
            f.dest_if_name = optarg;
            break;
        case 'f':
            strncpy(logfile_path, optarg, sizeof(logfile_path) - 1);
            logfile_path[sizeof(logfile_path) - 1] = '\0';
            break;
        default:
            fprintf(stderr, "Usage: %s [options]\n", argv[0]);
            fprintf(stderr, "Options:\n");
            fprintf(stderr, "  -t, --TCP          Filter TCP packets\n");
            fprintf(stderr, "  -u, --UDP          Filter UDP packets\n");
            fprintf(stderr, "  -s, --sip IP       Source IP address\n");
            fprintf(stderr, "  -d, --dip IP       Destination IP address\n");
            fprintf(stderr, "  -p, --sport PORT   Source port\n");
            fprintf(stderr, "  -o, --dport PORT   Destination port\n");
            fprintf(stderr, "  -i, --sif IFACE    Source interface\n");
            fprintf(stderr, "  -g, --dif IFACE    Destination interface\n");
            fprintf(stderr, "  -f, --logfile PATH Log file path\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("\n[Echoes]: Initializing resonance field...\n");
    printf("   Protocol Filter: %s\n", f.t_protocol == IPPROTO_TCP ? "TCP" : f.t_protocol == IPPROTO_UDP ? "UDP"
                                                                                                         : "ALL");
    printf("   Source IP: %s | Dest IP: %s\n", f.source_ip_addr ? f.source_ip_addr : "ANY", f.dest_ip_addr ? f.dest_ip_addr : "ANY");
    printf("   Source Port: %d | Dest Port: %d\n", f.source_port, f.dest_port);
    printf("   Source Interface: %s | Dest Interface: %s\n", f.source_if_name ? f.source_if_name : "ANY", f.dest_if_name ? f.dest_if_name : "ANY");
    printf("   Logfile: %s\n\n", logfile_path);

    logfile = fopen(logfile_path, "w");
    if (!logfile)
        echoes_error("Echoes couldn't write resonance log");

    if (f.source_if_name)
        echoes_get_mac(f.source_if_name, &f, "source");
    if (f.dest_if_name)
        echoes_get_mac(f.dest_if_name, &f, "dest");

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
        echoes_error("Echoes failed to attune socket");

    uint8_t *buf = malloc(65536);
    if (!buf)
    {
        fclose(logfile);
        close(sockfd);
        echoes_error("Echoes failed to create buffer");
    }

    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    printf("[Echoes]: Reverb scan engaged...\n\n");

    while (1)
    {
        int len = recvfrom(sockfd, buf, 65536, 0, &saddr, &saddr_len);
        if (len < 0)
        {
            perror("[Echoes]: Failed to catch vibration");
            continue;
        }
        echoes_process(buf, len, &f, logfile);
        fflush(logfile);
    }

    fclose(logfile);
    free(buf);
    close(sockfd);
    return 0;
}