
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <poll.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

struct config {
    uint32_t src;
    const char* dst_name;
    struct sockaddr* dst;
    uint16_t dst_port;
    uint16_t src_port;
    int max_ttl;
    int nqueries;
    int timeout;
    char* device;
};
struct record {
    int ttl;
    int q;
    u_short id;
    struct timeval timestamp;
    double delta_time;
    char *addr, *dnat_ip;
};
#define MX_PKT_SZ 500
#define MX_TEXT 500
#define SYN_PK_SIZE 100
#define DEFAULT_DEST_PORT 80

extern pcap_t* pcap; 
extern struct config* conf; 
extern int send_sck; 
extern int pcap_sck; 

void start_pcap_listener();
void probe(struct record *log); 
int capture(const u_char** buffer, struct pcap_pkthdr** pkt_hdr, int timeout);
int packet_ok(u_char* buffer, struct pcap_pkthdr* pkt_hdr, struct record* log);
size_t build_syn_packet(u_char* packet, uint32_t src, uint32_t dst, uint16_t id, 
        uint8_t ttl, uint16_t sp ,uint16_t dp);
void build_ip_packet(u_char* packet, uint16_t ip_len, uint8_t tos, uint16_t id, 
        uint16_t frag,uint8_t ttl, uint8_t prot, uint32_t src, uint32_t dst,
        const uint8_t *payload, uint32_t payload_s);
void build_tcp_packet(u_char* packet, uint16_t sp, uint16_t dp, uint32_t seq, 
        uint32_t ack, uint8_t control, uint16_t win, uint16_t urg, 
        const uint8_t *payload, uint32_t payload_s); 
void dump_packet(u_char* packet, int len);

u_short in_chksum(u_char *addr, int len);
u_short tcp_chksum(u_char *addr); 
void find_usable_addr(const char* node);
void find_src_addr(void);
void find_device(void);
void find_unused_port(u_short req);
char* find_host(char *ip_addr); 
char* ip_to_str(u_long addr); 
double time_diff(struct timeval* t1, struct timeval *t2);
int check_numeric(char* s); 
int get_optarg(); 
void prep_sockets(); 
int trace();
void usage(char**);
struct config* conf;
int send_sck;
char *optstr;
char dst_prt_name[MX_TEXT];
int main(int argc, char *argv[]) 
{
    conf = calloc(1, sizeof(struct config));
    if (conf == NULL) {
        perror("error in calloc for conf\n");
        exit(EXIT_FAILURE);
    }   
    conf->max_ttl = 30;
    conf->nqueries = 3;
    conf->dst_port = 80;
    conf->timeout = 1000;
    conf->device = NULL;
    int c;
    optstr = "hm:p:t";
    while ((c = getopt(argc, argv, optstr)) != -1) {
        switch (c) {
            case 'm':
                conf->max_ttl = max(1, get_optarg());
                break;
            case 'p':
                conf->dst_port = max(1, get_optarg());
                break;
            case 't':
                conf->dst_name = optarg;
                break;
            case 'h':
                usage(argv);
                break;
            case '?':
            default:
                if (optopt != ':' && strchr(optstr, optopt)) {
					fprintf(stderr, "Argument required for -%c\n", optopt);
                    exit(EXIT_FAILURE);
                }
				fprintf(stderr, "Unknown command line argument: -%c\n", optopt);
                usage(argv);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc > 1 && check_numeric(argv[1])) {
        conf->dst_port = atoi(argv[1]);
    }
    find_usable_addr(argv[0]);
    find_src_addr();
    find_unused_port(0);
    find_device();
    if (conf->device) {
        fprintf(stderr, "Selected device %s, address %s, port %d\n", 
                conf->device, ip_to_str(conf->src), conf->src_port);
    } else {
        fprintf(stderr, "%s\n", "unable to find device");
    }
    struct servent* serv;
    if ((serv = getservbyport(htons(conf->dst_port), "tcp")) == NULL) {
        snprintf(dst_prt_name, MX_TEXT, "%d", conf->dst_port);
    } else {
        snprintf(dst_prt_name, MX_TEXT, "%d (%s)", conf->dst_port, serv->s_name);
    }

    prep_sockets();
    start_pcap_listener();
    trace();
}
void prep_sockets() {
    send_sck = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sck < 1) {
        perror("error creating socket for sending");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(send_sck, IPPROTO_IP, IP_HDRINCL, &optval ,
                sizeof(optval)) < 0) {
        perror("cannot set socket option for sending socket");
        exit(EXIT_FAILURE);
    }
}

char hbuf[NI_MAXHOST];
void find_usable_addr(const char* node)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;

    struct addrinfo* res; 
    int err;
    
    if ((err = getaddrinfo(node, NULL, &hints, &res))) {
        fprintf(stderr, "name resolution error: %s\n", gai_strerror(err));
        exit(EXIT_FAILURE);
    }

    conf->dst_name = res->ai_canonname ? strdup(res->ai_canonname) : node;
    conf->dst = calloc(1, sizeof(struct sockaddr));
    memcpy(conf->dst, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
}
void find_src_addr()
{
    int s;
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sinsrc, sindest;
    memset(&sinsrc, 0, sizeof(struct sockaddr_in)); 
    memset(&sindest, 0, sizeof(struct sockaddr_in)); 
    sindest.sin_addr.s_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    sindest.sin_family = AF_INET;
    sindest.sin_port = htons(53); 
    if (connect(s, (struct sockaddr*)&sindest, sizeof(sindest)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    } 
    unsigned int size = sizeof(sinsrc);
    if (getsockname(s, (struct sockaddr *)&sinsrc, &size) < 0) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    close(s);
    conf->src = sinsrc.sin_addr.s_addr;
}
char* find_host(char *ip_addr) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip_addr);
    socklen_t len = sizeof(struct sockaddr_in);
    if (getnameinfo((struct sockaddr *)&sin, len, hbuf, sizeof(hbuf)
                , NULL, 0, NI_NAMEREQD) != 0) {
        return NULL;
    }
    char* ret = malloc(strlen(hbuf) + 1);
    strcpy(ret, hbuf);
    return ret;
}
void find_unused_port(u_short req)
{
    int s;
    if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in in;
    unsigned int sz = sizeof(in);

    in.sin_family = AF_INET;
    in.sin_port = htons(req);

    if (bind(s, (struct sockaddr*)&in, sz) < 0) {
        perror("cannot bind to any port");
        exit(EXIT_FAILURE);
    }

    if (getsockname(s, (struct sockaddr*)&in, &sz) < 0) {
        perror("get sockname");
        exit(EXIT_FAILURE);   
    }

    close(s);
    conf->src_port = ntohs(in.sin_port);
}
void find_device() 
{
    struct ifaddrs *ifaddr;
    char* dev = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    struct ifaddrs *ifa;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        u_long s1 = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr.s_addr;
        if (conf->src && s1 == conf->src) {
            dev = ifa->ifa_name;
        }
    }

    if (!dev) {
        return;
    }

    conf->device = dev;
}
char* ip_to_str(u_long addr) 
{
    struct in_addr ip_addr;
    ip_addr.s_addr = addr;

    char* res = inet_ntoa(ip_addr);
    char* buffer = malloc(strlen(res) + 5);
    strcpy(buffer, res);

    return buffer; 
}
double time_diff(struct timeval* t1, struct timeval *t2) 
{
    return (double)(t2->tv_sec - t1->tv_sec) * 1000.0 +
        (double)(t2->tv_usec - t1->tv_usec) / 1000.0;
}
int check_numeric(char* s) {
    int is_number = 0;
    for (size_t i = 0; i < strlen(s); i++) {
        is_number |= isdigit(s[i]);
    }
    return is_number;
}
size_t build_syn_packet(u_char* packet, uint32_t src, uint32_t dst, uint16_t id, 
        uint8_t ttl, uint16_t sp ,uint16_t dp)
{
    size_t datalen = sizeof(struct ip) + sizeof(struct tcphdr);
    build_ip_packet(
        packet,
        datalen,                                   
        0,                                         
        htons(id),                                  
        0,                                          
        ttl,                                         
        IPPROTO_TCP,                                 
        src,                                         
        dst,                                        
        NULL,                                      
        0                                            
    );

    build_tcp_packet(
        packet,                                     
        sp,         
        dp,         
        0,           
        0,           
        TH_SYN,      
        0,          
        0,          
        NULL,        
        0            
    );

    return datalen;
}

void dump_packet(u_char* packet, int len)
{
    u_char *p = packet;
    fprintf(stderr, "packet: ");
    for (int i = 0; i < len; ++i) {
        if ((i % 24) == 0) {
            fprintf(stderr, "\n ");
        }

        fprintf(stderr, " %02x", *p);
        p++;
    } 
    fprintf(stderr, "\n");
}

int packet_ok(u_char* buffer, struct pcap_pkthdr* pkt_hdr, struct record* log)
{
    size_t mn = sizeof(struct ip) + sizeof(struct ether_header);
    if (pkt_hdr->caplen < mn) {
        return -1;
    } 
    struct ip *ip_hdr = (struct ip*)(buffer + sizeof(struct ether_header));
    if (ip_hdr->ip_v != 4 
            || ip_hdr->ip_hl > 5
            || ip_hdr->ip_dst.s_addr != conf->src) {
        return -1;
    }
    if (ip_hdr->ip_p != IPPROTO_ICMP && ip_hdr->ip_p != IPPROTO_TCP) {
        return -1;
    }

    int status = 0;
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        const size_t offset = 8;
        struct icmp *icmp_hdr = (struct icmp*)(buffer + sizeof(struct ip) 
                + sizeof(struct ether_header));
        struct ip* old_hdr = (struct ip*)(buffer + sizeof(struct ip) 
                + sizeof(struct ether_header) + offset);

        uint16_t* src_port = (uint16_t*)(((u_char*)old_hdr) + sizeof(struct ip));
        uint16_t* dst_port = (uint16_t*)(((u_char*)old_hdr) + sizeof(struct ip) + 2);
        if (ntohs(old_hdr->ip_id) != log->id 
                || old_hdr->ip_p != IPPROTO_TCP
                || old_hdr->ip_src.s_addr != conf->src
                || conf->src_port != ntohs(*src_port) 
                || conf->dst_port != ntohs(*dst_port)) {
            return -1;
        }        

        if (icmp_hdr->icmp_type == ICMP_UNREACH) {
            status = 1;
        }
    }

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
        if (ip_hdr->ip_src.s_addr != d_addr) {
            return -1;
        }

        struct tcphdr *tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr 
                + sizeof(struct ip));
       
        if (ntohs(tcp_hdr->th_sport) != conf->dst_port
                || ntohs(tcp_hdr->th_dport) != conf->src_port) {
            return -1;
        }

        status = 1;
    }
    log->dnat_ip = inet_ntoa(ip_hdr->ip_src);
    log->addr = find_host(log->dnat_ip);
    
    struct timeval rcv_time;
    if (gettimeofday(&rcv_time, NULL) < 0) {
        perror("get time failed");
        exit(EXIT_FAILURE);
    }

    log->delta_time = time_diff(&log->timestamp, &pkt_hdr->ts); 
    return status; 
}
void build_tcp_packet(u_char* packet, uint16_t sp, uint16_t dp, uint32_t seq, 
        uint32_t ack, uint8_t control, uint16_t win, uint16_t urg, 
        const uint8_t *payload, uint32_t payload_s) 
{
    struct tcphdr *tcp_header = (struct tcphdr*) (packet + sizeof(struct ip));

    tcp_header->th_sport = htons(sp);
    tcp_header->th_dport = htons(dp);
    tcp_header->th_seq = htonl(seq);
    tcp_header->th_ack = htonl(ack);
    tcp_header->th_flags = control;
    tcp_header->th_x2 = 0;
    tcp_header->th_off = 5;
    tcp_header->th_win = htons(win);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = htons(urg);
    tcp_header->th_sum = tcp_chksum(packet); 
    
    if (payload != NULL && payload_s > 0) {}
}

void build_ip_packet(u_char* packet, uint16_t ip_len, uint8_t tos, uint16_t id, 
        uint16_t frag,uint8_t ttl, uint8_t prot, uint32_t src, uint32_t dst,
        const uint8_t *payload, uint32_t payload_s)
{
    struct ip *ip_header = (struct ip*) packet; 

    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = tos;
    ip_header->ip_len = ip_len;
    ip_header->ip_id = id;
    ip_header->ip_off = frag;
    ip_header->ip_ttl = ttl;
    ip_header->ip_p = prot;
    ip_header->ip_src.s_addr = src;
    ip_header->ip_dst.s_addr = dst;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = in_chksum(packet, sizeof(struct ip));


    if (payload != NULL && payload_s > 0) {}
}


u_short in_chksum(u_char *addr, int len)
{
    u_short *p = (u_short*)addr;
    int cnt = len;

    int sum = 0;
    while (cnt > 1) {
        sum += *p;
        p++;
        cnt -= 2;
    }
    if (cnt == 1) {
        sum += *(u_char *)p;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ((unsigned short)~sum);
}


u_short tcp_chksum(u_char *addr) {
    struct ip* ip_hdr = (struct ip*) addr;
    struct tcphdr* tcp_hdr = (struct tcphdr*)(addr + sizeof(struct ip));

    struct pseudo_header {
        struct in_addr src;
        struct in_addr dest;
        u_char padding;
        u_char protocol;
        u_short length;
    } ph;

    ph.src = ip_hdr->ip_src;
    ph.dest = ip_hdr->ip_dst;
    ph.padding = 0;
    ph.protocol = ip_hdr->ip_p;
    ph.length = htons(sizeof(struct tcphdr));

    size_t len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  
    u_char *psuedo_pkt = malloc(len);
    if (psuedo_pkt == NULL) {
        perror("error in allocation");
        exit(EXIT_FAILURE);
    }

    memcpy(psuedo_pkt, &ph, sizeof(ph));
    memcpy(psuedo_pkt + sizeof(ph), tcp_hdr, sizeof(struct tcphdr));
    return in_chksum(psuedo_pkt, len);
}
u_char packet[SYN_PK_SIZE];
void probe(struct record *log) 
{
    memset(packet, 0, sizeof(packet));
    log->id = rand() & ((1 << 16) - 5);

    uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    size_t datalen = build_syn_packet(
        packet,
        conf->src,
        d_addr,
        log->id,
        log->ttl,
        conf->src_port,
        conf->dst_port
    );

    if (gettimeofday(&(log->timestamp), NULL) < 0) {
        perror("get time failed");
        exit(EXIT_FAILURE);
    }

    if (sendto(send_sck, packet, datalen, 0, conf->dst, sizeof(struct sockaddr_storage)) < 0) {
        perror("sending failed");
        exit(EXIT_FAILURE);
    }
}

pcap_t *pcap;
int pcap_sck;
char errbuf[MX_TEXT];
char filter[MX_TEXT];
void start_pcap_listener()
{
    pcap = pcap_open_live(conf->device, MX_PKT_SZ, 0, 10, errbuf);
    if (!pcap) {
        perror("error opening pcap");
        exit(EXIT_FAILURE);
    } 

    bpf_u_int32 localnet = 0;
    bpf_u_int32 netmask = 0;
    if (pcap_lookupnet(conf->device, &localnet, &netmask, errbuf) < 0) {
        fprintf(stderr, "pcap_lookupnet failed: %s\n", errbuf);
    }

    uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    char* dst_ip = ip_to_str(d_addr);
    char* src_ip = ip_to_str(conf->src);

	snprintf(filter, MX_TEXT, "\n\
		(tcp and src host %s and src port %d and dst host %s)\n\
		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			    dst_ip, conf->dst_port, src_ip, src_ip);

    struct bpf_program fcode;
    if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0) {
        perror("error compiling filter");
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap, &fcode) < 0) {
        perror("error setting filter");
        exit(EXIT_FAILURE);
    }

    pcap_sck = pcap_fileno(pcap);
}
int capture(const u_char** buffer, struct pcap_pkthdr** pkt_hdr, int timeout)
{
    struct pollfd pfd[1];
    int ok = 0;

    pfd[0].fd = pcap_sck;
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;

    if (poll(pfd, 1, timeout) > 0) {
        ok = pcap_next_ex(pcap, pkt_hdr, buffer);
    }

    return ok;
}

int trace(void)
{
    fprintf(stderr, "Tracing the path to %s (%s) on TCP port %s, %d hops max\n",
            conf->dst_name, inet_ntoa(((struct sockaddr_in*)conf->dst)->sin_addr)
            , dst_prt_name, conf->max_ttl); 

    const u_char *buffer;
    struct pcap_pkthdr *pkt_hdr;
    int last_succ;
    int done = 0;

    for (int ttl = 1; ttl <= conf->max_ttl && !done; ++ttl) {
        printf("%2u ", ttl);
        last_succ = 0;

        for (int q = 1; q <= conf->nqueries; ++q) {
            struct record *log = calloc(1, sizeof(struct record));
            if (log == NULL) {
                perror("calloc record failed");
                exit(EXIT_FAILURE);
            }

            log->ttl = ttl;
            log->q = q;

            probe(log);
            
#ifdef DEBUG
            printf("Send packet with ttl %d [q: %d]\n", ttl, q);
#endif

            int read_sz = 0;
            while ((read_sz = capture(&buffer, &pkt_hdr, conf->timeout)) > 0) {
                int status = packet_ok((u_char*)buffer, pkt_hdr, log);
                if (status == -1) {
                    continue;
                }

                if (!last_succ) {
                    if (log->addr) {
                        printf("%s (%s) ", log->addr, log->dnat_ip);
                    } else {
                        printf("%s ", log->dnat_ip);
                    }
                    last_succ = 1;
                } 

                if (status) {
                    done = 1;
                }

                printf(" %g ms", log->delta_time);
                break;
            }

            if (read_sz == 0) {
                printf(" *");
            }

            fflush(stdout);
        }
        if (done) {
            printf(" (Reached)");
        }

        printf("\n");
    }

    if (!done) {
        fprintf(stderr, "Destination not reached\n");
    }

    return 0;
}
void usage(char *argv[]) 
{
    printf("Usage: %s [-m max Hops] [-p destination port] -t Target \n\n", argv[0]);    
    exit(EXIT_SUCCESS);
}

int get_optarg() 
{
    int is_number = check_numeric(optarg);
    if (!is_number) {
        fprintf(stderr, "Numeric argument required for -%c\n", optopt);
        exit(EXIT_FAILURE);
    }

    return atoi(optarg);
}

