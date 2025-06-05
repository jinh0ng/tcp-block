// main.cpp

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// dumphex 출처 ; https://gist.github.com/ccbrown/9722406
void DumpHex(const void *data, int size)
{
    char ascii[17];
    int i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            printf(" ");
            if ((i + 1) % 16 == 0)
            {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

typedef struct s_info
{
    Mac mac;
    Ip ip;
} t_info;

t_info MyInfo;

#pragma pack(push, 1)
struct PacketInfo
{
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
};
#pragma pack(pop)

typedef struct _ChecksumHdr
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcpLen;
} ChecksumHdr;

// Retrieve our interface MAC & IP
int getMyInfo(t_info *MyInfo, const char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        MyInfo->mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
    }
    else
    {
        close(fd);
        return -1;
    }

    // IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
    {
        uint32_t raw_ip = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        MyInfo->ip = Ip(raw_ip);
    }
    else
    {
        close(fd);
        return -1;
    }

    printf("My Mac addr: [%s]\n", std::string(MyInfo->mac).c_str());
    printf("My Ip addr: [%s]\n", std::string(MyInfo->ip).c_str());

    close(fd);
    return 0;
}

uint16_t CheckSum(uint16_t *buffer, int size)
{
    uint32_t checksum = 0;
    while (size > 1)
    {
        checksum += *buffer++;
        size -= 2;
    }
    if (size > 0)
    {
        checksum += *(uint8_t *)buffer;
    }
    while (checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return (uint16_t)(~checksum);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }
    const char *dev = argv[1];
    const char *pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s (%s)\n", dev, errbuf);
        return -1;
    }

    if (getMyInfo(&MyInfo, dev) != 0)
    {
        fprintf(stderr, "failed to get interface info for %s\n", dev);
        pcap_close(handle);
        return -1;
    }

    // Raw socket for sending IP packets (backward direction)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        perror("socket");
        pcap_close(handle);
        return -1;
    }
    const int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        close(sockfd);
        pcap_close(handle);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // printf("%u bytes captured\n", header->caplen);
        PacketInfo *ethIpTcpHdr = (PacketInfo *)packet;

        // 1) Ethernet ⇒ IPv4?
        if (ethIpTcpHdr->ethHdr_.type() != EthHdr::Ip4)
        {
            continue;
        }

        // 2) IP ⇒ TCP?
        uint32_t iphdr_len = ethIpTcpHdr->ipHdr_.hl() * 4;
        uint32_t ippkt_len = ethIpTcpHdr->ipHdr_.len(); // 전체길이 (host-order)
        if (ethIpTcpHdr->ipHdr_.p() != IpHdr::Tcp)
        {
            continue;
        }

        // 3) TCP 데이터 유무 확인
        uint32_t tcphdr_len = ethIpTcpHdr->tcpHdr_.off() * 4;
        uint32_t tcpdata_len = ippkt_len - iphdr_len - tcphdr_len;
        if (tcpdata_len == 0)
        {
            continue;
        }

        // 4) Payload 내에서 pattern 검색
        const char *data = (const char *)(packet + sizeof(EthHdr) + iphdr_len + tcphdr_len);
        if (std::strstr(data, pattern) == nullptr)
        {
            continue;
        }
        printf("\nMatched payload: %.*s\n", tcpdata_len, data);

        //
        // === Forward (RST/ACK) Packest 생성 & 송신 ===
        //
        {
            // 원본 Eth+IP+TCP 헤더만 복사 (Payload 제외)
            PacketInfo *forward_pkt = (PacketInfo *)std::malloc(sizeof(PacketInfo));
            std::memcpy(forward_pkt, packet, sizeof(PacketInfo));

            // Ethernet: src MAC = 내 MAC, dst MAC = 원본 dst (서버 MAC)
            forward_pkt->ethHdr_.smac_ = MyInfo.mac;
            // dmac_는 원본 패킷 그대로 (서버 MAC)

            // IP header 수정: length = IP header + TCP header (payload 제외)
            uint16_t new_ip_len = static_cast<uint16_t>(iphdr_len + tcphdr_len);
            forward_pkt->ipHdr_.len_ = htons(new_ip_len);
            forward_pkt->ipHdr_.sum_ = 0;
            forward_pkt->ipHdr_.sum_ = CheckSum((uint16_t *)&forward_pkt->ipHdr_, sizeof(IpHdr));

            // TCP header 수정:
            //   seq = orig_seq + payload_len
            uint32_t orig_seq = ntohl(ethIpTcpHdr->tcpHdr_.seq_);
            uint32_t new_seq = orig_seq + tcpdata_len;
            forward_pkt->tcpHdr_.seq_ = htonl(new_seq);

            //   flags = RST | ACK
            forward_pkt->tcpHdr_.flags_ = TcpHdr::Rst | TcpHdr::Ack;

            //   data offset(4-bit) = TCP header 길이 (20 bytes) ⇒ 5 (4-byte words)
            forward_pkt->tcpHdr_.off_rsvd_ = static_cast<uint8_t>((sizeof(TcpHdr) / 4) << 4);

            //   checksum 재계산
            forward_pkt->tcpHdr_.sum_ = 0;
            // ChecksumHdr 대신 ChecksumHdr 구조체 이름만 변경했으므로 그대로 사용
            ChecksumHdr phdr_fwd;
            std::memset(&phdr_fwd, 0, sizeof(ChecksumHdr));
            phdr_fwd.srcAddr = (uint32_t)ethIpTcpHdr->ipHdr_.sip_; // host-order
            phdr_fwd.dstAddr = (uint32_t)ethIpTcpHdr->ipHdr_.dip_; // host-order
            phdr_fwd.reserved = 0;
            phdr_fwd.proto = ethIpTcpHdr->ipHdr_.p_; // protocol = TCP
            phdr_fwd.tcpLen = htons(sizeof(TcpHdr)); // TCP header (no data)

            uint32_t chksum_tcp = 0;
            chksum_tcp += CheckSum((uint16_t *)&forward_pkt->tcpHdr_, sizeof(TcpHdr));
            chksum_tcp += CheckSum((uint16_t *)&phdr_fwd, sizeof(ChecksumHdr));
            // fold
            chksum_tcp = (chksum_tcp & 0xFFFF) + (chksum_tcp >> 16);
            forward_pkt->tcpHdr_.sum_ = static_cast<uint16_t>(chksum_tcp);

            // 송신: pcap_sendpacket (Ethernet 레벨)
            int fwd_len = sizeof(PacketInfo);
            if (pcap_sendpacket(handle,
                                reinterpret_cast<const u_char *>(forward_pkt),
                                fwd_len) != 0)
            {
                fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
            }

            std::free(forward_pkt);
        }

        //
        // === Backward (FIN/ACK + 302 Redirect) Packet 생성 & 송신 ===
        //
        {
            // Eth+IP+TCP 헤더 + MSG 길이만큼 버퍼 선언
            struct
            {
                PacketInfo hdr;
                char msg[sizeof(MSG)];
            } backward_pkt;

            // 1) 원본 헤더 복사 (payload 제외)
            std::memcpy(&backward_pkt.hdr, packet, sizeof(PacketInfo));
            std::memcpy(backward_pkt.msg, MSG, sizeof(MSG));

            // Ethernet: src MAC = 내 MAC, dst MAC = 원본 src MAC (클라이언트 MAC)
            backward_pkt.hdr.ethHdr_.smac_ = MyInfo.mac;
            backward_pkt.hdr.ethHdr_.dmac_ = ethIpTcpHdr->ethHdr_.smac_;

            // IP header 수정:
            //   length = IP header + TCP header + MSG(payload)
            uint16_t new_ip_len_b = static_cast<uint16_t>(iphdr_len + tcphdr_len + sizeof(MSG));
            backward_pkt.hdr.ipHdr_.len_ = htons(new_ip_len_b);

            //   TTL = 128 (임의)
            backward_pkt.hdr.ipHdr_.ttl_ = 128;

            //   Swap src/dst IP
            backward_pkt.hdr.ipHdr_.sip_ = ethIpTcpHdr->ipHdr_.dip_;
            backward_pkt.hdr.ipHdr_.dip_ = ethIpTcpHdr->ipHdr_.sip_;

            //   재계산 checksum
            backward_pkt.hdr.ipHdr_.sum_ = 0;
            backward_pkt.hdr.ipHdr_.sum_ = CheckSum((uint16_t *)&backward_pkt.hdr.ipHdr_, sizeof(IpHdr));

            // TCP header 수정:
            //   Swap ports
            backward_pkt.hdr.tcpHdr_.sport_ = ethIpTcpHdr->tcpHdr_.dport_;
            backward_pkt.hdr.tcpHdr_.dport_ = ethIpTcpHdr->tcpHdr_.sport_;

            //   seq = orig_ack (raw network-order), ack = orig_seq + payload_len
            backward_pkt.hdr.tcpHdr_.seq_ = ethIpTcpHdr->tcpHdr_.ack_;
            uint32_t orig_seq_b = ntohl(ethIpTcpHdr->tcpHdr_.seq_);
            uint32_t new_ack = orig_seq_b + tcpdata_len;
            backward_pkt.hdr.tcpHdr_.ack_ = htonl(new_ack);

            //   flags = FIN | ACK
            backward_pkt.hdr.tcpHdr_.flags_ = TcpHdr::Fin | TcpHdr::Ack;

            //   data offset = TCP header만 (no options)
            backward_pkt.hdr.tcpHdr_.off_rsvd_ = static_cast<uint8_t>((sizeof(TcpHdr) / 4) << 4);

            //   재계산 TCP checksum over (TCP header + MSG) + pseudo header
            backward_pkt.hdr.tcpHdr_.sum_ = 0;
            ChecksumHdr phdr_bwd;
            std::memset(&phdr_bwd, 0, sizeof(ChecksumHdr));
            phdr_bwd.srcAddr = (uint32_t)ethIpTcpHdr->ipHdr_.dip_; // swap
            phdr_bwd.dstAddr = (uint32_t)ethIpTcpHdr->ipHdr_.sip_;
            phdr_bwd.reserved = 0;
            phdr_bwd.proto = ethIpTcpHdr->ipHdr_.p_;
            phdr_bwd.tcpLen = htons(static_cast<uint16_t>(sizeof(TcpHdr) + sizeof(MSG)));

            // Compute checksum over TCP header + MSG
            int tcp_segment_len = sizeof(TcpHdr) + sizeof(MSG);
            // Make a temporary buffer: [ TCP header | MSG ]
            u_char *tcp_segment = (u_char *)std::malloc(tcp_segment_len);
            std::memcpy(tcp_segment, &backward_pkt.hdr.tcpHdr_, sizeof(TcpHdr));
            std::memcpy(tcp_segment + sizeof(TcpHdr), backward_pkt.msg, sizeof(MSG));
            uint32_t csum_tmp = 0;
            csum_tmp += CheckSum((uint16_t *)tcp_segment, tcp_segment_len);
            std::free(tcp_segment);
            // Add pseudo header
            csum_tmp += CheckSum((uint16_t *)&phdr_bwd, sizeof(ChecksumHdr));

            csum_tmp = (csum_tmp & 0xFFFF) + (csum_tmp >> 16);
            backward_pkt.hdr.tcpHdr_.sum_ = static_cast<uint16_t>(csum_tmp);

            // 3) Raw IP 소켓으로 송신 (Ethernet header 제외)
            struct sockaddr_in sin;
            std::memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            // 클라이언트 IP (원본 src IP)
            sin.sin_addr.s_addr = inet_addr(std::string(ethIpTcpHdr->ipHdr_.sip()).c_str());

            int send_len = sizeof(IpHdr) + sizeof(TcpHdr) + sizeof(MSG);
            if (sendto(sockfd,
                       reinterpret_cast<const void *>(&backward_pkt.hdr.ipHdr_),
                       send_len,
                       0,
                       (struct sockaddr *)&sin,
                       sizeof(sin)) < 0)
            {
                perror("sendto");
            }
        }

        // (다음 패킷 처리를 위해 계속 loop)
    }

    close(sockfd);
    pcap_close(handle);
    return 0;
}
