#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "mac.h"
#include "ip.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "ethhdr.h"

// 자신의 인터페이스 정보(MAC, IP)를 담을 구조체
struct MyInfo
{
	Mac mac;
	Ip ip;
};

// 캡처된 패킷에서 Ethernet / IP / TCP 헤더와 페이로드를 한꺼번에 담는 구조체
struct PacketInfo
{
	EthHdr *ethhdr;		   // 이더넷 헤더
	IpHdr *iphdr;		   // IP 헤더
	TcpHdr *tcphdr;		   // TCP 헤더
	const u_char *payload; // TCP 페이로드(데이터) 시작 위치
	int payload_len;	   // 페이로드 길이 (바이트)
};

void usage()
{
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// 전역 변수로 pcap 핸들러를 두어 시그널 핸들러 안에서 접근할 수 있게 함
static pcap_t *pcap_handle = nullptr;
static int raw_sock_fd = -1;

// Ctrl+C 등 강제 종료 시 리소스 정리용
static void signal_handler(int signo)
{
	if (pcap_handle)
	{
		pcap_close(pcap_handle);
		pcap_handle = nullptr;
	}
	if (raw_sock_fd >= 0)
	{
		close(raw_sock_fd);
		raw_sock_fd = -1;
	}
	std::fprintf(stderr, "\nInterrupted, exiting.\n");
	std::_Exit(0);
}

// 패킷 덤프 함수: 이더넷/IPv4/TCP 헤더 필드와 페이로드 길이를 출력
void dumpPacket(const u_char *packet)
{
	// 이더넷 헤더
	const EthHdr *eth = reinterpret_cast<const EthHdr *>(packet);
	if (eth->type() != EthHdr::Ip4)
	{
		std::printf("[dump] Not IPv4, EtherType = 0x%04x\n", eth->type());
		return;
	}
	std::printf("[dump] Ethernet: SRC MAC = %s, DST MAC = %s, Type = 0x%04x\n",
				// std::string((eth->smac()).to_string()).c_str(),
				std::string(eth->smac()).c_str(),
				// std::string((eth->dmac()).to_string()).c_str(),
				std::string(eth->dmac()).c_str(),
				eth->type());

	// IP 헤더
	const u_char *ptr_ip = packet + sizeof(EthHdr);
	const IpHdr *iphdr = reinterpret_cast<const IpHdr *>(ptr_ip);
	if (iphdr->v() != 4 || iphdr->p() != IpHdr::Tcp)
	{
		std::printf("[dump] Not IPv4/TCP packet, V=%u, Proto=%u\n",
					iphdr->v(), iphdr->p());
		return;
	}
	std::printf("[dump] IP: SRC IP = %s, DST IP = %s, TTL = %u, TotalLen = %u\n",
				std::string(static_cast<std::string>(iphdr->sip())).c_str(),
				std::string(static_cast<std::string>(iphdr->dip())).c_str(),
				iphdr->ttl(), iphdr->len());

	// TCP 헤더 및 페이로드
	int ip_hdr_len = iphdr->hl() * 4;
	const u_char *ptr_tcp = ptr_ip + ip_hdr_len;
	const TcpHdr *tcphdr = reinterpret_cast<const TcpHdr *>(ptr_tcp);
	int tcp_hdr_len = tcphdr->off() * 4;
	int payload_len = iphdr->len() - ip_hdr_len - tcp_hdr_len;
	std::printf("[dump] TCP: SRC PORT = %u, DST PORT = %u, Seq = %u, Ack = %u, Flags = 0x%02x, PayloadLen = %d\n",
				tcphdr->sport(), tcphdr->dport(),
				tcphdr->seq(), tcphdr->ack(),
				tcphdr->flags(), payload_len);
}

// 내 인터페이스 정보(MAC, IP)를 얻어서 myinfo에 채워주는 함수
// 성공 시 true, 실패 시 false 반환
bool getMyInfo(const char *iface, MyInfo &myinfo)
{
	// 1) 소켓을 열어 ioctl 호출 준비
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0)
	{
		perror("socket");
		return false;
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	// 2) MAC 주소 얻기 (SIOCGIFHWADDR)
	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl(SIOCGIFHWADDR)");
		close(sock_fd);
		return false;
	}
	// ifr.ifr_hwaddr.sa_data 에 6바이트 MAC 주소가 들어있음
	myinfo.mac = Mac(reinterpret_cast<const uint8_t *>(ifr.ifr_hwaddr.sa_data));

	// 3) IP 주소 얻기 (SIOCGIFADDR)
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl(SIOCGIFADDR)");
		close(sock_fd);
		return false;
	}
	struct sockaddr_in *ipaddr = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
	char ip_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &ipaddr->sin_addr, ip_str, sizeof(ip_str)))
	{
		perror("inet_ntop");
		close(sock_fd);
		return false;
	}
	myinfo.ip = Ip(std::string(ip_str));

	close(sock_fd);
	return true;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		usage();
		return EXIT_FAILURE;
	}

	const char *iface = argv[1];
	const char *pattern = argv[2];

	// 시그널 핸들러 등록 (Ctrl+C 등)
	std::signal(SIGINT, signal_handler);
	std::signal(SIGTERM, signal_handler);

	// 1) 내 인터페이스 정보 가져오기
	MyInfo myinfo;
	if (!getMyInfo(iface, myinfo))
	{
		std::fprintf(stderr, "Failed to get local MAC/IP for interface '%s'\n", iface);
		return EXIT_FAILURE;
	}
	std::printf("[info] Local MAC = %s, Local IP = %s\n",
				std::string(myinfo.mac).c_str(), // to_string()).c_str(),
				std::string(myinfo.ip).c_str());

	// 2) pcap 핸들러 열기
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(iface,
								 65536,
								 1,	   // promiscuous mode
								 1000, // timeout (ms)
								 errbuf);
	if (!pcap_handle)
	{
		std::fprintf(stderr, "pcap_open_live(%s) failed: %s\n", iface, errbuf);
		return EXIT_FAILURE;
	}

	// (선택) BPF 필터 → “tcp 포트 80” 같은 식으로 HTTP 트래픽만 걸러내려면 이곳에 추가

	// 3) Raw socket (IP_HDRINCL) 열기
	raw_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock_fd < 0)
	{
		perror("socket(AF_INET, SOCK_RAW)");
		pcap_close(pcap_handle);
		return EXIT_FAILURE;
	}
	int one = 1;
	if (setsockopt(raw_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
	{
		perror("setsockopt(IP_HDRINCL)");
		close(raw_sock_fd);
		pcap_close(pcap_handle);
		return EXIT_FAILURE;
	}

	std::printf("[info] Started packet capture on interface '%s', searching for pattern: \"%s\"\n",
				iface, pattern);

	// 4) 패킷 캡처 및 처리 루프
	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int ret = pcap_next_ex(pcap_handle, &header, &packet);
		if (ret == 0)
		{
			// Timeout
			continue;
		}
		if (ret < 0)
		{
			std::fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap_handle));
			break;
		}

		// 이더넷 헤더 검사
		const EthHdr *eth = reinterpret_cast<const EthHdr *>(packet);
		if (eth->type() != EthHdr::Ip4)
		{
			continue; // IPv4 외 패킷 무시
		}

		// IP 헤더 파싱
		const u_char *ptr_ip = packet + sizeof(EthHdr);
		const IpHdr *iphdr = reinterpret_cast<const IpHdr *>(ptr_ip);
		if (iphdr->v() != 4 || iphdr->p() != IpHdr::Tcp)
		{
			continue; // IPv4/TCP 외는 무시
		}
		int ip_hdr_len = iphdr->hl() * 4;

		// TCP 헤더 파싱
		const u_char *ptr_tcp = ptr_ip + ip_hdr_len;
		const TcpHdr *tcphdr = reinterpret_cast<const TcpHdr *>(ptr_tcp);
		int tcp_hdr_len = tcphdr->off() * 4;

		// 페이로드 검사
		int payload_len = iphdr->len() - ip_hdr_len - tcp_hdr_len;
		if (payload_len <= 0)
		{
			continue; // 데이터 없음
		}
		const u_char *payload = ptr_tcp + tcp_hdr_len;

		// 패턴 찾기 (예: payload 내에 pattern이 포함되는지)
		bool found = false;
		size_t pat_len = std::strlen(pattern);
		for (int i = 0; i + (int)pat_len <= payload_len; i++)
		{
			if (std::memcmp(payload + i, pattern, pat_len) == 0)
			{
				found = true;
				break;
			}
		}
		if (!found)
		{
			continue;
		}

		// 디버깅: 패킷 덤프
		std::printf("[match] Pattern found; dumping headers:\n");
		dumpPacket(packet);

		// TODO:
		//   → 정방향 RST 패킷 생성/전송 코드
		//   → 역방향 FIN+Redirect 패킷 생성/전송 코드
		//   → 단일 연결에 여러 번 차단하지 않도록 플래그/상태 관리

		// 일단, 캡처 루프를 멈추지 않고 계속 진행
	}

	// 5) 정리
	if (pcap_handle)
	{
		pcap_close(pcap_handle);
	}
	if (raw_sock_fd >= 0)
	{
		close(raw_sock_fd);
	}
	return EXIT_SUCCESS;
}