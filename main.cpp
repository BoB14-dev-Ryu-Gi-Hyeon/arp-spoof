#include "network.h"
#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

// 코드 흐름
#define PCAP_ERRBUF_SIZE 256

using namespace std;

// get_mac_address, get_ip_address GPT 사용했습니다.
// https://chatgpt.com/share/688eda95-fa28-8004-8578-516519effd41
int get_ip_address(const std::string& device, Ip& dest_ip) {
    int sock;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return -1;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    dest_ip = Ip(ntohl(ipaddr->sin_addr.s_addr));  // ✅ Ip 객체로 저장
    close(sock);
    return 0;
}

int get_mac_address(const std::string& device, Mac& mac_out) {
    int sock;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return -1;
    }

    mac_out = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);  // ✅ MAC 객체로 저장
    close(sock);
    return 0;
}

// 이건 내가 작성
int get_target_mac(Ip myIp, Mac myMac, Ip targetIp) {

    return 0;
}



int main(int argc, char* argv[]) {

    // 입력 예외 처리
    if (argc != 4) {
        printf("인자 개수가 안 맞음.\n입력포멧 : send-arp wlan0 192.168.10.2 192.168.10.1");
        return -1;
    }

    char* dev = argv[1];
    Ip targetIp(argv[2]);
    Ip gatewayIp(argv[3]);
    
    // 공격자(나) ip
    Ip myIp;
    get_ip_address(dev, myIp);

    printf("my IP : %s\n", std::string(myIp).c_str());
    
    // 공격자(나) mac
    Mac myMac;
    get_mac_address(dev, myMac);

    printf("my MAC : %s\n", std::string(myMac).c_str());


    // 타겟의 mac 주소 알아오기 - ARP
    u_int8_t tragetMac[ETHER_ADDR_LEN];
    get_target_mac(myIp, myMac, targetIp);
    

    // 정상 arp request
    // EthArpPacket arpReqPacket;
    // arpReqPacket.eth_.smac_ = Mac("90:de:80:9d:bd:69");
	// arpReqPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    // arpReqPacket.eth_.type_ = htons(EthHdr::Arp);
    // arpReqPacket.arp_.hln_ = Mac::Size;
	// arpReqPacket.arp_.pln_ = Ip::Size;
	// arpReqPacket.arp_.op_ = htons(ArpHdr::Request);
    // arpReqPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	// arpReqPacket.arp_.pro_ = htons(EthHdr::Ip4);
    // arpReqPacket.arp_.sip_= htonl(IP(myIp));
    // arpReqPacket.arp_.tmac_ = MAC();
    // arpReqPacket.arp_.tip_ = htonl(IP(targetIp))




    // 상대 mac



    // 게이트웨이 mac


    return 0;

    // 패킷 캡쳐
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}

    // 패킷 수신
    while (true) {

        // 멘토님 코드
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }


        

        

        

    }

    



    // 패킷 전송!
    EthArpPacket packet;

    

    return 0;
}