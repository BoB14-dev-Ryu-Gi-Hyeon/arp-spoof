#pragma once

#include "ethhdr.h"
#include "ip.h"
#include "arphdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)