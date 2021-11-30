#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct IpHdr final{
	uint8_t h_len:4;
	uint8_t ver:4;
	uint8_t tos;
	uint16_t plen_;
	
	uint16_t id_;
	uint16_t offset_;
	
	uint8_t ttl_;
	uint8_t pid_;
	uint16_t chksum_;

	Ip sip_;
	Ip dip_;

	enum : uint8_t {
		ICMP = 1,
		IGMP = 2,
		TCP = 6,
		UDP = 17,
		SCTP = 132,
	};


};
#pragma pack(pop)
