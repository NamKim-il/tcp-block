#pragma once

#include<cstdint>
#include<arpa/inet.h>

#pragma pack(push, 1)

struct TcpHdr final {
	uint16_t sport_;
	uint16_t dport_;
	
	uint32_t seq_;
	uint32_t ack_;

	uint8_t rev_:4,
		off_:4;
	uint8_t flags_;
	uint16_t win_;

	uint16_t chksum_;
	uint16_t urp_;

	enum : uint8_t {
    		URG = 0x20,
    		ACK = 0x10,
		PSH = 0x08,
    		RST = 0x04,
    		SYN = 0x02,
    		FIN = 0x01
  	};
};

#pragma pack(pop)

