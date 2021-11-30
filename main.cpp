#include <cstdio>
#include <pcap.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define TCP_PRO 6

#pragma pack(push, 1)
struct TcpPacket final {
	EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
};
#pragma pack(pop)
#pragma pack(push,1)
struct PseHdr final {
	Ip sip_;
	Ip dip_;
	
	uint8_t rev_;
	uint8_t pro_;
	uint16_t len_;
};
#pragma pack(pop)

#define BLOCK_MSG  "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n"
#define MSG_LEN 55
char PATTERN[1024];
int PATTERN_LEN;
Mac myMac;

bool getMyInfo(char* dev)
{
    	char mac[32];
    	struct ifreq ifr;
    	int sock = socket(PF_INET, SOCK_STREAM, 0);
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)-1);
    	ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';

    	if(sock==-1) {
        	printf("Error : socket failed\n");
        	return false;
    	}
    	if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1) {
        	printf("Error : MAC error\n");
        	return false;
    	}
    	for(int i=0, k=0; i<6; i++) {
        	k += snprintf(mac+k, sizeof(mac)-k-1, i ? ":%02x" : "%02x", (int)(unsigned int)(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    	}
    	mac[sizeof(mac)-1]='\0';
    	myMac=Mac(mac);
    	return true;
}


char *strnstr(u_char* s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == '\0' || slen-- < 1)
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp((char*)s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

bool check(const u_char* packet, int packet_len)
{
	TcpPacket* tcp_pkt = (TcpPacket*) packet;
	if(tcp_pkt->eth_.type() != EthHdr::Ip4) return false;
	if(tcp_pkt->ip_.pid_ != IpHdr::TCP) return false;
	u_char* data = (u_char*)packet + sizeof(TcpPacket);
	if(!strnstr(data, PATTERN, packet_len-sizeof(TcpPacket))) return false;
	
	return true;
}

uint32_t wrap(uint16_t* buffer, int size)
{
	uint32_t chksum = 0;
	for(int i=0; i<(size+1)/2; i++) {
		chksum += htons(buffer[i]);
	}
	while(chksum > 0xffff) {
		chksum = (chksum >> 16) + (chksum & 0xffff);
	}
	return chksum;
}

uint16_t checksum_tcp(TcpPacket *tcpHdr, int tcplen)
{
	tcpHdr->tcp_.chksum_ = 0;

	PseHdr* pseudo = (PseHdr*)malloc(sizeof(PseHdr));
	pseudo->sip_ = tcpHdr->ip_.sip_;
	pseudo->dip_ = tcpHdr->ip_.dip_;
	pseudo->rev_ = 0;
	pseudo->pro_ = TCP_PRO;
	pseudo->len_ = htons(tcplen);
	uint32_t chksum = wrap((uint16_t*)pseudo, sizeof(PseHdr));
	chksum += wrap((uint16_t*)&(tcpHdr->tcp_), tcplen);
	
	while(chksum > 0xffff) {
                chksum = (chksum >> 16) + (chksum & 0xffff);
        }

	free(pseudo);
	return (uint16_t)(~chksum);
}	

uint16_t checksum_ip(TcpPacket *tcpHdr)
{
	int len = tcpHdr->ip_.h_len << 2;
	tcpHdr->ip_.chksum_ = 0;
	uint32_t chksum = wrap((uint16_t*)&(tcpHdr->ip_), len);

	while(chksum > 0xffff) {
                chksum = (chksum >> 16) + (chksum & 0xffff);
        }
		
	return (uint16_t)(~chksum);
}

void send_pkt(pcap_t* handle, TcpPacket* packet, int size)
{
	if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), size)) {
		puts("packet send error");
		return;
	}
	else{
		puts("send success");
	}
}


void block(pcap_t* handle, const u_char* packet, int pkt_len)
{
	if(!check(packet, pkt_len)) return;

	TcpPacket* pkt = (TcpPacket*) packet;
	TcpPacket* pkt_fr = (TcpPacket*)malloc(sizeof(TcpPacket));
        TcpPacket* pkt_bk = (TcpPacket*)malloc(sizeof(TcpPacket)+sizeof(BLOCK_MSG));

	memcpy(pkt_fr, packet, sizeof(TcpPacket));
	memcpy(pkt_bk, packet, sizeof(TcpPacket));

	uint32_t header_len = (pkt->ip_.h_len<<2) + (pkt->tcp_.off_<<2);
	uint32_t data_len = ntohs(pkt->ip_.plen_) - header_len;

	printf("\n%u, tcp:%u \n%u\n",header_len,data_len,pkt_fr->tcp_.off_<<2);


	pkt_fr->eth_.smac_ = myMac;
	pkt_bk->eth_.smac_ = myMac;
	pkt_bk->eth_.dmac_ = pkt->eth_.smac_;
	
	Ip tmpIp = pkt_bk->ip_.sip_;
	pkt_bk->ip_.sip_ = pkt_bk->ip_.dip_;
	pkt_bk->ip_.dip_ = tmpIp;

	pkt_fr->ip_.ttl_ = 128;
	pkt_bk->ip_.ttl_ = 128;
		
	pkt_fr->ip_.plen_ = htons(sizeof(IpHdr)+sizeof(TcpHdr));
	pkt_bk->ip_.plen_ = htons(sizeof(IpHdr)+sizeof(TcpHdr)+MSG_LEN);
	
	pkt_fr->ip_.chksum_ = htons(checksum_ip(pkt_fr));
	pkt_bk->ip_.chksum_ = htons(checksum_ip(pkt_bk));
	
	uint16_t tmpPort = pkt_bk->tcp_.sport_;
	pkt_bk->tcp_.sport_ = pkt_bk->tcp_.dport_;
	pkt_bk->tcp_.dport_ = tmpPort;

	pkt_fr->tcp_.off_ = 5;
	pkt_bk->tcp_.off_ = 5;
	
	pkt_fr->tcp_.seq_ = htonl(ntohl(pkt_fr->tcp_.seq_)+data_len);
	pkt_bk->tcp_.seq_ = pkt->tcp_.ack_;
	
	pkt_bk->tcp_.ack_ = pkt_fr->tcp_.seq_;
	
	pkt_fr->tcp_.flags_ = TcpHdr::RST | TcpHdr::ACK;
	pkt_bk->tcp_.flags_ = TcpHdr::FIN | TcpHdr::ACK;
	
	strncpy((char*)pkt_bk+sizeof(TcpPacket), BLOCK_MSG, MSG_LEN);

	pkt_fr->tcp_.chksum_ = htons(checksum_tcp(pkt_fr, pkt_fr->tcp_.off_<<2));
	pkt_bk->tcp_.chksum_ = htons(checksum_tcp(pkt_bk, (pkt_bk->tcp_.off_<<2)+MSG_LEN));

	send_pkt(handle, pkt_fr, sizeof(TcpPacket));
	

	send_pkt(handle, pkt_bk, sizeof(TcpPacket)+MSG_LEN);
	
	free(pkt_fr);
	free(pkt_bk);
}

void usage() {
   	printf("syntax : tcp-block <interface> <pattern>\n");
    	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int main(int argc, char* argv[]) {
    	if (argc != 3 ) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	PATTERN_LEN = strlen(argv[2]);
	strncpy(PATTERN, argv[2], PATTERN_LEN);
	char errbuf[PCAP_ERRBUF_SIZE];
    	
    	if(!getMyInfo(dev)) {
       		return -1;
    	}

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	
	printf("capture start!\n");
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet); 
		
		puts("captured!");

		if(res==0) continue;
		if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		block(handle, packet, header->caplen);
			
	}
	
	pcap_close(handle);

}
