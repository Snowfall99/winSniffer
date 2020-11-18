#pragma once
#include "protocolHeader.h"

class packet {
public:
	Ethernet_Header *eth_header;					// 以太网首部
	IP_Header		*ip_header;						// IP首部
	TCP_Header		*tcp_header;					// TCP首部
	UDP_Header		*udp_header;					// UDP首部

	char			*http_msg;						// HTTP报文
	char			*packet_data;					// 数据包
	struct pcap_pkthdr	*header;					// 捕获数据包长度，数据包到达时间
	short			num;							// 数据包编号，从1开始
	CString         protocol;						// 协议

	packet();
	packet(const packet& p);
	packet(const struct pcap_pkthdr* header, const char* pkt_data, const short& packet_num);
	packet& operator=(const packet& p);
	~packet();

	bool isEmpty() const;

	int decodeEthernet();
	int decodeIP(char *L2Payload);
	int decodeTCP(char *L3Payload);
	int decodeUDP(char *L3Payload);
	int decodeHTTP(char *L4Payload);

	int getIPHeaderLength() const;
	int getIPHeaderLengthRaw() const;
	int getIPFlags() const;
	int getIPFlagsMF() const;
	int getIPFlagDF() const;
	int getIPOffset() const;

	int getTCPHeaderLength() const;
	int getTCPHeaderLengthRaw() const;
	short getTCPFlags()		const;
	int getTCPFlagsURG()	const;
	int getTCPFlagsACK()	const;
	int getTCPFlagsPSH()	const;
	int getTCPFlagsRST()	const;
	int getTCPFlagsSYN()	const;
	int getTCPFlagsFIN()	const;

	int getL4PayloadLength() const;
};