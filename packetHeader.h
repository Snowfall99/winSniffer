#pragma once
#include "protocolHeader.h"
#include <vector>
#include <string>

class packet {
public:
	Ethernet_Header *eth_header;					// eth首部
	IP_Header		*ip_header;						// IPv4首部
	IPv6_Header		*ipv6_header;					// IPv6首部
	ARP_Header		*arp_header;					// ARP首部
	ICMP_Header		*icmp_header;					// ICMP首部
	IGMP_Header		*igmp_header;					// IGMP首部
	TCP_Header		*tcp_header;					// TCP首部
	UDP_Header		*udp_header;					// UDP首部
	
	CString			message;						// 数据报所携带的信息概括
	u_char			*http_msg;						// HTTP报文
	u_char			*packet_data;					// 数据包
	struct pcap_pkthdr	*header;					// 捕获数据包长度，数据包到达时间
	u_short			num;							// 数据包编号，从1开始
	CString         protocol;						// 协议

	packet();
	packet(const packet& p);
	packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& packet_num);
	packet& operator=(const packet& p);
	~packet();

	bool isEmpty() const;

	int decodeEthernet();
	int decodeIP(u_char* L2Payload);
	int decodeIPv6(u_char* L2Payload);
	int decodeARP(u_char* L2Payload);
	int decodeICMP(u_char* L3Payload);
	int decodeIGMP(u_char* L3PayLoad);
	int decodeTCP(u_char *L3Payload);
	int decodeUDP(u_char *L3Payload);
	int decodeHTTP(u_char *L4Payload);

	int getIPHeaderLength() const;
	int getIPHeaderLengthRaw() const;
	int getIPFlags() const;
	int getIPFlagsMF() const;
	int getIPFlagDF() const;
	int getIPOffset() const;
	
	void search(CString keyword);

	u_short getICMPID()	const;
	u_short getICMPSeq() const;

	int getTCPHeaderLength() const;
	int getTCPHeaderLengthRaw() const;
	u_short getTCPFlags()		const;
	int getTCPFlagsURG()	const;
	int getTCPFlagsACK()	const;
	int getTCPFlagsPSH()	const;
	int getTCPFlagsRST()	const;
	int getTCPFlagsSYN()	const;
	int getTCPFlagsFIN()	const;

	int getL4PayloadLength() const;
};

CString getIPMessage(packet pkt);
CString getIPv6Message(packet pkt);
CString getARPMessage(packet pkt);