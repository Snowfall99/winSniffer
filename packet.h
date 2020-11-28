#pragma once
#include "protocolHeader.h"

class packet {
public:
	Ethernet_Header *eth_header;					// 以太网首部
	IP_Header		*ip_header;						// IP首部
	ARP_Header		*arp_header;					// ARP首部
	ICMP_Header		*icmp_header;					// ICMP首部
	IGMP_Header		*igmp_header;					// IGMP首部
	TCP_Header		*tcp_header;					// TCP首部
	UDP_Header		*udp_header;					// UDP首部
	DNS_Header		*dns_header;					// DNS首部
	DHCP_Header		*dhcp_header;					// DHCP首部

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
	int decodeIP(u_char *L2Payload);
	int decodeARP(u_char* L2Payload);
	int decodeICMP(u_char* L3Payload);
	int decodeIGMP(u_char* L3PayLoad);
	int decodeTCP(u_char *L3Payload);
	int decodeUDP(u_char *L3Payload);
	int decodeDNS(u_char* L4Payload);
	int decodeDHCP(u_char* L4Payload);
	int decodeHTTP(u_char *L4Payload);

	int getIPHeaderLength() const;
	int getIPHeaderLengthRaw() const;
	int getIPFlags() const;
	int getIPFlagsMF() const;
	int getIPFlagDF() const;
	int getIPOffset() const;

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

	int getDNSFlagsQR()		const;
	int getDNSFlagsOPCODE()	const;
	int getDNSFlagsAA()		const;
	int getDNSFlagsTC()		const;
	int getDNSFlagsRD()		const;
	int getDNSFlagsRA()		const;
	int getDNSFlagsZ()		const;
	int getDNSFlagsRCODE()	const;
};