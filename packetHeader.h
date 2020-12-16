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

	int decodeEthernet();							// 解析Ethernet数据包
	int decodeIP(u_char* L2Payload);				// 解析IP数据包
	int decodeIPv6(u_char* L2Payload);				// 解析IPv6数据包
	int decodeARP(u_char* L2Payload);				// 解析ARP数据包
	int decodeICMP(u_char* L3Payload);				// 解析ICMP数据包
	int decodeIGMP(u_char* L3PayLoad);				// 解析IGMP数据包
	int decodeTCP(u_char *L3Payload);				// 解析TCP数据包
	int decodeUDP(u_char *L3Payload);				// 解析UDP数据包
	int decodeHTTP(u_char *L4Payload);				// 解析HTTP数据包

	int getIPHeaderLength() const;					// 获取IP数据包头部长度
	int getIPHeaderLengthRaw() const;				// 获取IP数据包头部长度(RAW)
	int getIPFlags() const;							// 获取IP数据包标志位
	int getIPFlagsMF() const;						// 获取IP数据包MF标志位
	int getIPFlagDF() const;						// 获取IP数据包DF标志位
	int getIPOffset() const;						// 获取IP数据包片偏移量
	
	bool search(CString keyword);					// 根据搜索信息搜索数据包

	u_short getICMPID()	const;						// 获取ICMP数据包ID
	u_short getICMPSeq() const;						// 获取ICMP数据包Seq

	int getTCPHeaderLength() const;					// 获取TCP数据包头部长度
	int getTCPHeaderLengthRaw() const;				// 获取TCP数据包头部长度(RAW)
	u_short getTCPFlags()		const;				// 获取TCP数据包标志位
	int getTCPFlagsURG()	const;					// 获取TCP数据包URG标志位
	int getTCPFlagsACK()	const;					// 获取TCP数据包ACK标志位
	int getTCPFlagsPSH()	const;					// 获取TCP数据包PSH标志位
	int getTCPFlagsRST()	const;					// 获取TCP数据包RST标志位
	int getTCPFlagsSYN()	const;					// 获取TCP数据包SYN标志位
	int getTCPFlagsFIN()	const;					// 获取TCP数据包FIN标志位

	int getL4PayloadLength() const;					// 获取数据包第四层负载长度
};

CString getIPMessage(packet pkt);					// 获取IP数据包对应信息
CString getIPv6Message(packet pkt);					// 获取IPv6数据包对应信息
CString getARPMessage(packet pkt);					// 获取ARP数据包对应信息