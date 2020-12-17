#include "pch.h"
#include "stdafx.h"
#include "packetHeader.h"
#include "pcap.h"
#include "utils.h"

packet::packet() {
	eth_header = NULL;
	ip_header = NULL;
	ipv6_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	igmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	http_msg = NULL;

	packet_data = NULL;
	num = -1;
	header = NULL;
}

packet::packet(const packet& p) {
	eth_header = NULL;
	ip_header = NULL;
	ipv6_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	igmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	http_msg = NULL;

	if (!p.isEmpty()) {
		u_int caplen = p.header->caplen;

		packet_data = (u_char*)malloc(caplen);
		memcpy(packet_data, p.packet_data, caplen);

		header = (struct pcap_pkthdr*)malloc(sizeof(*(p.header)));
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else {
		packet_data = NULL;
		header = NULL;
		num = -1;
	}
}

packet::packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& packet_num) {
	eth_header = NULL;
	ip_header = NULL;
	ipv6_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	igmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	http_msg = NULL;
	num = packet_num;

	if (pkt_data != NULL && header != NULL) {
		this->packet_data = (u_char*)malloc(header->caplen);
		memcpy(this->packet_data, pkt_data, header->caplen);

		this->header = (struct pcap_pkthdr*)malloc(sizeof(*header));
		memcpy(this->header, header, sizeof(*header));

		decodeEthernet();
	}
	else {
		this->packet_data = NULL;
		this->header = NULL;
	}
}

packet& packet::operator=(const packet& p) {
	if (this == &p) {
		return *this;
	}
	eth_header = NULL;
	ip_header = NULL;
	ipv6_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	igmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	
	if (!p.isEmpty()) {
		int caplen = p.header->caplen;
		if (packet_data == NULL) {
			packet_data = (u_char*)malloc(caplen);
		}
		memcpy(packet_data, p.packet_data, caplen);

		if (header == NULL) {
			header = (struct pcap_pkthdr*)malloc(sizeof(*(p.header)));
		}
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	} else {
		packet_data = NULL;
		header = NULL;
		http_msg = NULL;
		num = -1;
	}
	return *this;
}

packet::~packet() {
	eth_header = NULL;
	ip_header = NULL;
	ipv6_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	igmp_header = NULL;
	tcp_header = NULL;
	udp_header = NULL;
	http_msg = NULL;
	num = -1;

	free(packet_data);
	packet_data = NULL;

	free(header);
	header = NULL;
	protocol.Empty();
}

bool packet::isEmpty() const {
	if (packet_data == NULL || header == NULL) {
		return true;
	} 
	return false;
}

int packet::decodeEthernet() {
	if (isEmpty()) {
		return -1;
	}
	
	protocol = "Ethernet";
	eth_header = (Ethernet_Header*)packet_data;

	switch (ntohs(eth_header->eth_type)) {
	case ETHERNET_TYPE_IP:
		decodeIP(packet_data + ETHERNET_HEADER_LENGTH);
		break;
	case ETHERNET_TYPE_IPv6:
		decodeIPv6(packet_data + ETHERNET_HEADER_LENGTH);
		break;
	case ETHERNET_TYPE_ARP:
		decodeARP(packet_data + ETHERNET_HEADER_LENGTH);
		break;
	default:
		break;
	}
	return 0;
}

int packet::decodeIP(u_char* L2Payload) {
	if (L2Payload == NULL) {
		return -1;
	}

	protocol = "IPv4";
	ip_header = (IP_Header*)(L2Payload);
	short IPHeaderLen = (ip_header->ver_headerLen & 0x0f) * 4;

	switch (ip_header->protocol) {
	case PROTOCOL_ICMP:
		decodeICMP(L2Payload + IPHeaderLen);
		break;
	case PROTOCOL_IGMP:
		decodeIGMP(L2Payload + IPHeaderLen);
		break;
	case PROTOCOL_TCP:
		decodeTCP(L2Payload + IPHeaderLen);
		break;
	case PROTOCOL_UDP:
		decodeUDP(L2Payload + IPHeaderLen);
		break;
	default:
		break;
	}
	return 0;
}

int packet::decodeIPv6(u_char* L2Payload) {
	if (L2Payload == NULL) {
		return -1;
	}

	protocol = "IPv6";
	ipv6_header = (IPv6_Header*)(L2Payload);
	
	return 0;
}

int packet::decodeARP(u_char* L2Payload) {
	if (L2Payload == NULL) {
		return -1;
	}

	protocol = "ARP";
	arp_header = (ARP_Header*)(L2Payload);

	return 0;
}

int packet::decodeICMP(u_char* L3Payload) {
	if (L3Payload == NULL) {
		return -1;
	}

	protocol = "ICMP";
	icmp_header = (ICMP_Header*)(L3Payload);
	return 0;
}

int packet::decodeIGMP(u_char* L3Payload) {
	if (L3Payload == NULL) {
		return -1;
	}

	protocol = "IGMP";
	igmp_header = (IGMP_Header*)(L3Payload);
	return 0;
}

int packet::decodeTCP(u_char* L3Payload) {
	if (L3Payload == NULL) {
		return -1;
	} 
	
	protocol = "TCP";
	tcp_header = (TCP_Header*)(L3Payload);

	short TCPHeaderLen = (ntohs(tcp_header->headerLen_rsv_flags) >> 12) * 4;
	if (ntohs(tcp_header->src) == PORT_HTTP || ntohs(tcp_header->dst) == PORT_HTTP) {
		int HTTPMsgLen = getL4PayloadLength();
		if (HTTPMsgLen > 0) {
			decodeHTTP(L3Payload + TCPHeaderLen);
		}
	}
	return 0;
}

int packet::decodeUDP(u_char* L3Payload) {
	if (L3Payload == NULL) {
		return -1;
	}

	protocol = "UDP";
	udp_header = (UDP_Header*)(L3Payload);

	return 0;
}

int packet::decodeHTTP(u_char* L4Payload) {
	if (L4Payload == NULL) {
		return 1;
	}

	protocol = "HTTP";
	http_msg = L4Payload;
	
	return 0;
}

int packet::getIPHeaderLength() const {
	if (ip_header == NULL) return -1;
	else return (ip_header->ver_headerLen & 0x0f) * 4;
}

int packet::getIPHeaderLengthRaw() const {
	if (ip_header == NULL) return -1;
	else return (ip_header->ver_headerLen & 0x0f);
}

int packet::getIPFlags() const {
	if (ip_header == NULL) return -1;
	else return (ntohs(ip_header->flags_offset) >> 13);
}

int packet::getIPFlagDF() const {
	if (ip_header == NULL) return -1;
	else return (ntohs(ip_header->flags_offset) >> 13) & 0x0001;
}

int packet::getIPFlagsMF() const {
	if (ip_header == NULL) return -1;
	else return (ntohs(ip_header->flags_offset) >> 14) & 0x0001;
}

int packet::getIPOffset() const {
	if (ip_header == NULL) return -1;
	else return ntohs(ip_header->flags_offset) & 0x1fff;
}

u_short packet::getICMPID() const {
	if (icmp_header == NULL) {
		return -1;
	}
	else
	{
		return (u_short)(ntohl(icmp_header->icmp_id));
	}
}

u_short packet::getICMPSeq() const {
	if (icmp_header == NULL) {
		return -1;
	}
	else {
		return (u_short)(ntohl(icmp_header->icmp_seq) & 0x0000FFFF);
	}
}

int packet::getTCPHeaderLength() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 12) * 4;
}

int packet::getTCPHeaderLengthRaw() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 12);
}

u_short packet::getTCPFlags() const {
	if (tcp_header == NULL) return -1;
	else return ntohs(tcp_header->headerLen_rsv_flags) & 0xFF;
}

int packet::getTCPFlagsURG() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 5) & 0x0001;
}

int packet::getTCPFlagsACK() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 4) & 0x0001;
}

int packet::getTCPFlagsPSH() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 3) & 0x01;
}

int packet::getTCPFlagsRST() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 2) & 0x01;
}

int packet::getTCPFlagsSYN() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 1) & 0x01;
}

int packet::getTCPFlagsFIN() const {
	if (tcp_header == NULL) return -1;
	else return ntohs(tcp_header->headerLen_rsv_flags) & 0x01;
}

int packet::getL4PayloadLength() const {
	if (ip_header == NULL || tcp_header == NULL) {
		return -1;
	}

	if (ip_header->total_len == NULL) { return -1; }
	int IPTotalLen = ntohs(ip_header->total_len);
	int IPHeaderLen = (ip_header->ver_headerLen & 0x0f) * 4;
	int TCPHeaderLen = (ntohs(tcp_header->headerLen_rsv_flags) >> 12) * 4;

	return IPTotalLen - IPHeaderLen - TCPHeaderLen;
}

CString getARPMessage(packet pkt) {
	CString message;
	if (pkt.arp_header != NULL) {
		switch (ntohs(pkt.arp_header->opcode)) {
		case ARP_OPCODE_REQUEST:
			message = IPAddr2CString(pkt.arp_header->src_ip) + _T(" request MAC address of ") + IPAddr2CString(pkt.arp_header->dst_ip);
			break;
		case ARP_OPCODE_REPLY:
			message = IPAddr2CString(pkt.arp_header->src_ip) + _T(" reply ") + IPAddr2CString(pkt.arp_header->dst_ip);
			break;
		default:
			break;
		}
		return message;
	}
	else {
		return NULL;
	}
}

CString getIPv6Message(packet pkt) {
	CString message;
	if (pkt.ipv6_header != NULL) {
		message = _T("From ") + IPv6Addr2CString(pkt.ipv6_header->src) + _T(" to ") + IPv6Addr2CString(pkt.ipv6_header->dst);
		return message;
	}
	else {
		return NULL;
	}
	
}

CString getIPMessage(packet pkt) {
	CString message;
	if (pkt.ip_header != NULL) {
		switch (pkt.ip_header->protocol) {
		case PROTOCOL_ICMP:
			message.Format(_T("Type: %u"), pkt.icmp_header->icmp_type);
			break;
		case PROTOCOL_IGMP:
			message.Format(_T("Type: %u"), pkt.igmp_header->igmp_type);
			break;
		case PROTOCOL_TCP:
			message = _T("From ") + IPAddr2CString(pkt.ip_header->src) + _T(" to ") + IPAddr2CString(pkt.ip_header->src);
			break;
		case PROTOCOL_UDP:
			message = _T("From ") + IPAddr2CString(pkt.ip_header->src) + _T(" to ") + IPAddr2CString(pkt.ip_header->dst);
			break;
		default:
			break;
		}
		return message;
	}
	else {
		return NULL;
	}
}

bool packet::search(CString keyword) {
	CString message, strTmp;
	u_char* data;
	int len_data = getL4PayloadLength();
	data = (packet_data + 54);

	for (int i = 0; i < len_data; i++) {
		strTmp.Format(_T("%c"), *data);
		message += strTmp;
	}

	if (message == keyword) {
		return true;
	}
	return false;
}