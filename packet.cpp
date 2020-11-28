#include "pch.h"
#include "stdafx.h"
#include "packet.h"
#include "pcap.h"

packet::packet() {
	eth_header = NULL;
	ip_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	dns_header = NULL;
	dhcp_header = NULL;
	http_msg = NULL;

	packet_data = NULL;
	num = -1;
	header = NULL;
}

packet::packet(const packet& p) {
	eth_header = NULL;
	ip_header = NULL;
	arp_header = NULL;
	icmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	dns_header = NULL;
	dhcp_header = NULL;
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
	arp_header = NULL;
	icmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	dns_header = NULL;
	dhcp_header = NULL;
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
	arp_header = NULL;
	icmp_header = NULL;
	udp_header = NULL;
	tcp_header = NULL;
	dns_header = NULL;
	dhcp_header = NULL;

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
	arp_header = NULL;
	icmp_header = NULL;
	tcp_header = NULL;
	udp_header = NULL;
	dns_header = NULL;
	dhcp_header = NULL;
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

int packet::decodeTCP(u_char* L3Payload) {
	if (L3Payload == NULL) {
		return -1;
	} 
	
	protocol = "TCP";
	tcp_header = (TCP_Header*)(L3Payload);

	short TCPHeaderLen = (ntohs(tcp_header->headerLen_rsv_flags) >> 12) * 4;
	if (ntohs(tcp_header->src) == PORT_DNS || ntohs(tcp_header->dst) == PORT_DNS) {
		decodeDNS(L3Payload + TCPHeaderLen);
	} else if (ntohs(tcp_header->src) == PORT_HTTP || ntohs(tcp_header->dst) == PORT_HTTP) {
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
	if (ntohs(udp_header->src) == PORT_DNS || ntohs(udp_header->dst) == PORT_DNS) {
		decodeDNS(L3Payload + UDP_HEADER_LENGTH);
	}
	else if ((ntohs(udp_header->src) == PORT_DHCP_CLIENT && ntohs(udp_header->dst) == PORT_DHCP_SERVER) || (ntohs(udp_header->src) == PORT_DHCP_SERVER && ntohs(udp_header->dst) == PORT_DHCP_CLIENT)) {
		decodeDHCP(L3Payload + UDP_HEADER_LENGTH);
	}

	return 0;
}

int packet::decodeDNS(u_char* L4Payload) {
	if (L4Payload == NULL) {
		return -1;
	}

	protocol = "DNS";
	dns_header = (DNS_Header*)(L4Payload);
	return 0;
}

int packet::decodeDHCP(u_char* L4Payload) {
	if (L4Payload == NULL) {
		return -1;
	}

	protocol = "DHCP";
	dhcp_header = (DHCP_Header*)(L4Payload);
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
		return (u_short)(ntohl(icmp_header->others) >> 16);
	}
}

u_short packet::getICMPSeq() const {
	if (icmp_header == NULL) {
		return -1;
	}
	else {
		return (u_short)(ntohl(icmp_header->others) & 0x0000FFFF);
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
	else return ntohs(tcp_header->headerLen_rsv_flags) & 0x0FFF;
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
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 3) & 0x0001;
}

int packet::getTCPFlagsRST() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 2) & 0x0001;
}

int packet::getTCPFlagsSYN() const {
	if (tcp_header == NULL) return -1;
	else return (ntohs(tcp_header->headerLen_rsv_flags) >> 1) & 0x0001;
}

int packet::getTCPFlagsFIN() const {
	if (tcp_header == NULL) return -1;
	else return ntohs(tcp_header->headerLen_rsv_flags);
}

int packet::getL4PayloadLength() const {
	if (ip_header == NULL || tcp_header == NULL) {
		return 0;
	}

	int IPTotalLen = ntohs(ip_header->total_len);
	int IPHeaderLen = (ip_header->ver_headerLen & 0x0f) * 4;
	int TCPHeaderLen = (ntohs(tcp_header->headerLen_rsv_flags) >> 12) * 4;

	return IPTotalLen - IPHeaderLen - TCPHeaderLen;
}

int packet::getDNSFlagsQR() const
{
	if (dns_header == NULL)
		return -1;
	else
		return	dns_header->flags >> 15;
}

int packet::getDNSFlagsOPCODE() const {
	if (dns_header == NULL) {
		return -1;
	}
	else {
		return (ntohs(dns_header->flags) >> 11) & 0x000F;
	}
}

int packet::getDNSFlagsAA() const
{
	if (dns_header == NULL)
		return -1;
	else
		return (ntohs(dns_header->flags) >> 10) & 0x0001;
}

int packet::getDNSFlagsTC() const
{
	if (dns_header == NULL)
		return -1;
	else
		return (ntohs(dns_header->flags) >> 9) & 0x0001;
}

int packet::getDNSFlagsRD() const
{
	if (dns_header == NULL)
		return -1;
	else
		return (ntohs(dns_header->flags) >> 8) & 0x0001;
}

int packet::getDNSFlagsRA() const
{
	if (dns_header == NULL)
		return -1;
	else
		return (ntohs(dns_header->flags) >> 7) & 0x0001;
}

int packet::getDNSFlagsZ() const
{
	if (dns_header == NULL)
		return -1;
	else
		return (ntohs(dns_header->flags) >> 4) & 0x0007;
}

int packet::getDNSFlagsRCODE() const
{
	if (dns_header == NULL)
		return -1;
	else
		return ntohs(dns_header->flags) & 0x000F;
}