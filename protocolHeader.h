#pragma once

#define ETHERNET_HEADER_LENGTH	14
#define UDP_HEADER_LENGTH		8
#define DNS_HEADER_LENGTH		12

#define ETHERNET_TYPE_IP		0x0800
#define ETHERNET_TYPE_IPv6		0x86DD
#define ETHERNET_TYPE_ARP		0x0806

#define PROTOCOL_ICMP			1
#define PROTOCOL_IGMP			2		
#define PROTOCOL_TCP			6
#define PROTOCOL_UDP			17

#define PORT_HTTP				80

#define ARP_OPCODE_REQUEST		1
#define ARP_OPCODE_REPLY		2

/**
*	@brief	ICMP Type
*/
#define ICMP_TYPE_ECHO_REPLY													0
#define	ICMP_TYPE_DESTINATION_UNREACHABLE										3
#define ICMP_TYPE_SOURCE_QUENCH													4
#define ICMP_TYPE_REDIRECT														5
#define ICMP_TYPE_ECHO															8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT											9
#define ICMP_TYPE_ROUTER_SOLICITATION											10
#define ICMP_TYPE_TIME_EXCEEDED													11
#define ICMP_TYPE_PARAMETER_PROBLEM												12
#define ICMP_TYPE_TIMESTAMP														13
#define ICMP_TYPE_TIMESTAMP_REPLY												14

/**
*	@brief	ICMP Code
*/
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE					0
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE					1
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE				2
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE					3
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_FRAGMENTATION_NEEDED_AND_DF_SET	4
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_SOURCE_ROUTE_FAILED				5

#define ICMP_TYPE_SOURCE_QUENCH_CODE											0

#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK				0
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST					1
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK		2
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST			3

#define ICMP_TYPE_ECHO_CODE														0

#define ICMP_TYPE_ROUTER_ADVERTISEMENT_CODE										0
#define ICMP_TYPE_ROUTER_SOLICITATION_CODE										0

#define ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT					0
#define ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE			1

#define ICMP_TYPE_PARAMETER_PROBLEM_CODE_POINTER_INDICATES_THE_ERROR			0	

#define ICMP_TYPE_TIMESTAMP_CODE												0

/* 6位 Mac地址 */
typedef struct MAC_Address {
	u_char bytes[6];
}MAC_Address;

/* 4位IP地址 */
typedef struct IP_Address {
	u_char bytes[4];
}IP_Address;

typedef struct IPv6_Address {
	u_char bytes[16];
}IPv6_Address;

/* 数据链路层Ethernet */
typedef struct Ethernet_Header {
	MAC_Address dst;	// 目的MAC地址
	MAC_Address src;	// 源MAC地址
	u_short eth_type;	// 类型
}Ethernet_Header;

/* IP数据包头部 */
typedef struct IP_Header {
	u_char		ver_headerLen;			// 版本号(4 bits) + 首部长度(4 bits)
	u_char		tos;					// 服务类型
	u_short		total_len;				// 总长度
	u_short		identifier;				// 标识
	u_short		flags_offset;			// 标志(3 bits) + 片偏移(13 bits)
	u_char		ttl;					// 生存时间
	u_char		protocol;				// 协议
	u_short		checksum;				// 首部校验和
	IP_Address	src;					// 源地址
	IP_Address	dst;					// 目的地址
	u_int		option_padding; 		// 选项和填充				
}IP_Header;

/* ipv6数据包头部 */
typedef struct IPv6_Header {
	u_char			version;				// 版本号(4bits)
	u_char			traffic;				// 优先级(8bits)
	u_short			label;					// 流标识(20bits）
	u_char			length[2];				// 报文长度（16 bit）
	u_char			next_header;			// 下一头部（8 bit）
	u_char			limits;					// 跳数限制（8 bit）
	IPv6_Address	src;					// 源IPv6地址（128 bit）
	IPv6_Address	dst;					// 目的IPv6地址（128 bit）
} ipv6_header;

/* ARP数据包头部 */
typedef struct ARP_Header {
	u_short		hw_type;				// 16位硬件类型
	u_short		protocol_type;			// 16位协议类型
	u_char		hw_len;					// 8位硬件长度
	u_char		protocol_len;			// 8位协议长度
	u_short		opcode;					// 16位操作码
	MAC_Address	src_mac;				// 源MAC地址
	IP_Address	src_ip;					// 源IP地址
	MAC_Address	dst_mac;				// 目的MAC地址
	IP_Address	dst_ip;					// 目的IP地址
	u_char		padding[18];			// 填充
}ARP_Header;

/* ICMP数据包头部 */
typedef struct ICMP_Header {
	u_short		icmp_type;				// 类型
	u_char		icmp_code;				// 代码
	u_short		icmp_checksum;			// 校验和
	u_short		icmp_id;				// ICMP ID
	u_short		icmp_seq;				// 序列号
	u_short		icmp_timestamp;			// 时间戳
}ICMP_Header;

/* IGMP数据包头部 */
typedef struct IGMP_Header {
	u_short		igmp_type;				// 类型
	u_short		max_resp;				// 最大响应时延
	u_short		igmp_checksum;			// 校验和
	IP_Address	group_addr;				// 组地址
}IGMP_Header;

/* TCP数据包头部 */
typedef struct TCP_Header {
	u_short		src;					// 16位源端口
	u_short		dst;    				// 16位目的端口
	u_int 		seq;					// 32位序号
	u_int 		ack;					// 32位确认号
	u_short		headerLen_rsv_flags; 	// 首部长度(4 bits) + 保留(6 bits) +  
										// URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
	u_short		win_size;				// 16位窗口大小
	u_short		checksum;				// 16位校验和
	u_short		urg_ptr;				// 16位紧急指针
	u_int 		option;					// 选项
}TCP_Header;

/* UDP数据包头部 */
typedef struct UDP_Header {
	u_short		src;					// 源端口
	u_short		dst;					// 目的端口
	u_short		len;					// 长度
	u_short		checksum;				// 校验和

}UDP_Header;
