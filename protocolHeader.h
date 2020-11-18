#pragma once

#define ETHERNET_HEADER_LENGTH 14
#define UDP_HEADER_LENGTH 8

#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_ARP 0x0806

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define PORT_HTTP 80

typedef struct MAC_Address {
	char bytes[6];
}MAC_Address;

typedef struct IP_Address {
	char bytes[4];
}IP_Address;

typedef struct Ethernet_Header {
	MAC_Address dst;
	MAC_Address src;
	short eth_type;
}Ethernet_Header;

typedef struct IP_Header {
	char		ver_headerLen;			// 版本号(4 bits) + 首部长度(4 bits)
	char		service;				// 服务类型
	short		total_len;				// 总长度
	short		identifier;				// 标识
	short		flags_offset;			// 标志(3 bits) + 片偏移(13 bits)
	char		ttl;					// 生存时间
	char		protocol;				// 上层协议
	short		checksum;				// 首部校验和
	IP_Address	src;					// 源地址
	IP_Address	dst;					// 目的地址
	int			option_padding; 		// 选项和填充

}IP_Header;

typedef struct TCP_Header {
	short		src;					// 源端口
	short		dst;    				// 目的端口
	int 		seq;					// 序号
	int 		ack;					// 确认号
	short		headerLen_rsv_flags;	// 首部长度(4 bits) + 保留(6 bits) + 
										// URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
	short		win_size;				// 窗口大小
	short		checksum;				// 校验和
	short		urg_ptr;				// 紧急指针
	int 		option;					// 选项

}TCP_Header;

typedef struct UDP_Header {
	short		src;					// 源端口
	short		dst;					// 目的端口
	short		len;					// 长度
	short		checksum;				// 校验和

}UDP_Header;