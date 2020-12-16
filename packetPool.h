#pragma once
#include <map>
#include "pcap.h"
#include "packetHeader.h"

class packetPool {
private:
	std::map<int, packet> m_packet;
public:
	packetPool();
	~packetPool();

	void add(const struct pcap_pkthdr* header, const u_char* pkt_data);	// 添加数据包到数据包池
	void add(packet& pkt);												// 添加数据包到数据包池
	void remove(int pktNum);											// 从数据包池中删除数据包
	void clear();														// 清除数据包池中全部数据包
	packet& get(int pktNum);											// 获取数据包池中对应数据包
	packet& getLast();													// 获取数据包池中最后一个数据包
	int getSize() const;												// 获取数据包池中数据包个数
	bool isEmpty() const;												// 判断数据包池是否为空
};