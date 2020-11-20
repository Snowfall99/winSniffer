#pragma once
#include <map>
#include "pcap.h"
#include "packet.h"

class packetPool {
private:
	std::map<int, packet> m_packet;
public:
	packetPool();
	~packetPool();

	void add(const struct pcap_pkthdr* header, const u_char* pkt_data);
	void add(packet& pkt);
	void remove(int pktNum);
	void clear();
	packet& get(int pktNum);
	packet& getLast();
	int getSize() const;
	bool isEmpty() const;
};