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

	void add(const struct pcap_pkt_hdr* header, const char* pkt_data);
	void add(packet& pkt);
	void remove(int pktNum);
	void clear();
	packet& get(int pktNum);
	packet& getLast();
	int getSize() const;
	bool isEmpty() const;
};