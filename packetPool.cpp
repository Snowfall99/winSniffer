#include "pch.h"
#include "stdafx.h"
#include "packetPool.h"

packetPool::packetPool() {

}

packetPool::~packetPool() {

}

void packetPool::add(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (header && pkt_data) {
		int pktNum = 1 + m_packet.size();
		packet pkt(header, pkt_data, pktNum);
		m_packet[pktNum] = pkt;
	}
}

void packetPool::add(packet& pkt) {
	if (!pkt.isEmpty())
		m_packet[pkt.num] = pkt;
}

void packetPool::remove(int pktNum) {
	if (pktNum < 1 || pktNum > m_packet.size()) {
		return;
	}
	m_packet.erase(pktNum);
}

void packetPool::clear() {
	if (m_packet.size() > 0)
		m_packet.clear();
}

packet& packetPool::get(int pktNum) {
	if (m_packet.count(pktNum) > 0)
		return m_packet[pktNum];
	return packet();
}

packet& packetPool::getLast() {
	if (m_packet.count(m_packet.size()) > 0)
		return m_packet[m_packet.size()];
	return packet();
}

int packetPool::getSize() const {
	return m_packet.size();
}

bool packetPool::isEmpty() const {
	if (m_packet.size())
		return false;
	return true;
}