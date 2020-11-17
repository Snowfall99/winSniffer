#include "stdafx.h"
#include "packetCatcher.h"
#include "packet.h"
#include "threadParam.h"
#include "pcap.h"

packetCatcher::packetCatcher() {
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

packetCatcher::packetCatcher(packetPool* pool) {
	m_adhandle = NULL;
	m_pool = pool;
	m_dumper = NULL;
}

packetCatcher::~packetCatcher() {
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

