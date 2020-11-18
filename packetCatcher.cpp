#include "pch.h"
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

bool packetCatcher::setPool(packetPool* pool) {
	if (pool) {
		m_pool = pool;
		return true;
	}
	else {
		return false;
	}
}

bool packetCatcher::openAdapter(int setItemIndexOfDevList, const CTime& currentTime) {
	if (setItemIndexOfDevList < 0 || m_adhandle) {
		return false;
	}
	int count = 0, setDevIndex = setItemIndexOfDevList - 1;
	pcap_if_t* dev, * allDevs;
	if (pcap_findalldevs(&allDevs, NULL) == -1) {
		AfxMessageBox(_T("pcap_findalldevs failed!"), MB_OK);
		return false;
	}

	for (dev = allDevs; cout < setDevIndex; dev = dev->next, count++);

	m_dev = dev->description = CString(" ( ") + dev->name + " ) ";

	if ((m_adhandle = pcap_open_live(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, READ_PACKET_TIMEOUT, NULL) == NULL) {
		AfxMessageBox(_t("pcap_open_live failed!"), MB_OK);
		return false;
	}

	CString file = "SnifferUI_" + currentTime.Format("%Y%m%d%H%M%S") + ".pcap";
	CString path = ".\\tmp\\" + file;
	m_dumper = pcap_dump_open(m_adhandle, path);

	pcap_freealldevs(allDevs);
	return true;
}

bool packetCatcher::openAdapter(CString path) {
	if (path.IsEmpty()) {
		return false;
	}
	m_dev = path;
	if (m_adhandle = pcap_open_offline(path, NULL) == NULL) {
		AfxMessageBox(_T("pcap_open_offline failed!"), MB_OK);
		return false;
	}
	return true;
}

bool packetCatcher::closeAdapter() {
	if (m_adhandle) {
		pcap_close(m_adhandle);
		m_adhandle = NULL;
		if (m_dumper) {
			pcap_dump_close(m_dumper);
			m_dumper = NULL;
		}
		return true;
	}
	return false;
}

void packetCatcher::startCapture(int mode) {
	if (m_adhandle && m_pool) {
		AfxBeginThread(capture_thread, new threadParam(m_adhandle, m_pool, m_dumper, mode));
	}
}

void packetCatcher::stopCapture() {
	if (m_adhandle) {
		pcap_breakloop(m_adhandle);
	}
}

CString packetCatcher::getDevName() {
	return m_dev;
}

int capture_thread(LPVOID pParam) {
	threadParam* p = (threadParam)pParam;
	pcap_loop(p->m_adhandle, -1, packet_handler, (unsigned char*)p);
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_TEXTIT, NULL, NULL);
	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	threadParam* threadParam = (threadParam*)param;
	switch (threadParam->m_mode) {
	case MODE_CAPTURE_LIVE:
	{
		threadParam->m_pool->add(header, pkt_data);
		pcap_dump((u_char*)threadParam->m_dumper, header, pkt_data);
		break;
	}
	case MODE_CAPTURE_OFFLINE:
	{
		threadParam->m_pool->add(header, pkt_data);
		break;
	}
	}

	PostMessage(AfxGetMainWnd()->m_hWnd, WM_PKTCATCH, NULL, (LPARAM)(threadParam->m_pool->getLast().num));
}
