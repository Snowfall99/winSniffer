#include "pch.h"
#include "stdafx.h"
#include "packetcatcher.h"
#include "packet.h"
#include "threadparam.h"
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

bool packetCatcher::openAdapter(int setitemindexofdevlist, const CTime& currenttime) {
	if (setitemindexofdevlist < 0 || m_adhandle) {
		return false;
	}
	int count = 0, setdevindex = setitemindexofdevlist - 1;
	pcap_if_t* dev, * alldevs;
	if (pcap_findalldevs(&alldevs, NULL) == -1) {
		AfxMessageBox(_T("pcap_findalldevs failed!"), MB_OK);
		return false;
	}

	for (dev = alldevs; count < setdevindex; dev = dev->next, count++);

	m_dev = dev->description = CString(" ( ") + dev->name + " ) ";

	if ((m_adhandle = pcap_open_live(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS,  READ_PACKET_TIMEOUT, NULL)) == NULL) {
		AfxMessageBox(_T("pcap_open_live failed!"), MB_OK);
		return false;
	}

	CString file = _T("snifferui_") + currenttime.Format("%y%m%d%h%m%s") + _T(".pcap");
	CString path = _T(".\\tmp\\") + file;
	m_dumper = pcap_dump_open(m_adhandle, CStringA(path));

	pcap_freealldevs(alldevs);
	return true;
}

bool packetCatcher::openAdapter(CString path) {
	if (path.IsEmpty()) {
		return false;
	}
	m_dev = path;
	if ((m_adhandle = pcap_open_offline(CStringA(path), NULL)) == NULL) {
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

UINT capture_thread(LPVOID pParam)
{
	threadParam* p = (threadParam*)pParam;

	/* 开始捕获数据包 */
	pcap_loop(p->m_adhandle, -1, packet_handler, (unsigned char*)p);
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_TEXTIT, NULL, NULL);
	return 0;
}

/**
*	@brief	捕获数据包处理函数，全局回调函数
*	@param	param		自定义参数
*	@param	header		数据包首部
*	@param	pkt_data	数据包（帧）
*	@return
*/
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	threadParam* threadparam = (threadParam*)param;
	// 根据捕获模式抓包
	switch (threadparam->m_mode)
	{
	case MODE_CAPTURE_LIVE:
	{
		threadparam->m_pool->add(header, pkt_data);
		pcap_dump((u_char*)threadparam->m_dumper, header, pkt_data);
		break;
	}
	case MODE_CAPTURE_OFFLINE:
	{
		threadparam->m_pool->add(header, pkt_data);
		break;
	}
	}

	// 发送消息给主窗口SnifferUIDlg
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_PKTCATCH, NULL, (LPARAM)(threadparam->m_pool->getLast().num));
}