#include "stdafx.h"
#include "ThreadParam.h"

threadParam::threadParam()
{
	m_adhandle = NULL;
	m_pool = NULL;
}

threadParam::threadParam(pcap_t* adhandle, packetPool* pool, pcap_dumper_t* dumper, int mode)
{
	m_adhandle = adhandle;
	m_pool = pool;
	m_dumper = dumper;
	m_mode = mode;
}

threadParam::~threadParam()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}