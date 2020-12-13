#include "pch.h"
#include "stdafx.h"
#include "utils.h"

CString MACAddr2CString(const MAC_Address& addr) {
	CString strAddr, strTmp;

	for (int i = 0; i < 6; i++) {
		strTmp.Format(_T("%02X"), addr.bytes[i]);
		strAddr += strTmp + _T("-");
	}
	strAddr.Delete(strAddr.GetLength() - 1);

	return strAddr;
}

CString IPAddr2CString(const IP_Address& addr) {
	CString strAddr, strTmp;

	for (int i = 0; i < 3; i++) {
		strTmp.Format(_T("%d"), addr.bytes[i]);
		strAddr += strTmp + _T(".");
	}
	strTmp.Format(_T("%d"), addr.bytes[3]);
	strAddr += strTmp;

	return strAddr;
}

CString IPv6Addr2CString(const IPv6_Address& addr) {
	CString strAddr, strTmp;

	for (int i = 0; i < 7; i++) {
		strTmp.Format(_T("%02X"), addr.bytes[2*i]);
		strAddr += strTmp;
		strTmp.Format(_T("%02X"), addr.bytes[2 * i + 1]);
		strAddr += strTmp + _T(":");
	}
	strTmp.Format(_T("%02X"), addr.bytes[14]);
	strAddr += strTmp;
	strTmp.Format(_T("%02X"), addr.bytes[15]);
	strAddr += strTmp;

	return strAddr;
}