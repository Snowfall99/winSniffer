#pragma once
#include "packetHeader.h"
#include "stdafx.h"

/* MAC地址转换为CString格式 */
CString MACAddr2CString(const MAC_Address& addr);

/* IP地址转换为CString格式 */
CString IPAddr2CString(const IP_Address& addr);

/* IPv6地址转换为CString格式 */
CString IPv6Addr2CString(const IPv6_Address& addr);