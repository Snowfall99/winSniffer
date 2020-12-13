#pragma once
#include "packetHeader.h"
#include "stdafx.h"

CString MACAddr2CString(const MAC_Address& addr);

CString IPAddr2CString(const IP_Address& addr);

CString IPv6Addr2CString(const IPv6_Address& addr);