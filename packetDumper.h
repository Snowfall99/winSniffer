#pragma once
#include "stdafx.h"

class packetDumper {
private:
	CString m_path;
public:
	packetDumper();
	~packetDumper();

	void setPath(CString path);
	CString getPath();

	void dump(CString path);
	void copyFile(CFile* dst, CFile* src);
};