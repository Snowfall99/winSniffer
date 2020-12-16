#pragma once
#include "stdafx.h"

class packetDumper {
private:
	CString m_path;
public:
	packetDumper();
	~packetDumper();

	void setPath(CString path);						// 设置缓存路径
	CString getPath();								// 获取路径

	void dump(CString path);						// 网卡信息缓存
	void copyFile(CFile* dst, CFile* src);			// 复制文件
};