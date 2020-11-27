#include "pch.h"
#include "packetDumper.h"

packetDumper::packetDumper() {}
packetDumper::~packetDumper() {}

void packetDumper::setPath(CString path) {
	m_path = path;
}

CString packetDumper::getPath() {
	return m_path;
}

void packetDumper::dump(CString path) {
	CFile dumpFile(m_path, CFile::modeRead | CFile::shareDenyNone);
	CFile saveAsFile(path, CFile::modeCreate | CFile::modeWrite);

	copyFile(&saveAsFile, &dumpFile);

	saveAsFile.Close();
	dumpFile.Close();
}

void packetDumper::copyFile(CFile* dst, CFile* src) {
	char buf[1024];
	int byteCount;

	while ((byteCount = src->Read(buf, sizeof(buf))) > 0) {
		dst->Write(buf, byteCount);
	}
}