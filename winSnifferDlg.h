
// winSnifferDlg.h: 头文件
//

#pragma once
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)
#include "afxwin.h"
#include "packetDumper.h"
#include "packetCatcher.h"
#include "packetPool.h"
#define _CRT_SECURE_NO_WARNINGS
// CwinSnifferDlg 对话框
class CwinSnifferDlg : public CDialogEx
{
// 构造
public:
	CwinSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	CToolBar m_toolBarMain;

	/* 标志 */
	bool m_pktCaptureFlag;
	bool m_fileOpenFlag;
	CString m_openFilename;

	/* 数据报相关类 */
	packetCatcher m_catcher;
	packetPool m_pool;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnEnChangeEdit3();
	afx_msg void OnEnChangeEdit5();
	afx_msg void OnBnClickedStartButton();
	afx_msg void OnBnClickedEndButton();

	CComboBox m_comboBoxDevList;
	afx_msg void initialComboDevList();
	CComboBox m_comboBoxFilterList;
	afx_msg void initialComboFilterlist();
	CListCtrl m_listCtrlPacketList;
	afx_msg void initialListCtrlPacketList();
	CTreeCtrl m_treeCtrlPacketDetails;
	afx_msg void initialTreeCtrlPacketDetails();
	afx_msg void initialDevList();
	afx_msg void initialFilterList();
	afx_msg int printListCtrlPacketList(const packet &pkt);
	afx_msg int printListCtrlPacketList(packetPool& pool);
	afx_msg CString MACAddr2CString(const MAC_Address& addr);
	afx_msg CString IPAddr2CString(const IP_Address& addr);
	afx_msg int printTreeCtrlPacketDetails(const packet &pkt);
	afx_msg int printEthernet2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printIP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printARP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printICMP2TreeCtrl(const packet& pkt, HTREEITEM& packetNode);
	afx_msg int printTCP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printUDP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printDNS2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printDHCP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printHTTP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	CEdit m_editorCtrlPacketBytes;
	afx_msg void initialEditCtrlPacketBytes();
	afx_msg int printEditCtrlPacketBytes(const packet& pkt);
	afx_msg void onClickedList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);
};
