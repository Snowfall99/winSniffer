
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

	/* 源\目的地址 */
	CString ip_src_addr;
	CString ip_dst_addr;
	CString mac_src_addr;
	CString mac_dst_addr;

	/* 搜索信息 */
	CString search_info;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedStartButton();
	afx_msg void OnBnClickedEndButton();
	afx_msg void OnBnClickedSaveButton();

	CComboBox m_comboBoxDevList;
	CComboBox m_comboBoxFilterList;
	CListCtrl m_listCtrlPacketList;
	CTreeCtrl m_treeCtrlPacketDetails;
	CEdit m_editorCtrlPacketBytes;
	afx_msg void initialListCtrlPacketList();
	afx_msg void initialBtns();
	afx_msg void initialEditCtrl();
	afx_msg void initialTreeCtrlPacketDetails();
	afx_msg void initialDevList();
	afx_msg void initialFilterList();
	afx_msg int printListCtrlPacketList(const packet &pkt);
	afx_msg int printListCtrlPacketList(packetPool& pool);
	afx_msg int printListCtrlPacketList(packetPool& pool, const CString filter, const CString ip_src, const CString ip_dst, const CString mac_src, const CString mac_dst);
	afx_msg int printListCtrlPacketList(packetPool& pool, CString search_info);
	afx_msg int printTreeCtrlPacketDetails(const packet &pkt);
	afx_msg int printEthernet2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printIP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printARP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printICMP2TreeCtrl(const packet& pkt, HTREEITEM& packetNode);
	afx_msg int printIGMP2TreeCtrl(const packet& pkt, HTREEITEM& packetNode);
	afx_msg int printTCP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printUDP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printHTTP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg int printIPv62TreeCtrl(const packet& pkt, HTREEITEM& parentNode);
	afx_msg void initialEditCtrlPacketBytes();
	afx_msg int printEditCtrlPacketBytes(const packet& pkt);
	afx_msg void onClickedList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickedFilterButton();
	CButton m_filter_btn;
	CString m_src_edit;
	CString m_dst_edit;
	CString m_mac_src;
	CString m_mac_dst;
	CString m_search_edit;
	afx_msg void OnBnClickedSearchButton();
};
