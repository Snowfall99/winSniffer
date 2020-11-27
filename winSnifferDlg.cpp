
// winSnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "pcap.h"
#include "threadParam.h"
#include "packet.h"
#include "framework.h"
#include "winSniffer.h"
#include "resource.h"
#include "winSnifferDlg.h"
#include "afxdialogex.h"
#include "threadParam.h"
#include <vector>

#define _CRT_SECURE_NO_WARNINGS

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define IPTOSBUFFERS    12
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void initialComboBoxDevList();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)

END_MESSAGE_MAP()


// CwinSnifferDlg 对话框



CwinSnifferDlg::CwinSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_WINSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_catcher.setPool(m_pool);			// catcher 初始化

	/* 标志初始化 */
	m_pktCaptureFlag = false;
	m_fileOpenFlag = false;
}

void CwinSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PACKET_LIST, m_listCtrlPacketList);
	DDX_Control(pDX, IDC_COMBO_DEVLIST, m_comboBoxDevList);
	DDX_Control(pDX, IDC_COMBO_FILTERLIST, m_comboBoxFilterList);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrlPacketDetails);
}

BEGIN_MESSAGE_MAP(CwinSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START_BUTTON, &CwinSnifferDlg::OnBnClickedStartButton)
	ON_BN_CLICKED(IDC_END_BUTTON, &CwinSnifferDlg::OnBnClickedEndButton)
	// ON_NOTIFY(LVN_ITEMCHANGED, IDC_PACKET_LIST, &CwinSnifferDlg::initialListCtrlPacketList)
	//ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, &CwinSnifferDlg::initialTreeCtrlPacketDetails)
	ON_EN_CHANGE(IDC_EDIT1, &CwinSnifferDlg::test)
	ON_CBN_EDITUPDATE(IDC_COMBO_DEVLIST, &CwinSnifferDlg::initialDevList)
	ON_CBN_EDITUPDATE(IDC_COMBO_FILTERLIST, &CwinSnifferDlg::initialFilterList)
END_MESSAGE_MAP()


// CwinSnifferDlg 消息处理程序

BOOL CwinSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	initialDevList();
	initialFilterList();
	initialListCtrlPacketList();
	initialTreeCtrlPacketDetails();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CwinSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CwinSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CwinSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/******************************************
* 按钮事件实现
* *****************************************/

void CwinSnifferDlg::OnBnClickedStartButton()
{
	// TODO: 在此添加控件通知处理程序代码
	time_t tt = time(NULL);
	localtime(&tt);
	CTime currentTime(tt);

	/* 若没有选中网卡，报提示信息；否则，创建线程抓包 */
	int setItemIndex = m_comboBoxDevList.GetCurSel();
	if (setItemIndex <= 0)
	{
		AfxMessageBox(_T("Please choose Adapter"), MB_OK);
		return; 
	}

	pcap_if_t* dev;
	pcap_if_t* alldevs;
	pcap_t* m_adhandle;
	char errbuf[1024];
	int count = 0;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		AfxMessageBox(_T("pcap_findalldevs_ex failed"), MB_OK);
		return;
	}

	for (dev = alldevs; count < setItemIndex - 1; dev = dev->next, count++);

	if ((m_adhandle = pcap_open(dev->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		READ_PACKET_TIMEOUT,
		NULL,
		errbuf)) == NULL) {
		AfxMessageBox(_T("pcap_open failed"), MB_OK);
		pcap_freealldevs(alldevs);
		return;
	} 

	pcap_dumper_t* dumpfile;
	char filename[1024];
	strcpy(filename, "pkt_cap");

	dumpfile = pcap_dump_open(m_adhandle, filename);

	AfxMessageBox(_T("Start catching..."), MB_OK);
	GetDlgItem(IDC_START_BUTTON)->EnableWindow(FALSE);
	GetDlgItem(IDC_END_BUTTON)->EnableWindow(TRUE);

	// pcap_loop(m_adhandle, -1, packet_handler, (unsigned char*)dumpfile);
	return;
}

void CwinSnifferDlg::OnBnClickedEndButton()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_START_BUTTON)->EnableWindow(TRUE);
	GetDlgItem(IDC_END_BUTTON)->EnableWindow(FALSE);
	AfxMessageBox(_T("End Catching..."), MB_OK);
	// m_catcher.stopCapture();
}


/********************************
* 控件初始化
* *******************************/


void CwinSnifferDlg::initialDevList()
{
	// TODO: 在此添加控件通知处理程序代码
	CString str;
	str = "Choose Adapter";
	m_comboBoxDevList.AddString(str);
	m_comboBoxDevList.SetCurSel(0);

	pcap_if_t* dev = NULL;
	pcap_if_t* allDevs = NULL;
	char errbuf[1024];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevs, errbuf) == -1) {
		AfxMessageBox(_T("pcap_findallDevs fails"), MB_OK);
		return;
	}

	pcap_addr_t* addr;
	char ip6str[128];
	CString strname;
	for (dev = allDevs; dev != NULL; dev = dev->next) {
		if (dev->description != NULL) {
			addr = dev->addresses;
			strname = dev->description;
			str = ip6tos(addr->addr, ip6str, sizeof(ip6str));
			m_comboBoxDevList.AddString(strname + ": " + str);
		}
	}
}

void CwinSnifferDlg::initialFilterList()
{
	// TODO: 在此添加控件通知处理程序代码
	std::vector<CString> filterList;
	filterList.push_back(_T("Ethernet"));
	filterList.push_back(_T("IP"));
	filterList.push_back(_T("TCP"));
	filterList.push_back(_T("UDP"));
	filterList.push_back(_T("HTTP"));

	CString str;
	str.Format(_T("Choose filter(optional)"));
	m_comboBoxFilterList.AddString(str);
	m_comboBoxFilterList.SetCurSel(0);

	for (int i = 0; i < filterList.size(); i++) {
		m_comboBoxFilterList.AddString(LPCTSTR(filterList[i]));
	}
}


/* 数据报列表初始化 */
void CwinSnifferDlg::initialListCtrlPacketList()
{
	CRect rect;
	m_comboBoxFilterList.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_PACKET_LIST)->SetWindowPos(NULL, rect.left, rect.bottom + 5, 0, 0, SWP_NOZORDER | SWP_NOSIZE);

	DWORD dwStyle = m_listCtrlPacketList.GetExtendedStyle();	// 添加列表控件的网格线
	dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;
	m_listCtrlPacketList.SetExtendedStyle(dwStyle);

	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);

	int index = 0;
	CString strname;
	strname= "ID";
	m_listCtrlPacketList.InsertColumn(index, strname, LVCFMT_CENTER, double(rect.Width() * 0.05));
	strname = "Time";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.15));
	strname = "Protocol";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.05));
	strname = "Length";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.05));
	strname = "SRC MAC Address";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.175));
	strname = "DST MAC Address";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.175));
	strname = "SRC IP Address";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.175));
	strname = "DST IP Address";
	m_listCtrlPacketList.InsertColumn(++index, strname, LVCFMT_CENTER, double(rect.Width() * 0.175));

}


/* 树形控件初始化 */
void CwinSnifferDlg::initialTreeCtrlPacketDetails()
{
	CRect rect, winRect;
	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_TREE1)->SetWindowPos(NULL, rect.left, rect.bottom + 5, rect.Width() * 0.2, rect.Height() + 125, SWP_NOZORDER);
}


/*****************
* 打印数据包信息
* *************/

/* 打印数据包概要信息到列表控件中 */
/*
* 输入：数据包
* 输出：0-成功，-1-失败 
*/

void CwinSnifferDlg::test()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}