
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
	m_catcher.setPool(&m_pool);			// catcher 初始化

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
	DDX_Control(pDX, IDC_EDIT1, m_editorCtrlPacketBytes);
}

BEGIN_MESSAGE_MAP(CwinSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START_BUTTON, &CwinSnifferDlg::OnBnClickedStartButton)
	ON_BN_CLICKED(IDC_END_BUTTON, &CwinSnifferDlg::OnBnClickedEndButton)
	// ON_NOTIFY(LVN_ITEMCHANGED, IDC_PACKET_LIST, &CwinSnifferDlg::initialListCtrlPacketList)
	// ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, &CwinSnifferDlg::initialTreeCtrlPacketDetails)
	ON_CBN_EDITUPDATE(IDC_COMBO_DEVLIST, &CwinSnifferDlg::initialDevList)
	ON_CBN_EDITUPDATE(IDC_COMBO_FILTERLIST, &CwinSnifferDlg::initialFilterList)
	// ON_NOTIFY(LVN_ITEMCHANGED, IDC_PACKET_LIST, &CwinSnifferDlg::printListCtrlPacketList)
	// ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, &CwinSnifferDlg::printTreeCtrlPacketDetails)
	ON_EN_CHANGE(IDC_EDIT1, &CwinSnifferDlg::initialEditCtrlPacketBytes)
	ON_NOTIFY(NM_CLICK, IDC_PACKET_LIST, &CwinSnifferDlg::onClickedList)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_PACKET_LIST, &CwinSnifferDlg::OnCustomDrawList)
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

	if (m_catcher.openAdapter(setItemIndex, currentTime)) {
		AfxMessageBox(_T("Start Catching..."));
		GetDlgItem(IDC_START_BUTTON)->EnableWindow(FALSE);
		GetDlgItem(IDC_END_BUTTON)->EnableWindow(TRUE);

		m_listCtrlPacketList.DeleteAllItems();
		m_treeCtrlPacketDetails.DeleteAllItems();

		m_pool.clear();

		m_catcher.startCapture(MODE_CAPTURE_LIVE);
		m_pktCaptureFlag = true;
	}
}

void CwinSnifferDlg::OnBnClickedEndButton()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_START_BUTTON)->EnableWindow(TRUE);
	GetDlgItem(IDC_END_BUTTON)->EnableWindow(FALSE);
	AfxMessageBox(_T("End Catching..."), MB_OK);
	m_catcher.stopCapture();
	m_pktCaptureFlag = false;

	printListCtrlPacketList(m_pool);
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

/* 数据包字节流显示窗初始化 */
void CwinSnifferDlg::initialEditCtrlPacketBytes()
{
	CRect rect;
	m_treeCtrlPacketDetails.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_EDIT1)->SetWindowPos(NULL, rect.right + 5, rect.top, rect.Width(), rect.Height(), SWP_NOZORDER);
}

/*****************
* 打印数据包信息
* *************/
int CwinSnifferDlg::printListCtrlPacketList(const packet &pkt)
{
	if (pkt.isEmpty()) {
		return -1;
	}

	int row = 0;
	int col = 0;

	CString strNum;
	strNum.Format(_T("%d"), pkt.num);

	UINT mask = LVIF_PARAM | LVIF_TEXT;

	row = m_listCtrlPacketList.InsertItem(mask, m_listCtrlPacketList.GetItemCount(), strNum, 0, 0, 0, (LPARAM)&(pkt.protocol));
	
	CTime pktArrivalTime = ((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");
	m_listCtrlPacketList.SetItemText(row, ++col, strPktArrivalTime);

	if (!pkt.protocol.IsEmpty()) {
		m_listCtrlPacketList.SetItemText(row, ++col, pkt.protocol);
	}
	else {
		col++;
	}

	/* 打印MAC地址 */
	CString strCaplen;
	strCaplen.Format(_T("%d"), pkt.header->caplen);
	m_listCtrlPacketList.SetItemText(row, ++col, strCaplen);

	if (pkt.eth_header != NULL)
	{
		CString strSrcMAC = MACAddr2CString(pkt.eth_header->src);
		CString strDstMAC = MACAddr2CString(pkt.eth_header->dst);

		m_listCtrlPacketList.SetItemText(row, ++col, strSrcMAC);
		m_listCtrlPacketList.SetItemText(row, ++col, strDstMAC);
	}
	else
	{
		col += 2;
	}

	/* 打印源目IP地址 */
	if (pkt.ip_header != NULL)
	{
		CString strSrcIP = IPAddr2CString(pkt.ip_header->src);
		CString strDstIP = IPAddr2CString(pkt.ip_header->dst);

		m_listCtrlPacketList.SetItemText(row, ++col, strSrcIP);
		m_listCtrlPacketList.SetItemText(row, ++col, strDstIP);
	}
	else
	{
		col += 2;
	}
	
	return 0;
}

int CwinSnifferDlg::printListCtrlPacketList(packetPool& pool) {
	if (pool.isEmpty()) {
		AfxMessageBox(_T("Empty pool"));
		return -1;
	}

	int pktNum = pool.getSize();
	AfxMessageBox(_T("%d"), pktNum);
	for (int i = 1; i <= pktNum; i++) {
		printListCtrlPacketList(pool.get(i));
	}

	return pktNum;
}

int CwinSnifferDlg::printEditCtrlPacketBytes(const packet& pkt) {
	if (pkt.isEmpty()) {
		return -1;
	}

	CString strPacketBytes, strTmp;
	u_char* pHexPacketBytes = pkt.packet_data;
	u_char* pASCIIPacketBytes = pkt.packet_data;
	for (int byteCount = 0, byteCount16 = 0, offset = 0; byteCount < pkt.header->caplen && pHexPacketBytes != NULL; ++byteCount)
	{
		/* 若当前字节是行首，打印行首偏移量 */
		if (byteCount % 16 == 0)
		{
			strTmp.Format(_T("%04X:"), offset);
			strPacketBytes += strTmp + _T(" ");
		}

		/* 打印16进制字节 */
		strTmp.Format(_T("%02X"), *pHexPacketBytes);
		strPacketBytes += strTmp + _T(" ");
		++pHexPacketBytes;
		++byteCount16;

		switch (byteCount16)
		{
		case 8:
		{
			/* 每读取8个字节打印一个制表符 */
			strPacketBytes += "\t";
		}
		break;
		case 16:
		{
			/* 每读取16个字节打印对应字节的ASCII字符，只打印字母数字 */
			if (byteCount16 == 16)
			{
				strPacketBytes += " ";
				for (int charCount = 0; charCount < 16; ++charCount, ++pASCIIPacketBytes)
				{
					strTmp.Format(_T("%c"), isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
					strPacketBytes += strTmp;
				}
				strPacketBytes += "\r\n";
				offset += 16;
				byteCount16 = 0;
			}
		}
		break;
		default:break;
		}
	}

	/* 若数据包总长度不是16字节对齐时，打印最后一行字节对应的ASCII字符 */
	if (pkt.header->caplen % 16 != 0)
	{
		/* 空格填充，保证字节流16字节对齐 */
		for (int spaceCount = 0, byteCount16 = (pkt.header->caplen % 16); spaceCount < 16 - (pkt.header->caplen % 16); ++spaceCount)
		{
			strPacketBytes += "  ";
			strPacketBytes += " ";
			++byteCount16;
			if (byteCount16 == 8)
			{
				strPacketBytes += "\t";
				//strPacketBytes += "#";
			}
		}
		strPacketBytes += " ";
		/* 打印最后一行字节对应的ASCII字符 */
		for (int charCount = 0; charCount < (pkt.header->caplen % 16); ++charCount, ++pASCIIPacketBytes)
		{
			strTmp.Format(_T("%c"), isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : _T('.'));
			strPacketBytes += strTmp;
		}
		strPacketBytes += "\r\n";
	}

	m_editorCtrlPacketBytes.SetWindowText(strPacketBytes);

	return 0;
}

int CwinSnifferDlg::printTreeCtrlPacketDetails(const packet& pkt)
{
	if (pkt.isEmpty()) {
		return -1;
	}

	m_treeCtrlPacketDetails.DeleteAllItems();

	/* 建立编号节点 */
	CString strText;

	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");

	strText.Format(_T("No.%d packet (%s, %hu bytes in total, capture %hu bytes)"), pkt.num, strPktArrivalTime, pkt.header->len, pkt.header->caplen);

	HTREEITEM rootNode = m_treeCtrlPacketDetails.InsertItem(strText, TVI_ROOT);
	if (pkt.eth_header != NULL)
	{
		printEthernet2TreeCtrl(pkt, rootNode);
	}

	m_treeCtrlPacketDetails.Expand(rootNode, TVE_EXPAND);
	return 0;
}

int CwinSnifferDlg::printEthernet2TreeCtrl(const packet& pkt, HTREEITEM& parentNode) {
	if (pkt.isEmpty() || pkt.eth_header == NULL || parentNode == NULL) {
		return -1;
	}

	/* 获取源目MAC地址 */
	CString strSrcMAC = MACAddr2CString(pkt.eth_header->src);
	CString	strDstMAC = MACAddr2CString(pkt.eth_header->dst);
	CString strEthType;
	strEthType.Format(_T("0x%04X"), ntohs(pkt.eth_header->eth_type));

	HTREEITEM EthNode = m_treeCtrlPacketDetails.InsertItem(_T("Internet (") + strSrcMAC + _T(" -> ") + strDstMAC + _T("）"), parentNode, 0);

	m_treeCtrlPacketDetails.InsertItem(_T("DST MAC address:") + strDstMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem(_T("SRC MAC address：") + strSrcMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem(_T("Type:") + strEthType, EthNode, 0);

	if (pkt.ip_header != NULL)
	{
		printIP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.arp_header != NULL)
	{
		printARP2TreeCtrl(pkt, parentNode);
	}

	return 0;
}

int CwinSnifferDlg::printIP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode) {
	if (pkt.isEmpty() || pkt.ip_header == NULL || parentNode == NULL) {
		return -1;
	}

	HTREEITEM IPNode = m_treeCtrlPacketDetails.InsertItem(_T("IP(") + IPAddr2CString(pkt.ip_header->src) + "->" + IPAddr2CString(pkt.ip_header->dst) + _T(")"), parentNode, 0);
	CString strText;

	strText.Format(_T("版本号：%d"), pkt.ip_header->ver_headerLen >> 4);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("首部长度：%d 字节（%d）"), pkt.getIPHeaderLength(), pkt.getIPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("服务质量：0x%02X"), pkt.ip_header->service);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("总长度：%hu"), ntohs(pkt.ip_header->total_len));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("标识：0x%04hX（%hu）"), ntohs(pkt.ip_header->identifier), ntohs(pkt.ip_header->identifier));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("标志：0x%02X"), pkt.getIPFlags());
	HTREEITEM IPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "RSV：0";
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format(_T("DF：%d"), pkt.getIPFlagDF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format(_T("MF：%d"), pkt.getIPFlagsMF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format(_T("片偏移：%d"), pkt.getIPOffset());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("TTL：%u"), pkt.ip_header->ttl);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	switch (pkt.ip_header->protocol)
	{
	case PROTOCOL_TCP:	strText = "协议：TCP（6）";	break;
	case PROTOCOL_UDP:	strText = "协议：UDP（17）";	break;
	default:			strText.Format(_T("协议：未知（%d）"), pkt.ip_header->protocol);	break;
	}

	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format(_T("校验和：0x%02hX"), ntohs(pkt.ip_header->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = _T("源IP地址：") + IPAddr2CString(pkt.ip_header->src);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = _T("目的IP地址：") + IPAddr2CString(pkt.ip_header->dst);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);
	
	if (pkt.icmp_header != NULL) {
		printICMP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.tcp_header != NULL)
	{
		printTCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.udp_header != NULL)
	{
		printUDP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

int CwinSnifferDlg::printARP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode) 
{
	if (pkt.isEmpty() || pkt.arp_header == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ARPNode;
	CString strText, strTmp;

	switch (ntohs(pkt.arp_header->opcode))
	{
	case ARP_OPCODE_REQUEST:	strText.Format(_T("ARP（请求)"));	break;
	case ARP_OPCODE_REPLY:		strText.Format(_T("ARP（响应)"));	break;
	default:					strText.Format(_T("ARP"));			break;
	}
	ARPNode = m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, parentNode, 0);

	strText.Format(_T("硬件类型：%hu"), ntohs(pkt.arp_header->hw_type));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format(_T("协议类型：0x%04hx (%hu)"), ntohs(pkt.arp_header->protocol_type), ntohs(pkt.arp_header->protocol_type));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format(_T("硬件地址长度：%u"), pkt.arp_header->hw_len);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format(_T("协议地址长度：%u"), pkt.arp_header->protocol_len);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	switch (ntohs(pkt.arp_header->opcode))
	{
	case ARP_OPCODE_REQUEST:	strText = _T("OP码：请求（%hu）") + ntohs(pkt.arp_header->opcode); break;
	case ARP_OPCODE_REPLY:		strText.Format(_T("OP码：响应（%hu）"), ntohs(pkt.arp_header->opcode));	break;
	default:					strText.Format(_T("OP码：未知（%hu）"), ntohs(pkt.arp_header->opcode));	break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = _T("源MAC地址：") + MACAddr2CString(pkt.arp_header->src_mac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = _T("源IP地址：") + IPAddr2CString(pkt.arp_header->src_ip);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = _T("目的MAC地址：") + MACAddr2CString(pkt.arp_header->dst_mac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = _T("目的IP地址：") + IPAddr2CString(pkt.arp_header->dst_ip);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	return 0;
}

int CwinSnifferDlg::printICMP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.icmp_header == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ICMPNode;
	CString strText, strTmp;

	strText = "ICMP";
	switch (pkt.icmp_header->type)
	{
	case ICMP_TYPE_ECHO_REPLY:					strTmp = "（回应应答报告）";			break;
	case ICMP_TYPE_DESTINATION_UNREACHABLE:		strTmp = "（信宿不可达报告）";		break;
	case ICMP_TYPE_SOURCE_QUENCH:				strTmp = "（源端抑制报告）";			break;
	case ICMP_TYPE_REDIRECT:					strTmp = "（重定向报告）";			break;
	case ICMP_TYPE_ECHO:						strTmp = "（回应请求报告）";			break;
	case ICMP_TYPE_ROUTER_ADVERTISEMENT:		strTmp = "（路由器通告报告）";		break;
	case ICMP_TYPE_ROUTER_SOLICITATION:			strTmp = "（路由器询问报告）";		break;
	case ICMP_TYPE_TIME_EXCEEDED:				strTmp = "（超时报告）";				break;
	case ICMP_TYPE_PARAMETER_PROBLEM:			strTmp = "（数据报参数错误报告）";		break;
	case ICMP_TYPE_TIMESTAMP:					strTmp = "（时间戳请求报告）";		break;
	case ICMP_TYPE_TIMESTAMP_REPLY:				strTmp = "（时间戳响应报告）";		break;
	default:									strTmp.Format(_T("（未知）"));		break;
	}
	strText += strTmp;
	ICMPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	IP_Address addr = *(IP_Address*)&(pkt.icmp_header->others);
	u_short id = pkt.getICMPID();
	u_short seq = pkt.getICMPSeq();

	strText.Format(_T("类型：%u"), pkt.icmp_header->type);
	m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

	switch (pkt.icmp_header->type)
	{
	case ICMP_TYPE_ECHO_REPLY:
	{
		strText = "代码：0";
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和:0x%04hX"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("标识：%hu"), id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("序号：%hu"), seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;
	}


	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strText = "代码：";
		switch (pkt.icmp_header->code)
		{
		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE:
			strText.Format(_T("网络不可达 （%d）"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE:
			strText.Format(_T("主机不可达 （%d）"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE:
			strText.Format(_T("协议不可达 （%d）"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE:
			strText.Format(_T("端口不可达 （%d）"), pkt.icmp_header->code);
			break;

		case 6:
			strTmp = "信宿网络未知 （6）";
			break;

		case 7:
			strTmp = "信宿主机未知 （7）";
			break;

		default:
			strText.Format(_T("未知 （%d）"), pkt.icmp_header->code); break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hX"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_SOURCE_QUENCH:
		strText.Format(_T("代码：%d"), ICMP_TYPE_SOURCE_QUENCH_CODE);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hX"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_REDIRECT:
		strText = "代码：";
		switch (pkt.icmp_header->code)
		{
		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK:
			strText.Format(_T("对特定网络重定向（%d)"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST:
			strText.Format(_T("对特定主机重定向 （%d)"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK:
			strText.Format(_T("基于指定的服务类型对特定网络重定向 （%d）"), pkt.icmp_header->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST:
			strText.Format(_T("基于指定的服务类型对特定主机重定向 （%d）"), pkt.icmp_header->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hx"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText = _T("目标路由器的IP地址：") + IPAddr2CString(addr);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_ECHO:
		strText.Format(_T("代码：%d"), pkt.icmp_header->code);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hX"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("标识：%hu"), id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("序号：%hu"), seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_TIME_EXCEEDED:
		strText = "代码：";
		switch (pkt.icmp_header->code)
		{
		case ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT:
			strText.Format(_T("TTL超时 （%d）"), pkt.icmp_header->code);
			break;
		case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE:
			strText.Format(_T("分片重组超时 （%d）"), pkt.icmp_header->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hx"), ntohs(pkt.icmp_header->checksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;

	default:
		strText.Format(_T("代码：%d"), pkt.icmp_header->code);
		m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, ICMPNode, 0);

		strText.Format(_T("校验和：0x%04hX"), pkt.icmp_header->checksum);
		m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, ICMPNode, 0);

		break;
	}
	return 0;
}

int CwinSnifferDlg::printTCP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.tcp_header == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM TCPNode;
	CString strText, strTmp;

	strText.Format(_T("TCP（%hu -> %hu）"), ntohs(pkt.tcp_header->src), ntohs(pkt.tcp_header->dst));
	TCPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format(_T("源端口：%hu"), ntohs(pkt.tcp_header->src));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("目的端口：%hu"), ntohs(pkt.tcp_header->dst));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("序列号：0x%0lX"), ntohl(pkt.tcp_header->seq));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("确认号：0x%0lX"), ntohl(pkt.tcp_header->ack));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("首部长度：%d 字节（%d）"), pkt.getTCPHeaderLength(), pkt.getTCPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("标志：0x%03X"), pkt.getTCPFlags());
	HTREEITEM TCPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("URG：%d"), pkt.getTCPFlagsURG());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("ACK：%d"), pkt.getTCPFlagsACK());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("PSH：%d"), pkt.getTCPFlagsPSH());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("RST：%d"), pkt.getTCPFlagsRST());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("SYN：%d"), pkt.getTCPFlagsSYN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("FIN：%d"), pkt.getTCPFlagsFIN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(_T("窗口大小：%hu"), ntohs(pkt.tcp_header->win_size));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("校验和：0x%04hX"), ntohs(pkt.tcp_header->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format(_T("紧急指针：%hu"), ntohs(pkt.tcp_header->urg_ptr));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	if (pkt.dns_header != NULL)
	{
		//printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcp_header != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.http_msg != NULL)
	{
		printHTTP2TreeCtrl(pkt, parentNode);
	}

	return 0;
}

int CwinSnifferDlg::printUDP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.udp_header == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM UDPNode;
	CString strText, strTmp;

	strText.Format(_T("UDP（%hu -> %hu）"), ntohs(pkt.udp_header->src), ntohs(pkt.udp_header->dst));
	UDPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format(_T("源端口：%hu"), ntohs(pkt.udp_header->src));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format(_T("目的端口：%hu"), ntohs(pkt.udp_header->dst));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format(_T("长度：%hu"), ntohs(pkt.udp_header->len));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format(_T("校验和：0x%04hX"), ntohs(pkt.udp_header->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	if (pkt.dns_header != NULL)
	{
		//printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcp_header != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

int CwinSnifferDlg::printDHCP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.dhcp_header == NULL || parentNode == NULL)
	{
		return -1;
	}

	HTREEITEM DHCPNode = m_treeCtrlPacketDetails.InsertItem(_T("DHCP"), parentNode, 0);
	CString strText, strTmp;
	/* 解析dhcp首部 */
	strText.Format(_T("报文类型：%d"), pkt.dhcp_header->op);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("硬件类型：%d"), pkt.dhcp_header->hw_type);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("硬件地址长度：%d"), pkt.dhcp_header->hw_len);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("跳数：%d"), pkt.dhcp_header->hops);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("事务ID：0x%08lX"), ntohl(pkt.dhcp_header->xid));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("客户启动时间：%hu"), ntohs(pkt.dhcp_header->secs));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format(_T("标志：0x%04hX"), ntohs(pkt.dhcp_header->flags));
	switch (ntohs(pkt.dhcp_header->flags) >> 15)
	{
	case DHCP_FLAGS_BROADCAST: strText += "（广播）"; break;
	case DHCP_FLAGS_UNICAST: strText += "（单播）"; break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = _T("客户机IP地址：") + IPAddr2CString(pkt.dhcp_header->client_ipaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = _T("你的（客户）IP地址：") + IPAddr2CString(pkt.dhcp_header->you_ipaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = _T("服务器IP地址：") + IPAddr2CString(pkt.dhcp_header->server_ipaddr);;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = _T("网关IP地址：") + IPAddr2CString(pkt.dhcp_header->gate_ipaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	/*  解析dhcp首部剩余部分 */
	CString strChaddr;
	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format(_T("%02X"), pkt.dhcp_header->client_addr[i]);
		strChaddr += strTmp + _T("-");
	}
	strChaddr.Delete(strChaddr.GetLength() - 1, 1);

	strText = _T("客户机MAC地址：") + strChaddr;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "服务器主机名：";
	strTmp.Format(_T("%s"), pkt.dhcp_header->server_name);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "引导文件名：";
	strTmp.Format(_T("%s"), pkt.dhcp_header->file);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	// 跳过引导文件名
	u_char* p = (u_char*)pkt.dhcp_header->file + 128;

	if (ntohl(*(u_long*)p) == 0x63825363)
	{
		strText = "Magic cookie: DHCP";
		m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);
	}

	// 跳过magic cookie
	p += 4;

	while (*p != 0xFF)
	{
		switch (*p)
		{
		case DHCP_OPTIONS_DHCP_MESSAGE_TYPE:
		{
			strText = "选项：（53）DHCP报文类型";
			switch (*(p + 2))
			{
			case 1: strText += "（Discover）"; break;
			case 2: strText += "（Offer）"; break;
			case 3: strText += "（Request）"; break;
			case 4: strText += "（Decline）"; break;
			case 5: strText += "（ACK）"; break;
			case 6: strText += "（NAK）"; break;
			case 7: strText += "（Release）"; break;
			case 8: strText += "（Inform）"; break;
			}
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format(_T("长度：%d"), *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText.Format(_T("DHCP：%d"), *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			++p;
		}
		break;

		case DHCP_OPTIONS_REQUESTED_IP_ADDRESS:
		{
			strText = "选项：（50）请求IP地址";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format(_T("长度：%d"), *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* addr = (IP_Address*)(++p);
			strText = _T("地址：") + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_IP_ADDRESS_LEASE_TIME:
		{
			strText = "选项：（51）IP地址租约时间";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format(_T("长度：%d"), *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			u_int time = *(++p);
			strText.Format(_T("租约时间：%u"), time);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_CLIENT_IDENTIFIER:
		{
			strText = "选项：（61）客户机标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText = "硬件类型：";
			if (*(++p) == 0x01)
			{
				strText += "以太网（0x01）";
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				MAC_Address* addr = (MAC_Address*)(++p);
				strText = _T("客户机标识：") + MACAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				p += 6;
			}
			else
			{
				strText.Format(_T("%d"), *p);
				strText += strTmp;
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				p += len;
			}
		}
		break;

		case DHCP_OPTIONS_VENDOR_CLASS_IDENTIFIER:
		{
			strText = "选项：（60）供应商类标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "供应商类标识：";
			for (; count < len; count++)
			{
				strTmp.Format(_T("%c"), *(++p));
				strText += strTmp;
			}
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_SERVER_IDENTIFIER:
		{
			strText = "选项：（54）服务器标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* addr = (IP_Address*)(++p);
			strText = _T("服务器标识：") + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_SUBNET_MASK:
		{


			strText = "选项：（1）子网掩码";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* submask = (IP_Address*)(++p);
			strText = _T("子网掩码：") + IPAddr2CString(*submask);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_ROUTER_OPTION:
		{


			strText = "选项：（3）路由器";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			while (count < len)
			{
				IP_Address* addr = (IP_Address*)(++p);
				strText = _T("路由器：") + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_DOMAIN_NAME_SERVER_OPTION:
		{
			strText = "选项：（6）DNS服务器";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			++p;
			while (count < len)
			{
				IP_Address* addr = (IP_Address*)(p);
				strText = _T("DNS服务器：") + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;


		case DHCP_OPTIONS_HOST_NAME_OPTION:
		{
			strText = "选项：（12）主机名";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "主机名：";

			for (; count < len; count++)
			{
				strTmp.Format(_T("%c"), *(++p));
				strText += strTmp;
			}
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_PAD_OPTION:
			++p;
			break;

		default:
		{
			strText.Format(_T("选项：（%d）"), *p);
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(_T("长度：%d"), len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向选项内容
			++p;

			// 跳过选项内容
			p += len;
		}
		break;
		}

	}
	strText = "选项：（255）结束";
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	return 0;
}

int CwinSnifferDlg::printHTTP2TreeCtrl(const packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.http_msg == NULL || parentNode == NULL)
	{
		return -1;
	}

	u_char* p = pkt.http_msg;
	int HTTPMsgLen = pkt.getL4PayloadLength();

	CString strText;
	if (ntohs(pkt.tcp_header->dst) == PORT_HTTP)
	{
		strText = "HTTP（请求）";
	}
	else if (ntohs(pkt.tcp_header->src) == PORT_HTTP)
	{
		strText = "HTTP（响应）";
	}
	HTREEITEM HTTPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	for (int count = 0; count < HTTPMsgLen; )
	{
		strText = "";
		while (*p != '\r')
		{
			strText += *p;
			++p;
			++count;
		}
		strText += "\\r\\n";
		m_treeCtrlPacketDetails.InsertItem(strText, HTTPNode, 0);

		p += 2;
		count += 2;
	}
	return 0;
}

/************************
* 控件触发事件
*************************/

void CwinSnifferDlg::onClickedList(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	int selectItemIndex = m_listCtrlPacketList.GetSelectionMark();
	CString strPktNum = m_listCtrlPacketList.GetItemText(selectItemIndex, 0);
	int pktNum = _ttoi(strPktNum);
	if (pktNum < 1 || pktNum > m_pool.getSize()) {
		return;
	}

	const packet& pkt = m_pool.get(pktNum);

	printTreeCtrlPacketDetails(pkt);
	printEditCtrlPacketBytes(pkt);
}

/***************
* 辅助函数
***************/

CString CwinSnifferDlg::MACAddr2CString(const MAC_Address& addr) {
	CString strAddr, strTmp;

	for (int i = 0; i < 6; i++) {
		strTmp.Format(_T("%02X"), addr.bytes[i]);
		strAddr += strTmp + _T("-");
	}
	strAddr.Delete(strAddr.GetLength() - 1);

	return strAddr;
}

CString CwinSnifferDlg::IPAddr2CString(const IP_Address& addr) {
	CString strAddr, strTmp;

	for (int i = 0; i < 4; i++) {
		strTmp.Format(_T("% d"), addr.bytes[i]);
		strAddr += strTmp + _T(".");
	}

	return strAddr;
}


void CwinSnifferDlg::OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) // 一个Item(一行)被绘画前
	{
		COLORREF itemColor;
		CString* pStrPktProtocol = (CString*)(pNMCD->nmcd.lItemlParam);	// 在printListCtrlPacketList(pkt)里将数据包的protocol字段传递过来

		///* 若该行被选中，则将其背景颜色调整为 */
		//if (pNMCD->nmcd.uItemState & CDIS_SELECTED)
		//{
		//	pNMCD->clrTextBk = RGB(0, 0, 0);
		//}
		if (!pStrPktProtocol->IsEmpty())
		{
			if (*pStrPktProtocol == "ARP")
			{
				itemColor = RGB(255, 182, 193);	// 红色
			}
			else if (*pStrPktProtocol == "ICMP")
			{
				itemColor = RGB(186, 85, 211);	// 紫色
			}
			else if (*pStrPktProtocol == "TCP")
			{
				itemColor = RGB(144, 238, 144);	// 绿色
			}
			else if (*pStrPktProtocol == "UDP")
			{
				itemColor = RGB(100, 149, 237);	// 蓝色

			}
			else if (*pStrPktProtocol == "DNS")
			{
				itemColor = RGB(135, 206, 250);	// 浅蓝色
			}
			else if (*pStrPktProtocol == "DHCP")
			{
				itemColor = RGB(189, 254, 76);	// 淡黄色
			}
			else if (*pStrPktProtocol == "HTTP")
			{
				itemColor = RGB(238, 232, 180);	// 黄色
			}
			else
			{
				itemColor = RGB(211, 211, 211);	// 灰色
			}
			pNMCD->clrTextBk = itemColor;
		}
		*pResult = CDRF_DODEFAULT;
	}
}
