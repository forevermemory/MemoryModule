
// PE2HeaderDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "PE2Header.h"
#include "PE2HeaderDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define MAGIC 0x35



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


// CPE2HeaderDlg 对话框



CPE2HeaderDlg::CPE2HeaderDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PE2HEADER_DIALOG, pParent)
	, m_Target_Header_Name(_T(""))
	, m_Source_Pe_File(_T(""))
	, m_Target_Path(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPE2HeaderDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_TARGET_HEADER_NAME, m_Target_Header_Name);
	DDX_Text(pDX, ID_CHOOSE_SOURCE_FILE, m_Source_Pe_File);
	DDX_Text(pDX, IDC_EDIT_TARGET_PATH, m_Target_Path);
}

BEGIN_MESSAGE_MAP(CPE2HeaderDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_GENERATE, &CPE2HeaderDlg::OnBnClickedButtonGenerate)
	ON_BN_CLICKED(IDC_BUTTON_SOURCE_PE_FILE, &CPE2HeaderDlg::OnBnClickedButtonSourcePeFile)
	ON_BN_CLICKED(IDC_BUTTON_TARGET_PATH, &CPE2HeaderDlg::OnBnClickedButtonTargetPath)
	ON_BN_CLICKED(IDC_BUTTON_OPEN_DIRECTORY, &CPE2HeaderDlg::OnBnClickedButtonOpenDirectory)
END_MESSAGE_MAP()


// CPE2HeaderDlg 消息处理程序

BOOL CPE2HeaderDlg::OnInitDialog()
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
	m_Target_Header_Name = "pee.h";
	UpdateData(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPE2HeaderDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CPE2HeaderDlg::OnPaint()
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
HCURSOR CPE2HeaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}





void CPE2HeaderDlg::OnClickedStaticSource()
{
}


void CPE2HeaderDlg::OnBnClickedButtonSourcePeFile()
{


	
	CFileDialog dlg(TRUE);
	if (dlg.DoModal() == IDOK)
	{
		m_Source_Pe_File = dlg.GetPathName();
		int index = m_Source_Pe_File.ReverseFind('\\');

		//WCHAR buff[255] = { 0 };
		//wsprintf(buff, L"index:%d\n", index);
		//OutputDebugString(buff);

		m_Target_Path = m_Source_Pe_File.Left(index);
		UpdateData(FALSE);
	}

}


void CPE2HeaderDlg::OnBnClickedButtonTargetPath()
{
	BROWSEINFOW bi;
	memset(&bi, 0, sizeof(BROWSEINFOW));
	WCHAR spDisplayName[MAX_PATH] = { 0 };
	WCHAR pszPath[MAX_PATH] = { 0 };

	bi.hwndOwner = this->m_hWnd;
	bi.lpszTitle = L"请选择spyxx.exe所在目录";
	bi.pszDisplayName = spDisplayName;
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_BROWSEINCLUDEFILES | BIF_EDITBOX;

	ITEMIDLIST* idlist = SHBrowseForFolderW(&bi);
	SHGetPathFromIDListW(idlist, pszPath);
	
	m_Target_Path = pszPath;
	UpdateData(FALSE);
}



#pragma warning(disable:4996)
void CPE2HeaderDlg::OnBnClickedButtonGenerate()
{
	if (m_Source_Pe_File == L"")
	{
		MessageBoxA("please choose source file", "error", 0);
		return;
	}

	if (m_Target_Path == L"")
	{
		MessageBoxA("please choose source file", "error", 0);
		return;
	}

	// open source 
	CFile fp(m_Source_Pe_File, CFile::modeRead);
	
	// open target 
	CFile fpTarget(m_Target_Path + L"\\"+ m_Target_Header_Name, CFile::modeWrite | CFile::modeCreate);
	
	//char filebuff[1] = { 0 };
	char header[MAX_PATH] = {0};
	sprintf(header, "#pragma once\n\n#define FILEBUFF_LENGTH %lld\n\nchar FILEBUFF[FILEBUFF_LENGTH] = {", fp.GetLength());
	fpTarget.Write(header, strlen(header));

	PUCHAR buf =(PUCHAR) malloc(0x1000);
	memset(buf, 0, 0x1000);

	char tmp[MAX_PATH] = { 0 };

	int offset = 0;
	UINT readLen = fp.Read(buf, 0x1000);

	UCHAR value = 0;
	while (readLen > 0)
	{
		for (size_t i = 0; i < readLen; i++)
		{
			offset++;
			value = buf[i] ^ MAGIC;
			if (offset >= 16)
			{
				offset = 0;
				sprintf(tmp, "0x%02x, \n\t", value);
			}
			else
			{
				sprintf(tmp, "0x%02x,", value);
			}
			fpTarget.Write(tmp, strlen(tmp));
		}
		readLen = fp.Read(buf, 0x1000);
	}

	memset(header, 0, MAX_PATH);
	sprintf(header, "\n};");
	fpTarget.Write(header, strlen(header));

	fp.Close();
	fpTarget.Close();
	free(buf);

	// give tip
	CString title;
	GetWindowTextA(title);
	title += "-generate success!";
	SetWindowTextA(title);
}

void CPE2HeaderDlg::OnBnClickedButtonOpenDirectory()
{
	if (m_Target_Path == L"")
	{
		MessageBoxA("please choose source file", "error", 0);
		return;
	}

	ShellExecuteA(NULL, NULL, m_Target_Path, // param three: the target path you will open
		NULL, NULL, SW_SHOW);
}
