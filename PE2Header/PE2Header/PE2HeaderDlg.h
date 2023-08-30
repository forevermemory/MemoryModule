
// PE2HeaderDlg.h: 头文件
//

#pragma once


// CPE2HeaderDlg 对话框
class CPE2HeaderDlg : public CDialogEx
{
// 构造
public:
	CPE2HeaderDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PE2HEADER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString m_Target_Header_Name;
	afx_msg void OnBnClickedButtonGenerate();
	afx_msg void OnClickedStaticSource();
	afx_msg void OnBnClickedButtonSourcePeFile();
	CString m_Source_Pe_File;
	afx_msg void OnBnClickedButtonTargetPath();
	CString m_Target_Path;
	afx_msg void OnBnClickedButtonOpenDirectory();
};
