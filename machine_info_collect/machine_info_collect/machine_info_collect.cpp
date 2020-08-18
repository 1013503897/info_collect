#include <stdio.h>
#include <Windows.h>
#include <TCHAR.h>
#include <wtsapi32.h>
#include <assert.h>
#include <lm.h>
#include <cstdlib>
#include <sstream>
#pragma comment(lib,"Wtsapi32.lib")
#pragma comment(lib,"Netapi32.lib")

void get_service_info() {
	SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scHandle == NULL) {
		printf("OpenSCManager fail(%ld)", GetLastError());
	}
	else {
		printf("OpenSCManager -> scHandle=%p\n", scHandle);
		SC_ENUM_TYPE infoLevel = SC_ENUM_PROCESS_INFO;
		DWORD dwServiceType = SERVICE_WIN32;
		DWORD dwServiceState = SERVICE_STATE_ALL;
		LPBYTE lpServices = NULL;
		DWORD cbBufSize = 0;
		DWORD pcbBytesNeeded;
		DWORD servicesReturned;
		LPDWORD lpResumeHandle = NULL;
		LPCWSTR pszGroupName = NULL;
		BOOL ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
		printf("EnumServicesStatusEx scHandle=%p -> ret=%d, pcbBytesNeeded=%ld, servicesReturned=%ld\n", scHandle, ret, pcbBytesNeeded, servicesReturned);

		cbBufSize = pcbBytesNeeded;
		lpServices = new BYTE[cbBufSize];
		if (NULL == lpServices)
		{
			printf("lpServices = new BYTE[%ld] -> fail(%ld)\n", cbBufSize, GetLastError());
		}
		else {
			ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
			printf("EnumServicesStatusEx scHandle=%p, cbBufSize=%ld -> ret=%d, pcbBytesNeeded=%ld, servicesReturned=%ld\n", scHandle, cbBufSize, ret, pcbBytesNeeded, servicesReturned);
			LPENUM_SERVICE_STATUS_PROCESS lpServiceStatusProcess = (LPENUM_SERVICE_STATUS_PROCESS)lpServices;
			for (DWORD i = 0; i < servicesReturned; i++) {
				_tprintf(_T("service.lpServiceName=%s, lpDisplayName=%s\n"), lpServiceStatusProcess[i].lpDisplayName, lpServiceStatusProcess[i].lpServiceName);
				printf("service.ServiceStatusProcess.dwServiceType=%ld, dwCurrentState=%ld, dwControlsAccepted=%ld, dwWin32ExitCode=%ld, dwServiceSpecificExitCode=%ld, dwCheckPoint=%ld, dwWaitHint=%ld, dwProcessId=%ld, dwServiceFlags=%ld\n",
					lpServiceStatusProcess[i].ServiceStatusProcess.dwServiceType,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwCurrentState,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwControlsAccepted,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwWin32ExitCode,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwServiceSpecificExitCode,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwCheckPoint,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwWaitHint,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId,
					lpServiceStatusProcess[i].ServiceStatusProcess.dwServiceFlags);
			}

			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}

}

void get_session_info() {
	PWTS_SESSION_INFO psi;
	DWORD dwCount;

	BOOL bRet = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &psi, &dwCount);

	/*typedef enum _WTS_CONNECTSTATE_CLASS {
		WTSActive,              // User logged on to WinStation
		WTSConnected,           // WinStation connected to client
		WTSConnectQuery,        // In the process of connecting to client
		WTSShadow,              // Shadowing another WinStation
		WTSDisconnected,        // WinStation logged on without client
		WTSIdle,                // Waiting for client to connect
		WTSListen,              // WinStation is listening for connection
		WTSReset,               // WinStation is being reset
		WTSDown,                // WinStation is down due to error
		WTSInit,                // WinStation in initialization
	} WTS_CONNECTSTATE_CLASS;*/
	if (!bRet)
		return;
	for (unsigned int i = 0; i < dwCount; i++)
	{
		printf("%s \t", psi[i].pWinStationName);
		printf("%d \t", psi[i].SessionId);
		printf("%d \n", psi[i].State);
	}
	WTSFreeMemory(psi);
}

void get_user_info() {

	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = -1;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR  pszServerName = NULL;

	// The server is not the default local computer.
	//
	//
	// Call the NetUserEnum function, specifying level 0;
	// enumerate global user account types only.
	//
	do // begin do
	{
		nStatus = NetUserEnum(pszServerName,
			dwLevel,
			FILTER_NORMAL_ACCOUNT, // global users
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);
		//
		// If the call succeeds,
		//
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				//
				// Loop through the entries.
				//
				for (i = 0; (i < dwEntriesRead); i++)
				{
					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
					{
						break;
					}
					//
					//  Print the name of the user account.
				   //
					printf("%s\r\n", pTmpBuf);
					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		//
		// Otherwise, print the system error.
		//
		else
		{
		}

		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	}

	while (nStatus == ERROR_MORE_DATA); // end do

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

}

void get_group_info() {
	NET_API_STATUS               nas;
	LPBYTE* buf = NULL;
	DWORD                        entread, totent, rhand;
	DWORD                        maxlen = 32;//0xffffffff;
	GROUP_USERS_INFO_0* usrs;
	unsigned int                 i;
	int                          cc = 0;
	WCHAR                        user[30];

	entread = totent = rhand = nas = 0;
	if ((buf = (LPBYTE*)malloc(29000)) == NULL)
		printf("malloc probs1");

	nas = NetUserGetGroups(NULL, L"Administrator", 0, buf, maxlen, &entread, &totent);

	if (nas != NERR_Success)
	{
		fprintf(stderr, "couldn't enum users, ");
	}

	cc = sizeof(GROUP_USERS_INFO_0) * entread;

	if ((usrs = (GROUP_USERS_INFO_0*)malloc(cc)) == NULL)
	{
		fprintf(stderr, "malloc probs2\n");
	}

	memcpy(usrs, *buf, cc);


	for (i = 0; i < entread; i++)
	{
		wcscpy(user, usrs[i].grui0_name);
		wprintf(L"%s\n", user);

	}
}

/*
int main()
{
	// get_service_info();
	// get_session_info();
	// get_user_info();
	//get_group_info();
	system("pause");
	return 0;
}*/

int execmd(const char* cmd, char* result) {
	char buffer[128];
	FILE* pipe = _popen(cmd, "r");
	if (!pipe)
		return 0;
	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe)) {
			strcat(result, buffer);
		}
	}
	_pclose(pipe);
	return 1;
}
/*
#include <windows.h>


#define PIPE_BUFFER_SIZE 1024

int _tmain(int argc, _TCHAR* argv[])
{
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	TCHAR m_szReadBuffer[PIPE_BUFFER_SIZE];
	TCHAR m_szWriteBuffer[PIPE_BUFFER_SIZE];
	char m_szPipeOut[PIPE_BUFFER_SIZE];

	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInfo;
	SECURITY_ATTRIBUTES saOutPipe;
	HANDLE m_hPipeRead;
	HANDLE m_hPipeWrite;
	ZeroMemory(m_szReadBuffer, sizeof(m_szReadBuffer));
	ZeroMemory(&saOutPipe, sizeof(saOutPipe));
	saOutPipe.nLength = sizeof(SECURITY_ATTRIBUTES);
	saOutPipe.lpSecurityDescriptor = NULL;
	saOutPipe.bInheritHandle = TRUE;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	if (!CreatePipe(&m_hPipeRead, &m_hPipeWrite, &saOutPipe, PIPE_BUFFER_SIZE))
	{
	}


	HANDLE h = CreateFile(_T("out.log"),
		FILE_APPEND_DATA,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		&sa,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	BOOL ret = FALSE;
	DWORD flags = CREATE_NO_WINDOW;
	DWORD dwReadLen = 0;
	DWORD dwStdLen = 0;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdError = m_hPipeRead;
	si.hStdOutput = m_hPipeWrite;
	si.wShowWindow = SW_HIDE;
	TCHAR cmd[] = TEXT("C:\\Windows\\System32\\qwinsta.exe");
	ret = CreateProcess(NULL, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);
	do
	{
		if (!CreateProcess(NULL, m_CommandParam.szCommand,
			NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL,
			&si, &m_processInfo))
		{
			break;
		}
		if (WAIT_TIMEOUT == WaitForSingleObject(m_processInfo.hProcess, INFINITE))
		{
			if (m_CommandParam.OnCmdEvent)
				m_CommandParam.OnCmdEvent(&m_CommandParam, CO_E_SERVER_START_TIMEOUT, "");
			break;
		}
		// 预览管道中数据的内容
		if (!PeekNamedPipe(m_hPipeRead, NULL, 0, NULL, &dwReadLen, NULL)
			|| dwReadLen <= 0)
		{
			break;
		}
		else
		{
			ZeroMemory(m_szPipeOut, sizeof(m_szPipeOut));
			// 读取管道中的数据
			if (ReadFile(m_hPipeRead, m_szPipeOut, dwReadLen, &dwStdLen, NULL))
			{
				if (m_CommandParam.OnCmdEvent)
					m_CommandParam.OnCmdEvent(&m_CommandParam, S_OK, m_szPipeOut);
				break;
			}
			else
			{
				break;
			}
		}
	} while (0);

	if (ret)
	{
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	return -1;
}
*/

void get_privilage_info() {
	HANDLE hToken = NULL;
	PTOKEN_PRIVILEGES pTp = NULL;
	DWORD dwNeededSize = 0, dwI = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return;
	}
	// 试探一下需要分配多少内存
	GetTokenInformation(hToken, TokenPrivileges, NULL, dwNeededSize, &dwNeededSize);
	// 分配所需内存大小
	pTp = (PTOKEN_PRIVILEGES)malloc(dwNeededSize);
	if (!GetTokenInformation(hToken, TokenPrivileges, pTp, dwNeededSize, &dwNeededSize))
	{
		free(pTp);
		return;
	}
	else
	{
		// 先计数权限
		for (DWORD i = 0; i < pTp->PrivilegeCount; i++)
		{
			if (pTp->Privileges[i].Attributes == SE_PRIVILEGE_ENABLED)
			{
				dwI++;
				break;
			}
		}

		// 枚举进程权限

		char* pJsonData = (char*)malloc(1024);
		strcpy(pJsonData, "[\r\n");
		for (DWORD i = 0; i < pTp->PrivilegeCount; i++)
		{
			char* pUidName = NULL;    // 存权限名的指针
			DWORD dwNameLen = 0;    // 权限名字长度

			strcat(pJsonData, "    {\r\n");
			strcat(pJsonData, "        \"Permission\":  \"");
			LookupPrivilegeName(NULL, &pTp->Privileges[i].Luid, NULL, &dwNameLen);
			pUidName = (char*)malloc(dwNameLen);
			LookupPrivilegeNameA(NULL, &pTp->Privileges[i].Luid, pUidName, &dwNameLen);
			strcat(pJsonData, pUidName);
			strcat(pJsonData, "\", \r\n        \"Flags\":  \"");
			if (!pTp->Privileges[i].Attributes)
				strcat(pJsonData, "SE_PRIVILEGE_DISABLED");
			else {
				if (pTp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
					strcat(pJsonData, "SE_PRIVILEGE_ENABLED ");
				if (pTp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
					strcat(pJsonData, "SE_PRIVILEGE_ENABLED_BY_DEFAULT ");
				if (pTp->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED)
					strcat(pJsonData, "SE_PRIVILEGE_REMOVED ");
				if (pTp->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
					strcat(pJsonData, "SE_PRIVILEGE_USED_FOR_ACCESS ");
			}
			strcat(pJsonData, "\"\r\n");
			if (i == pTp->PrivilegeCount - 1)
				strcat(pJsonData, "    }\r\n]");
			else
				strcat(pJsonData, "    },\r\n");
			free(pUidName);
		}
	}
	free(pTp);
	CloseHandle(hToken);
	return;
}


#include <iostream>
#include <string>
#include <Windows.h>

using namespace std;

char* GetCmdRet(const char* cmdLine)
{
	HANDLE hRead = NULL, hWrite = NULL;
	PROCESS_INFORMATION pInfo = { 0 };
	SECURITY_ATTRIBUTES se = { 0 };
	STARTUPINFOA sInfo = { 0 };
	char tmpCmd[10000] = { 0 }, * retStr = NULL;
	DWORD dwLen = 0;
	string ret;

	se.nLength = sizeof(se);
	se.lpSecurityDescriptor = NULL;
	se.bInheritHandle = TRUE;

	CreatePipe(&hRead, &hWrite, &se, 0);
	sInfo.cb = sizeof(sInfo);
	sInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	sInfo.wShowWindow = SW_HIDE;
	sInfo.hStdOutput = hWrite;
	sInfo.hStdError = hWrite;
	PVOID OldValue = NULL;
	Wow64DisableWow64FsRedirection(&OldValue);
	CreateProcessA(
		NULL,
		(char*)cmdLine,
		NULL,
		NULL,
		TRUE,
		NULL,
		NULL,
		NULL,
		&sInfo,
		&pInfo);
	CloseHandle(hWrite);

	while (dwLen != -1) {
		PeekNamedPipe(hRead, NULL, NULL, NULL, &dwLen, NULL);
		if (dwLen) {
			ZeroMemory(tmpCmd, MAX_PATH);
			ReadFile(hRead, tmpCmd, dwLen, &dwLen, NULL);
			ret += tmpCmd;
		}
		else {
			DWORD dwExit = 0;
			GetExitCodeProcess(pInfo.hProcess, &dwExit);
			if (dwExit != STILL_ACTIVE) {
				CloseHandle(hRead);
				break;
			}
		}
		Sleep(1);
	}
	retStr = (char*)malloc(sizeof(char) * ret.length() + 1);
	ZeroMemory(retStr, ret.length() + 1);
	lstrcpynA(retStr, ret.c_str(), ret.length() + 1);
	return retStr;
}

wchar_t* GBKToUTF16(char* str, int& BufferNeed)
{
	wchar_t* pwBuffer = nullptr;
	BufferNeed = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);

	do
	{
		if (BufferNeed == 0)
		{
			break;
		}

		BufferNeed += 1;
		pwBuffer = (wchar_t*)malloc(BufferNeed * sizeof(wchar_t));
		if (pwBuffer == nullptr)
		{
			break;
		}

		BufferNeed = MultiByteToWideChar(CP_ACP, 0, str, -1, pwBuffer, BufferNeed);
		if (BufferNeed == 0)
		{
			break;
		}

		pwBuffer[BufferNeed] = 0;
	} while (false);
	return pwBuffer;
}


int main(void) {
	get_privilage_info();
	//get_session_info();
	//cout<<GetCmdRet("powershell Get-NetIPConfiguration|select @{Expression={$_.IPv4Address.IPAddress}}, InterfaceAlias, InterfaceDescription|ConvertTo-Json");
	system("pause");
	return 0;
}

