// WinIoInstall.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include "winio_nt.h"

using namespace std;

HANDLE hDriver = INVALID_HANDLE_VALUE;
bool IsWinIoInitialized = false;
wchar_t szWinIoDriverPath[32768] = { 0 };
bool g_Is64BitOS;


typedef UINT(WINAPI* GETSYSTEMWOW64DIRECTORY)(LPTSTR, UINT);

bool _stdcall InstallWinIoDriver(PWSTR pszWinIoDriverPath, bool IsDemandLoaded);
bool _stdcall RemoveWinIoDriver();
bool _stdcall StartWinIoDriver();
bool _stdcall StopWinIoDriver();
bool Is64BitOS();
bool GetDriverPath();
bool __stdcall InitializeWinIo(wchar_t *path = NULL);
void __stdcall ShutdownWinIo();
bool GetPrivilege();
BOOL IsRunAsAdmin();


int _tmain(int argc, _TCHAR* argv[])
{
	if (!IsRunAsAdmin())
	{
		GetPrivilege();
		exit(0);
	}

	bool is64BitOs = Is64BitOS();
	if (is64BitOs)
	{
		cout << "Current System Is 64Bit " << endl;
	}
	else
	{
		cout << "Current System Is 32Bit " << endl;
	}
	GetDriverPath();
	wcout << L"WinIo Driver Path Is \"" << szWinIoDriverPath << "\" Please Make Sure Exist" << endl;
	system("pause");
	bool initialed = InitializeWinIo(NULL);
	if (initialed)
	{
		cout << "WinIo Driver Install Success! ^_^ " << endl;
	}
	else
	{
		cout << "WinIo Driver Install Fail! |-_-| " << endl;
	}
	system("pause");
	exit(0);
}

BOOL IsRunAsAdmin()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}

bool GetPrivilege()
{
	CreateEvent(NULL, FALSE, FALSE, L"{29544E05-024F-4BC1-A272-452DBC8E17A4}");
	if (ERROR_SUCCESS != GetLastError())
	{
		return false;
	}
	else
	{
		TCHAR strPath[MAX_PATH] = L"winio.exe";
		HMODULE hModule = NULL;
		GetModuleFileName(hModule, strPath, MAX_PATH);

		SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
		sei.lpVerb = TEXT("runas");
		sei.lpFile = strPath;
		sei.nShow = SW_SHOWNORMAL;
		if (!ShellExecuteEx(&sei))
		{
			DWORD dwStatus = GetLastError();
			if (dwStatus == ERROR_CANCELLED)
			{
				return false;
			}
			else if (dwStatus == ERROR_FILE_NOT_FOUND)
			{
				return false;
			}
		}
	}
	return true;
}

bool Is64BitOS()
{
	GETSYSTEMWOW64DIRECTORY getSystemWow64Directory;
	HMODULE hKernel32;
	TCHAR Wow64Directory[32767];

	hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
	if (hKernel32 == NULL)
	{
		return false;
	}

	getSystemWow64Directory = (GETSYSTEMWOW64DIRECTORY)GetProcAddress(hKernel32, "GetSystemWow64DirectoryW");

	if (getSystemWow64Directory == NULL)
	{
		return false;
	}

	if ((getSystemWow64Directory(Wow64Directory, _countof(Wow64Directory)) == 0) &&
		(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)) {
		return false;
	}
	return true;
}

bool GetDriverPath()
{
	PWSTR pszSlash;

	if (!GetModuleFileName(GetModuleHandle(NULL), szWinIoDriverPath, sizeof(szWinIoDriverPath)))
	{
		return false;
	}

	pszSlash = wcsrchr(szWinIoDriverPath, '\\');

	if (pszSlash)
		pszSlash[1] = 0;
	else
		return false;

	if (Is64BitOS())
		wcscat(szWinIoDriverPath, L"winio64.sys");
	else
		wcscat(szWinIoDriverPath, L"winio32.sys");

	return true;
}

bool __stdcall InitializeWinIo(wchar_t* path)
{
	bool bResult;
	DWORD dwBytesReturned;

	g_Is64BitOS = Is64BitOS();

	hDriver = CreateFile(L"\\\\.\\WINIO",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	// If the driver is not running, install it
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		// if path is null, search the driver in the current path
		if (path == NULL)
		{
			GetDriverPath();
		}
		else
		{
			wcscpy(szWinIoDriverPath, path);
		}

		bResult = InstallWinIoDriver(szWinIoDriverPath, true);

		if (!bResult)
		{
			return false;
		}

		bResult = StartWinIoDriver();

		if (!bResult)
		{
			return false;
		}


		hDriver = CreateFile(L"\\\\.\\WINIO",
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hDriver == INVALID_HANDLE_VALUE)
		{
			return false;
		}

	}

	// Enable I/O port access for this process if running on a 32 bit OS

	if (!g_Is64BitOS)
	{
		if (!DeviceIoControl(hDriver, IOCTL_WINIO_ENABLEDIRECTIO, NULL,
			0, NULL, 0, &dwBytesReturned, NULL))
		{
			return false;
		}
	}

	IsWinIoInitialized = true;

	return true;
}

void _stdcall ShutdownWinIo()
{
	DWORD dwBytesReturned;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		// Disable I/O port access if running on a 32 bit OS

		if (!g_Is64BitOS)
		{
			DeviceIoControl(hDriver, IOCTL_WINIO_DISABLEDIRECTIO, NULL,
				0, NULL, 0, &dwBytesReturned, NULL);
		}

		CloseHandle(hDriver);

	}

	RemoveWinIoDriver();

	IsWinIoInitialized = false;
}

bool _stdcall InstallWinIoDriver(PWSTR pszWinIoDriverPath, bool IsDemandLoaded)
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;

	// Remove any previous instance of the driver

	RemoveWinIoDriver();

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager)
	{
		// Install the driver

		hService = CreateService(hSCManager,
			L"WINIO",
			L"WINIO",
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			(IsDemandLoaded == true) ? SERVICE_DEMAND_START : SERVICE_SYSTEM_START,
			SERVICE_ERROR_NORMAL,
			pszWinIoDriverPath,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);

		CloseServiceHandle(hSCManager);

		if (hService == NULL)
			return false;
	}
	else
		return false;

	CloseServiceHandle(hService);

	return true;
}

bool _stdcall RemoveWinIoDriver()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	LPQUERY_SERVICE_CONFIG pServiceConfig;
	DWORD dwBytesNeeded;
	DWORD cbBufSize;
	bool bResult;

	StopWinIoDriver();

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hSCManager)
	{
		return false;
	}

	hService = OpenService(hSCManager, L"WINIO", SERVICE_ALL_ACCESS);
	CloseServiceHandle(hSCManager);

	if (!hService)
	{
		return false;
	}

	bResult = QueryServiceConfig(hService, NULL, 0, &dwBytesNeeded);

	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		cbBufSize = dwBytesNeeded;
		pServiceConfig = (LPQUERY_SERVICE_CONFIG)malloc(cbBufSize);
		bResult = QueryServiceConfig(hService, pServiceConfig, cbBufSize, &dwBytesNeeded);

		if (!bResult)
		{
			free(pServiceConfig);
			CloseServiceHandle(hService);
			return bResult;
		}

		// If service is set to load automatically, don't delete it!
		if (pServiceConfig->dwStartType == SERVICE_DEMAND_START)
		{
			bResult = DeleteService(hService);
		}
	}

	CloseServiceHandle(hService);

	return bResult;
}

bool _stdcall StartWinIoDriver()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	bool bResult;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager)
	{
		hService = OpenService(hSCManager, L"WINIO", SERVICE_ALL_ACCESS);

		CloseServiceHandle(hSCManager);

		if (hService)
		{
			bResult = StartService(hService, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;

			CloseServiceHandle(hService);
		}
		else
			return false;
	}
	else
		return false;

	return bResult;
}


bool _stdcall StopWinIoDriver()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ServiceStatus;
	bool bResult;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager)
	{
		hService = OpenService(hSCManager, L"WINIO", SERVICE_ALL_ACCESS);

		CloseServiceHandle(hSCManager);

		if (hService)
		{
			bResult = ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);

			CloseServiceHandle(hService);
		}
		else
			return false;
	}
	else
		return false;

	return bResult;
}