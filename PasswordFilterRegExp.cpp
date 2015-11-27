#include "stdafx.h"
#include <atlbase.h>
#include <regex>
#include <atlconv.h>
#include <AtlBase.h>

#define MAX_REGEX_LENGTH 4096

using namespace std;

#define DEFAULT_REGEX L"^.{8,}$"

// Default DllMain implementation
BOOL APIENTRY DllMain(HANDLE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

// This function retrieves Regular Expression value
// from registry and updates passed by ref wregex object
void GetPasswordRegExFromRegistry(wregex& wrePassword)
{
	CRegKey rkRegEx;

	// Open registry key and check if we succeeded
	LONG res = rkRegEx.Open(HKEY_LOCAL_MACHINE,
		"Software\\KENSoft\\PasswordFilter",
		KEY_READ);

	if (ERROR_SUCCESS != res)
	{
		return;
	}
	
	ULONG ulSize = MAX_REGEX_LENGTH;
	char szRegEx[MAX_REGEX_LENGTH];

	// Query the RegEx value on open key
	// and check whether we succeeded
	res = rkRegEx.QueryStringValue("RegEx", LPTSTR(szRegEx), &ulSize);

	if ((ERROR_SUCCESS != res) ||
		(0 != szRegEx[ulSize - 1]))
	{
		return;
	}

	// Close registry key
	rkRegEx.Close();

	// Use the _bstr_t class for easier string handling
	_bstr_t bstrRegEx = szRegEx;

	// In case of empty RegEx string,
	// do not update wrePassword reference
	if (0 == bstrRegEx.length())
	{
		return;
	}

	wstring wstrRegEx;
	wstrRegEx = (wchar_t*)bstrRegEx;

	// Update wrePassword reference
	//with a new RegEx from Registry
	wrePassword = wstrRegEx;
	return;
}

/////////////////////////////////////////////
// Exported function
// -----------------
// Initialization of Password filter.
// This implementation just returns TRUE
// to let LSA know everything is fine
BOOLEAN __stdcall InitializeChangeNotify(void)
{
	return TRUE;
}

////////////////////////////////////////////
// Exported function
// -----------------
// This function is called by LSA when password
// was successfully changed.
//
// This implementation just returns 0 (Success)
NTSTATUS __stdcall PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword
	)
{
	return 0;
}

////////////////////////////////////////////
// Exported function
// -----------------
// This function actually validates
// a new password.
// LSA calls this function when a password is assign to a new user
// or password is changed on exisiting user.
// 
// This function return TRUE is password meets requirements
// that filter checks; FALSE is password does NOT meet these requirements
//
// In our implementation, specified Regular Expression must match new password
BOOLEAN __stdcall PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation
	)
{
	wchar_t* wszPassword = NULL;
	wstring wstrPassword;
	bool bMatch = FALSE;
	try
	{
		wszPassword = new wchar_t[Password->Length + 1];
		if (NULL == wszPassword)
		{
			throw E_OUTOFMEMORY;
		}
		wcsncpy_s(wszPassword, Password->Length, Password->Buffer, _TRUNCATE);
		
		wszPassword[Password->Length] = 0;

		wstrPassword = wszPassword;

		// Prepare iterator
		wstring::const_iterator start = wstrPassword.begin();
		wstring::const_iterator end = wstrPassword.end();

		match_results<wstring::const_iterator> what;

		// Validate password against regular expression

		wregex wrePassword(DEFAULT_REGEX);

		GetPasswordRegExFromRegistry(wrePassword);

		bMatch = regex_match(start, end, what, wrePassword);
		if (bMatch)
		{
		}
		
		{
		}
		throw S_OK;
	}
	catch (HRESULT)
	{
	}
	catch (...)
	{
	}
	// Erase all temporary password data
	// for security reasons
	wstrPassword.replace(0, wstrPassword.length(), wstrPassword.length(), (wchar_t)'?');
	wstrPassword.erase();
	if (NULL != wszPassword)
	{
		ZeroMemory(wszPassword, Password->Length);
		// Assure that there is no compiler optimizations and read random byte
		// from cleaned password string
		srand((unsigned int)time(NULL));
		wchar_t wch = wszPassword[rand() % Password->Length];
		delete[] wszPassword;
		wszPassword = NULL;
	}
	USES_CONVERSION;
	LPCSTR bwstrPassword = W2CT (wstrPassword.c_str());
	_bstr_t bwszPassword = wszPassword;
	OutputDebugString(bwstrPassword);
	OutputDebugString(bwszPassword);
	return bMatch;
}
