#include "memoryLoader.h"

#pragma warning(disable:4996)

#include <stdio.h>

#include <tlhelp32.h>

// Stretch PE structure
PUCHAR FileToImage(char* filebuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)filebuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(filebuff + pDos->e_lfanew);

	// Number of sections
	WORD numberOfSections = pNt->FileHeader.NumberOfSections;

	PIMAGE_NT_HEADERS32 pNt32 = NULL;
	PIMAGE_NT_HEADERS64 pNt64 = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL; // section header

	PUCHAR imagesBuff = NULL;
	ULONG_PTR sizeOfImage = 0;

	// Machine
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386: // x86
		pNt32 = (PIMAGE_NT_HEADERS32)(filebuff + pDos->e_lfanew);
		sizeOfImage = pNt32->OptionalHeader.SizeOfImage;

		// PS:use malloc, The requested memory does not have execution permission
		// imagesBuff = (PUCHAR)malloc(sizeOfImage);
		imagesBuff = (PUCHAR)VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memset(imagesBuff, 0, sizeOfImage);

		// Copy PE header
		memcpy(imagesBuff, filebuff, pNt32->OptionalHeader.SizeOfHeaders);

		// Get the first section
		pSection = IMAGE_FIRST_SECTION(pNt32);
		break;
	case IMAGE_FILE_MACHINE_IA64:
		break;
	case IMAGE_FILE_MACHINE_AMD64: // x64
		pNt64 = (PIMAGE_NT_HEADERS64)(filebuff + pDos->e_lfanew);
		sizeOfImage = pNt64->OptionalHeader.SizeOfImage;
		// PS:use malloc, The requested memory does not have execution permission
		// imagesBuff = (PUCHAR)malloc(sizeOfImage); 

		imagesBuff = (PUCHAR)VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memset(imagesBuff, 0, sizeOfImage);

		// Copy PE header
		memcpy(imagesBuff, filebuff, pNt64->OptionalHeader.SizeOfHeaders);

		// Get the first section
		pSection = IMAGE_FIRST_SECTION(pNt64);
		break;
	default:
		break;
	}

	// stretching section
	for (size_t i = 0; i < numberOfSections; i++)
	{
		memcpy(imagesBuff + pSection->VirtualAddress, filebuff + pSection->PointerToRawData, pSection->SizeOfRawData);
		pSection++;
	}

	return imagesBuff;
}

//  Repair relocation
BOOLEAN RepairRelocation(PUCHAR imageBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	PIMAGE_NT_HEADERS32 pNt32 = NULL;
	PIMAGE_NT_HEADERS64 pNt64 = NULL;

	// relocation table
	PIMAGE_DATA_DIRECTORY iRelocation = NULL;

	// Machine
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386: // x86
		pNt32 = (PIMAGE_NT_HEADERS32)(imageBuff + pDos->e_lfanew);
		iRelocation = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		;
		break;
	case IMAGE_FILE_MACHINE_IA64:
		break;
	case IMAGE_FILE_MACHINE_AMD64: // x64
		pNt64 = (PIMAGE_NT_HEADERS64)(imageBuff + pDos->e_lfanew);
		iRelocation = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		break;
	default:
		break;
	}

	// PIMAGE_BASE_RELOCATION 
	PIMAGE_BASE_RELOCATION pBase = (PIMAGE_BASE_RELOCATION)(imageBuff + iRelocation->VirtualAddress);

	while (pBase->SizeOfBlock)
	{
		// Skip the first 8 bytes,followed by each block
		// Every two bytes are RVAs of related global variables
		PIMAGE_RELOC_BLOCK block = (PIMAGE_RELOC_BLOCK)((ULONG_PTR)pBase + sizeof(IMAGE_BASE_RELOCATION));

		// get the block number of relocation
		ULONG32 numberOfRelocation = (pBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		// Traverse a block
		for (size_t i = 0; i < numberOfRelocation; i++)
		{
			if (block[i].Type == IMAGE_REL_BASED_DIR64) // 1010 x64
			{
				PULONG_PTR Address = (PULONG_PTR)((ULONG_PTR)imageBuff + pBase->VirtualAddress + block[i].Offset);
				ULONG_PTR Delta = *Address - pNt64->OptionalHeader.ImageBase + (ULONG_PTR)imageBuff;
				// Replace
				*Address = Delta;
			}
			else if (block[i].Type == IMAGE_REL_BASED_HIGHLOW) // 0011 x32
			{
				PULONG_PTR Address = (PULONG_PTR)((ULONG_PTR)imageBuff + pBase->VirtualAddress + block[i].Offset);
				ULONG_PTR Delta = *Address - pNt32->OptionalHeader.ImageBase + (ULONG_PTR)imageBuff;
				// Replace
				*Address = Delta;
			}
		}

		// Always offset backwards until the last structure is all 0
		pBase = (PIMAGE_BASE_RELOCATION)((PULONG_PTR)pBase + pBase->SizeOfBlock);
	}

	return TRUE;

}




static HMODULE FindModuleBaseByModuleName(char* moduleName)
{
	// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

	HMODULE hModule = 0;

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot (of modules)\n");
		return 0;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return 0;
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		printf("moduleBase:%p, name:%s\n", me32.hModule, me32.szModule); // C:\Windows\System32\KERNEL32.DLL
		if (strcmpi(me32.szModule, moduleName) == 0)
		{
			hModule = me32.hModule;
			break;
		}


	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return hModule;
}

// Repair IAT
BOOLEAN RepairIAT(PUCHAR imageBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	PIMAGE_NT_HEADERS32 pNt32 = NULL;
	PIMAGE_NT_HEADERS64 pNt64 = NULL;

	// Import Table   IMAGE_DIRECTORY_ENTRY_IMPORT  1
	PIMAGE_DATA_DIRECTORY directory = NULL;

	// Machine
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386: // x86
		pNt32 = (PIMAGE_NT_HEADERS32)(imageBuff + pDos->e_lfanew);
		directory = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		break;
	case IMAGE_FILE_MACHINE_IA64:
		break;
	case IMAGE_FILE_MACHINE_AMD64: // x64
		pNt64 = (PIMAGE_NT_HEADERS64)(imageBuff + pDos->e_lfanew);
		directory = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		break;
	default:
		break;
	}

	// Import Table
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuff + directory->VirtualAddress);

	PIMAGE_THUNK_DATA32 originalFirstThunk32 = NULL; 
	PIMAGE_THUNK_DATA64 originalFirstThunk64 = NULL; 

	PIMAGE_THUNK_DATA32 firstThunk32 = NULL; 
	PIMAGE_THUNK_DATA64 firstThunk64 = NULL; 

	while (pImport->Characteristics)
	{
		char* pname = (char*)(imageBuff + pImport->Name);

		// Query module base address based on module name,
		// If the module is not loaded by the current process, call LoadLibrary
		HMODULE hModule = FindModuleBaseByModuleName(pname);
		if (!hModule)
		{
			printf("Module base address not found:%s,call LoadLibrary,hModule:%p\n", pname, hModule);
			hModule = LoadLibraryA(pname);
		}

		// Machine
		switch (pNt->FileHeader.Machine)
		{
		case IMAGE_FILE_MACHINE_I386:  // x86
			originalFirstThunk32 = (PIMAGE_THUNK_DATA32)(imageBuff + pImport->OriginalFirstThunk);
			firstThunk32 = (PIMAGE_THUNK_DATA32)(imageBuff + pImport->FirstThunk);
			while (originalFirstThunk32->u1.Function)
			{
				//if(IMAGE_SNAP_BY_ORDINAL64(originalFirstThunk64->u1.Ordinal))
				if (originalFirstThunk32->u1.Ordinal & 0x80000000)
				{
					// The highest digit of 1 represents importing by sequence number, 
					// the remaining 31 digits are sequence numbers
					ULONG32 ordinal = originalFirstThunk32->u1.Ordinal & 0x7FFFFFFF;
					char tmpName[16] = { 0 };
					sprintf(tmpName, "%lld", ordinal);
					ULONG_PTR funcAddr = (ULONG_PTR)GetProcAddress(hModule, tmpName);
					if (funcAddr)
					{
						firstThunk32->u1.Function = funcAddr;
					}
					printf("\tImport by ordinal: %lld %llx\n", ordinal, funcAddr);
				}
				else
				{
					// 0 - Import by Name
					PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG32)
						imageBuff + originalFirstThunk32->u1.AddressOfData);
					ULONG_PTR funcAddr = (ULONG_PTR)GetProcAddress(hModule, pFuncName->Name);
					if (funcAddr)
					{
						firstThunk32->u1.Function = funcAddr;
					}
					printf("\tImport by Name:base:%s,  addr:%p,  %s  \n", pname, funcAddr, pFuncName->Name);

				}
				originalFirstThunk32++;
				firstThunk32++;
			}
			break;
		case IMAGE_FILE_MACHINE_IA64:
			break;
		case IMAGE_FILE_MACHINE_AMD64: // x64
			originalFirstThunk64 = (PIMAGE_THUNK_DATA64)(imageBuff + pImport->OriginalFirstThunk);
			firstThunk64 = (PIMAGE_THUNK_DATA64)(imageBuff + pImport->FirstThunk);

			while (originalFirstThunk64->u1.Function)
			{
				//if(IMAGE_SNAP_BY_ORDINAL64(originalFirstThunk64->u1.Ordinal))
				if (originalFirstThunk64->u1.Ordinal & 0x8000000000000000)
				{
					// The highest digit of 1 represents importing by sequence number, 
					// the remaining 31 digits are sequence numbers
					ULONG64 ordinal = originalFirstThunk64->u1.Ordinal & 0x7FFFFFFFFFFFFFFF;
					char tmpName[16] = { 0 };
					sprintf(tmpName, "%lld", ordinal);
					ULONG_PTR funcAddr = (ULONG_PTR)GetProcAddress(hModule, tmpName);
					if (funcAddr)
					{
						firstThunk64->u1.Function = funcAddr;
					}
					printf("\tImport by ordinal: %lld %llx\n", ordinal, funcAddr);
				}
				else
				{
					// 0 - Import by Name
					PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)
						imageBuff + originalFirstThunk64->u1.AddressOfData);
					ULONG_PTR funcAddr = (ULONG_PTR)GetProcAddress(hModule, pFuncName->Name);
					if (funcAddr)
					{
						firstThunk64->u1.Function = funcAddr;
					}
					printf("\tImport by Name:base:%s,  addr:%llx,  %s  \n", pname, funcAddr, pFuncName->Name);

				}
				originalFirstThunk64++;
				firstThunk64++;
			}
			break;
		default:
			break;
		}

		// Traverse Next Table
		pImport++;
	}

	return TRUE;
}


// Execute TLS
// still has bug
BOOLEAN ExecuteTLS(PUCHAR imageBuff)
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	PIMAGE_NT_HEADERS32 pNt32 = NULL;
	PIMAGE_NT_HEADERS64 pNt64 = NULL;

	// TLS±íµÄÄ¿Â¼
	PIMAGE_DATA_DIRECTORY directory = NULL;

	PIMAGE_TLS_DIRECTORY32 pTls32 = NULL;
	PIMAGE_TLS_DIRECTORY64 pTls64 = NULL;


	PIMAGE_TLS_CALLBACK* callback = NULL;
	// Machine
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386: // x86
		pNt32 = (PIMAGE_NT_HEADERS32)(imageBuff + pDos->e_lfanew);
		directory = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		pTls32 = (PIMAGE_TLS_DIRECTORY32)(imageBuff + directory->VirtualAddress);
		break;
	case IMAGE_FILE_MACHINE_IA64:
		break;
	case IMAGE_FILE_MACHINE_AMD64: // x64
		pNt64 = (PIMAGE_NT_HEADERS64)(imageBuff + pDos->e_lfanew);
		directory = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		pTls64 = (PIMAGE_TLS_DIRECTORY64)(imageBuff + directory->VirtualAddress);

		// Exec callback
		callback = (PIMAGE_TLS_CALLBACK*)(pTls64->AddressOfCallBacks);
		if (callback)
		{
			while (*callback) // callback 
			{
				printf("Exec TLS:%llx", *callback);
				(*callback)((LPVOID)imageBuff, DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}
		break;
	default:
		break;
	}

	return TRUE;
}


ULONG_PTR GetAddressOfEntryPoint(PUCHAR imageBuff)
{
	ULONG_PTR oep = 0;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	// AddressOfEntryPoint: The offset is the same in 32 and 64 bits
	oep = pNt->OptionalHeader.AddressOfEntryPoint;
	return oep;
}