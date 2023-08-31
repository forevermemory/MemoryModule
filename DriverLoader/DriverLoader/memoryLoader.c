#include "memoryLoader.h"


#include <ntimage.h>

typedef UINT16 WORD;

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

		imagesBuff = ExAllocatePool(NonPagedPool, sizeOfImage);
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

		imagesBuff = ExAllocatePool(NonPagedPool, sizeOfImage);
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
				DbgPrint("sysLoader:reloc, block[i].Offset:%llx, realAddress: %p\n", block[i].Offset+ pBase->VirtualAddress, Delta);
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


// Driver Mode 
static ULONG_PTR FindModuleBaseByModuleName(char* moduleName)
{

	ULONG_PTR hModule = 0;

	NTSTATUS status;
	ULONG realLen = 0;
	PVOID buffer = NULL;

	RTL_PROCESS_MODULES moduleInfo = { 0 };
	status = ZwQuerySystemInformation(SystemModuleInformation, &moduleInfo,
		sizeof(RTL_PROCESS_MODULES),&realLen);
	DbgPrint("sysLoader: status:%X , realLen:%d\n", status, realLen);

	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		DbgPrint("sysLoader: buffsize is not enough, requery\n");

		buffer = ExAllocatePool(PagedPool, realLen);
		status = ZwQuerySystemInformation(SystemModuleInformation, buffer,
			realLen,&realLen);

		PUCHAR kernelModuleName = ExAllocatePool(PagedPool, strlen(moduleName) + 1);
		memset(kernelModuleName, 0, strlen(moduleName) + 1);
		memcpy(kernelModuleName, moduleName, strlen(moduleName));
		PUCHAR kernelModuleName2 = _strupr(kernelModuleName);


		PRTL_PROCESS_MODULES pInfo = (PRTL_PROCESS_MODULES)buffer;
		for (size_t i = 0; i < pInfo->NumberOfModules; i++)
		{
			hModule = pInfo->Modules[i].ImageBase;

			PUCHAR pathName = _strupr(pInfo->Modules[i].FullPathName);

			DbgPrint("sysLoader: in:%s,,,moduleName:%s \n", kernelModuleName2, pathName);
			// compare FullPathName and moduleName
			if (strstr(pathName, kernelModuleName2))
			{
				break;
			}
		}

		ExFreePool(kernelModuleName);
	}

	if (buffer)
	{
		ExFreePool(buffer);
	}
	
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
		ULONG_PTR hModule = FindModuleBaseByModuleName(pname);
		if (!hModule)
		{
			DbgPrint("sysLoader: Module base address not found:%s,call LoadLibrary,hModule:%p\n", pname, hModule);
			return FALSE;
		}

		// Machine
		switch (pNt->FileHeader.Machine)
		{
		case IMAGE_FILE_MACHINE_I386:  // x86
			originalFirstThunk32 = (PIMAGE_THUNK_DATA32)(imageBuff + pImport->OriginalFirstThunk);
			firstThunk32 = (PIMAGE_THUNK_DATA32)(imageBuff + pImport->FirstThunk);
			while (originalFirstThunk32->u1.Function)
			{
				// Importing by sequence number does not exist in the kernel
				if (originalFirstThunk32->u1.Ordinal & 0x80000000)
				{
					
				}
				else
				{
					// 0 - Import by Name
					PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG32)
						imageBuff + originalFirstThunk32->u1.AddressOfData);
					ULONG_PTR funcAddr = (ULONG_PTR)RtlFindExportedRoutineByName(hModule, pFuncName->Name);
					if (funcAddr)
					{
						firstThunk32->u1.Function = funcAddr;
					}
					DbgPrint("sysLoader: Import by Name:%s,  addr:%p,  %s  \n", pname, funcAddr, pFuncName->Name);

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
				// Importing by sequence number does not exist in the kernel
				if (originalFirstThunk64->u1.Ordinal & 0x8000000000000000)
				{
					
				}
				else
				{
					// 0 - Import by Name
					PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)
						imageBuff + originalFirstThunk64->u1.AddressOfData);
					ULONG_PTR funcAddr = (ULONG_PTR)RtlFindExportedRoutineByName(hModule, pFuncName->Name);
					if (funcAddr)
					{
						firstThunk64->u1.Function = funcAddr;
					}
					DbgPrint("sysLoader: Import by Name:%s,  addr:%p,  %s \n", pname, funcAddr, pFuncName->Name);
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




ULONG_PTR GetAddressOfEntryPoint(PUCHAR imageBuff)
{
	ULONG_PTR oep = 0;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	// AddressOfEntryPoint: The offset is the same in 32 and 64 bits
	oep = pNt->OptionalHeader.AddressOfEntryPoint;
	return oep;
}


BOOLEAN RepairCookie(UINT_PTR oepAddr)
{
	//kd > uf FFFF8504E75F5000
	//ffff8504`e75f5000 48895c2408      mov     qword ptr[rsp + 8], rbx
	//ffff8504`e75f5005 57              push    rdi
	//ffff8504`e75f5006 4883ec20        sub     rsp, 20h
	//ffff8504`e75f500a 488bda          mov     rbx, rdx
	//ffff8504`e75f500d 488bf9          mov     rdi, rcx
	//ffff8504`e75f5010 e817000000      call    ffff8504`e75f502c   // nop
	//ffff8504`e75f5015 488bd3          mov     rdx, rbx
	//ffff8504`e75f5018 488bcf          mov     rcx, rdi
	//ffff8504`e75f501b e8e0bfffff      call    ffff8504`e75f1000

	char code[17] = {0x48 ,0x89 ,0x5c ,0x24 ,0x08 ,0x57 ,0x48 ,0x83 ,0xec ,0x20 ,0x48 ,0x8b ,0xda ,0x48 ,0x8b ,0xf9 ,0xe8 };

	PUCHAR buffer = (PUCHAR)(PUINT_PTR)oepAddr;
	//DbgBreakPoint();

	if (memcmp(code, buffer, 17) == 0)
	{
		DbgPrint("sysLoader: replace __security_init_cookie addr:[%p]\n", (ULONG_PTR)(buffer + 17));

		*(PUCHAR)((ULONG_PTR)buffer + 16) = 0x90;
		*(PUCHAR)((ULONG_PTR)buffer + 17) = 0x90;
		*(PUCHAR)((ULONG_PTR)buffer + 18) = 0x90;
		*(PUCHAR)((ULONG_PTR)buffer + 19) = 0x90;
		*(PUCHAR)((ULONG_PTR)buffer + 20) = 0x90;
	}

	return TRUE;
}

BOOLEAN RepairCookie2(PUCHAR imageBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuff + pDos->e_lfanew);

	PIMAGE_NT_HEADERS32 pNt32 = NULL;
	PIMAGE_NT_HEADERS64 pNt64 = NULL;

	PIMAGE_LOAD_CONFIG_DIRECTORY32 config32;
	PIMAGE_LOAD_CONFIG_DIRECTORY64 config64;

	// Load Configuration Directory   IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  10
	PIMAGE_DATA_DIRECTORY directory = NULL;

	// Machine
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386: // x86
		pNt32 = (PIMAGE_NT_HEADERS32)(imageBuff + pDos->e_lfanew);
		directory = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

		config32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(directory->VirtualAddress + imageBuff);
		*(PULONG32)(config32->SecurityCookie) = 1;
		break;
	case IMAGE_FILE_MACHINE_IA64:
		break;
	case IMAGE_FILE_MACHINE_AMD64: // x64
		pNt64 = (PIMAGE_NT_HEADERS64)(imageBuff + pDos->e_lfanew);
		directory = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

		config64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(directory->VirtualAddress + imageBuff);
		*(PULONG64)(config64->SecurityCookie) = 1;
		break;
	default:
		break;
	}

	


	return TRUE;
}

VOID LoadDriver(ULONG_PTR rawBuff)
{
	// Stretch PE structure
	PUCHAR imageBase = FileToImage(rawBuff);
	DbgPrint("sysLoader:imageBase:[%p]\n", imageBase);

	// Repair relocation
	RepairRelocation(imageBase);

	// Repair IAT
	RepairIAT(imageBase);

	// get OEP
	typedef NTSTATUS(*pDriverEntry)(IN PDRIVER_OBJECT, IN PUNICODE_STRING);
	ULONG_PTR oep = GetAddressOfEntryPoint(imageBase);
	pDriverEntry f_DriverEntry = (pDriverEntry)(imageBase + oep);
	DbgPrint("sysLoader:pDriverEntry:[%p]\n", f_DriverEntry);

	// Repair Cookie
	// RepairCookie(f_DriverEntry);
	RepairCookie2(imageBase);

	// call entryPoint
	NTSTATUS ret = f_DriverEntry(NULL, NULL);
	DbgPrint("sysLoader:pDriverEntry exec success:[%d]\n", ret);
}