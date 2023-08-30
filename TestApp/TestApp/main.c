#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
#include "pee.h"
#else
#include "pee_x86.h"
#endif

#include "memoryLoader.h"

#define MAGIC  0x35 

int main()
{
	// decode 
	for (size_t i = 0; i < sizeof(FILEBUFF); i++)
	{
		FILEBUFF[i] ^= MAGIC;
	}

	// Stretch PE structure
	PUCHAR filebuff =  FileToImage(FILEBUFF);

	// Repair relocation
	RepairRelocation(filebuff);

	// Repair IAT
	RepairIAT(filebuff);

	// Execute TLS
	// ExecuteTLS(filebuff);

	// get OEP
	ULONG_PTR oep = GetAddressOfEntryPoint(filebuff);

	// function prototype
	//BOOL APIENTRY DllMain(HMODULE hModule,
	//	DWORD  ul_reason_for_call,
	//	LPVOID lpReserved
	//)
	typedef BOOL(WINAPI* p_DllEntryPoint)(IN HMODULE, IN DWORD, IN LPVOID);
	p_DllEntryPoint f_DllMain = (p_DllEntryPoint)(filebuff + oep);
	printf("DllEntryPoint addr:%p \n", f_DllMain);

	// call entryPoint
	BOOLEAN ret = f_DllMain((HMODULE)-1, DLL_PROCESS_ATTACH, NULL); 

	// Memory cannot be released, otherwise the code block will also be released
	// VirtualFree(filebuff, sizeOfImage, MEM_DECOMMIT);

	printf("DLLEntry return:%d \n", ret);
	getchar();
	getchar();
	return 0;
}