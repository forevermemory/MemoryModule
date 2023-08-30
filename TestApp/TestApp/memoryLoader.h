#pragma once

// win32 mode
#include <Windows.h>


typedef struct _IMAGE_RELOC_BLOCK
{
	UINT16 Offset : 12;  // Low 12 bit
	UINT16 Type : 4;    // High 4 bit
}IMAGE_RELOC_BLOCK, * PIMAGE_RELOC_BLOCK;

// Stretch PE structure
PUCHAR FileToImage(char* filebuff);

//  Repair relocation
BOOLEAN RepairRelocation(PUCHAR imageBuff);

// Repair IAT
BOOLEAN RepairIAT(PUCHAR imageBuff);

// Execute TLS
BOOLEAN ExecuteTLS(PUCHAR imageBuff);

ULONG_PTR GetAddressOfEntryPoint(PUCHAR imageBuff);