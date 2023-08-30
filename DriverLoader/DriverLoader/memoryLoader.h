#pragma once

#include <ntddk.h>

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

// Repair Cookie
BOOLEAN RepairCookie(UINT_PTR oepAddr);


ULONG_PTR GetAddressOfEntryPoint(PUCHAR imageBuff);


///
VOID LoadDriver(ULONG_PTR filebuff);


//#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;
NTSTATUS  ZwQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);



// SystemModuleInformation = 11 Driver module information
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


// Export Undocumented Functions
ULONG_PTR  RtlFindExportedRoutineByName(ULONG64 a1, char* a2);