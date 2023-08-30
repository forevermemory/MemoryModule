#include <ntifs.h>


HANDLE threadHandle = NULL;

VOID P_KSTART_ROUTINE(_In_ PVOID StartContext)
{
	DbgPrint("sys: Enter KSTART_ROUTINE\n");

	for (size_t i = 0; i < 10; i++)
	{
		LARGE_INTEGER Interval = { 0 };
		Interval.QuadPart = -10 * 1000 * 1000; // 1s
		KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		DbgPrint("sys: times:%d\n", i);
	}
	DbgPrint("sys: Leave KSTART_ROUTINE\n");
}

//VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
//{
//	DbgPrint("sys:Enter DriverUnload\n");
//}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	DbgPrint("sys: Enter DriverEntry\n");
	//pDriverObject->DriverUnload = DriverUnload;

	PsCreateSystemThread(&threadHandle,0, NULL, NtCurrentProcess(), NULL, P_KSTART_ROUTINE, NULL);
	
	DbgPrint("sys: Leave DriverEntry\n");
	return STATUS_SUCCESS;
}