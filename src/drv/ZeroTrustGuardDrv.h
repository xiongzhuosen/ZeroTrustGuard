#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "../../include/ZtgShared.h"

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI SeLocateProcessImageName(_In_ PEPROCESS Process, _Outptr_ PUNICODE_STRING* pImageFileName);

extern ZTG_CONFIG_V2 g_Config;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
NTSTATUS RegProtectCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
OB_PREOP_CALLBACK_STATUS MemProtectCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
