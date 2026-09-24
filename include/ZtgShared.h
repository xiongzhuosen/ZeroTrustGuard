#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define ZTG_DEVICE_NAME  L"\\Device\\ZeroTrustGuard"
#define ZTG_SYM_NAME     L"\\DosDevices\\ZeroTrustGuard"
#define ZTG_USER_SYM     L"\\\\.\\ZeroTrustGuard"

#define IOCTL_ZTG_SET_CONFIG  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZTG_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZTG_GET_STATS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZTG_GET_EVENTS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ZTG_PROTOCOL_VERSION 4
#define ZTG_MAX_EVENT_PATH   260
#define ZTG_MAX_EVENTS_OUT   16

#define ZTG_EVENT_PROCESS    1
#define ZTG_EVENT_IMAGE      2
#define ZTG_EVENT_REGISTRY   3
#define ZTG_EVENT_LOLBIN     4
#define ZTG_EVENT_BEHAVIOR   5
#define ZTG_EVENT_LSASS      6
#define ZTG_EVENT_PERSIST    7
#define ZTG_EVENT_RANSOM     8

typedef struct _ZTG_CONFIG_V2 {
    WCHAR whiteDirs[512];
    WCHAR blackDirs[512];
    WCHAR denyExts[128];
    WCHAR usbWhitelist[512];
    WCHAR logPath[260];
    WCHAR regStartupWhite[256];
    BOOLEAN blockDLLHijack;
    BOOLEAN blockUsbExec;
    BOOLEAN enableExtBlock;
    BOOLEAN enableLolBins;
    BOOLEAN enableBehavior;
    BOOLEAN enableLsassProtect;
    BOOLEAN enablePersistProtect;
    BOOLEAN blockRansomTools;
    BOOLEAN enableUntrustedPath;
    BOOLEAN enableCanaryProtect;
    UCHAR reserved[249];
} ZTG_CONFIG_V2;

typedef struct _ZTG_STATS {
    ULONGLONG blockedProcesses;
    ULONGLONG blockedImages;
    ULONGLONG blockedRegistry;
    ULONGLONG strippedHandles;
    ULONGLONG allowedWhite;
    ULONGLONG blockedLolBins;
    ULONGLONG blockedBehavior;
    ULONGLONG blockedPersist;
    ULONGLONG protectedLsass;
    ULONGLONG blockedRansom;
    ULONG version;
    ULONG queueDropped;
} ZTG_STATS;

typedef struct _ZTG_EVENT {
    ULONG type;
    ULONG pid;
    ULONGLONG tick;
    WCHAR path[ZTG_MAX_EVENT_PATH];
} ZTG_EVENT;
