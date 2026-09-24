#include "ZeroTrustGuardDrv.h"

#define ZTG_MAX_TOKENS      32
#define ZTG_TOKEN_CHARS     96
#define ZTG_RING_SIZE       64
#define ZTG_PATCH_SIZE      6

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ           0x0010
#define PROCESS_VM_WRITE          0x0020
#define PROCESS_VM_OPERATION      0x0008
#define PROCESS_CREATE_THREAD     0x0002
#define PROCESS_DUP_HANDLE        0x0040
#define PROCESS_SUSPEND_RESUME    0x0800
#define PROCESS_SET_INFORMATION   0x0200
#endif

typedef struct _ZTG_TOKEN_TABLE {
    ULONG count;
    WCHAR tokens[ZTG_MAX_TOKENS][ZTG_TOKEN_CHARS];
    USHORT lengths[ZTG_MAX_TOKENS];
} ZTG_TOKEN_TABLE;

typedef struct _ZTG_RUNTIME {
    ZTG_TOKEN_TABLE white;
    ZTG_TOKEN_TABLE black;
    ZTG_TOKEN_TABLE denyExt;
    ZTG_TOKEN_TABLE usbWhite;
    ZTG_TOKEN_TABLE regWhite;
} ZTG_RUNTIME;

typedef struct _ZTG_RING {
    volatile LONG head;
    volatile LONG tail;
    ZTG_EVENT events[ZTG_RING_SIZE];
} ZTG_RING;

ZTG_CONFIG_V2   g_Config = { 0 };
ZTG_RUNTIME     g_Runtime = { 0 };
ZTG_STATS       g_Stats = { 0 };
ZTG_RING        g_Ring = { 0 };
KSPIN_LOCK      g_ConfigLock;
KSPIN_LOCK      g_RingLock;
LARGE_INTEGER   g_RegCookie = { 0 };
HANDLE          g_ObHandle = NULL;
BOOLEAN         g_ProcessNotify = FALSE;
BOOLEAN         g_ImageNotify = FALSE;

static const WCHAR* g_LolBins[] = {
    L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe",
    L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"certutil.exe",
    L"bitsadmin.exe", L"wmic.exe", L"msiexec.exe", L"msbuild.exe",
    L"csc.exe", L"installutil.exe", L"cmstp.exe", L"hh.exe",
    L"forfiles.exe", L"pcalua.exe", L"bash.exe", L"wsl.exe",
    L"python.exe", L"pythonw.exe", L"node.exe", L"cmd.exe",
    L"msdt.exe", L"presentationhost.exe", L"regasm.exe", L"regsvcs.exe",
    L"addinutil.exe", L"ieexec.exe", L"mavinject.exe", L"odbcconf.exe"
};

static const WCHAR* g_OfficeBrowsers[] = {
    L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
    L"onenote.exe", L"visio.exe", L"msaccess.exe", L"eqnedt32.exe",
    L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe",
    L"brave.exe", L"opera.exe"
};

static const WCHAR* g_SusCmd[] = {
    L"-enc", L"-encodedcommand", L"downloadstring", L"invoke-expression",
    L"frombase64", L"-nop", L"bypass", L"-windowstyle hidden",
    L"urlcache", L"-decode", L"/transfer", L"process call create",
    L"javascript:", L"vbscript:", L"http://", L"https://",
    L"\\temp\\", L"\\appdata\\", L"\\downloads\\", L"iex(",
    L"start-bitstransfer", L"add-mppreference", L"disableantivirus",
    L"vssadmin", L"delete shadows", L"wbadmin", L"recoveryenabled",
    L"cipher /w", L"shadowcopy", L"usn deletejournal", L"schtasks",
    L"/i:http", L"mshta http", L"downloadfile", L"webclient",
    L"reflection.assembly", L"virtualalloc", L"amsiutils"
};

static const WCHAR* g_RansomCmd[] = {
    L"delete shadows", L"shadowcopy delete", L"resize shadowstorage",
    L"wbadmin delete", L"recoveryenabled no", L"bootstatuspolicy ignoreallfailures",
    L"cipher /w", L"usn deletejournal", L"vssadmin delete", L"wmic shadowcopy"
};

static const WCHAR* g_PersistKeys[] = {
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppCertDlls",
    L"\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages",
    L"\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages",
    L"\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
};

static VOID ParseTokenTable(_Out_ ZTG_TOKEN_TABLE* table, _In_reads_(srcChars) const WCHAR* src, _In_ ULONG srcChars)
{
    RtlZeroMemory(table, sizeof(*table));
    if (!src || src[0] == L'\0') {
        return;
    }

    ULONG i = 0;
    while (i < srcChars && src[i] && table->count < ZTG_MAX_TOKENS) {
        while (i < srcChars && (src[i] == L' ' || src[i] == L';' || src[i] == L',')) {
            i++;
        }
        if (i >= srcChars || src[i] == L'\0') {
            break;
        }

        ULONG start = i;
        while (i < srcChars && src[i] && src[i] != L';' && src[i] != L',') {
            i++;
        }

        ULONG end = i;
        while (end > start && src[end - 1] == L' ') {
            end--;
        }

        ULONG len = end - start;
        if (len == 0) {
            continue;
        }
        if (len >= ZTG_TOKEN_CHARS) {
            len = ZTG_TOKEN_CHARS - 1;
        }

        RtlCopyMemory(table->tokens[table->count], &src[start], len * sizeof(WCHAR));
        table->tokens[table->count][len] = L'\0';
        table->lengths[table->count] = (USHORT)(len * sizeof(WCHAR));
        table->count++;
    }
}

static VOID RebuildRuntime(_In_ const ZTG_CONFIG_V2* cfg)
{
    ParseTokenTable(&g_Runtime.white, cfg->whiteDirs, ARRAYSIZE(cfg->whiteDirs));
    ParseTokenTable(&g_Runtime.black, cfg->blackDirs, ARRAYSIZE(cfg->blackDirs));
    ParseTokenTable(&g_Runtime.denyExt, cfg->denyExts, ARRAYSIZE(cfg->denyExts));
    ParseTokenTable(&g_Runtime.usbWhite, cfg->usbWhitelist, ARRAYSIZE(cfg->usbWhitelist));
    ParseTokenTable(&g_Runtime.regWhite, cfg->regStartupWhite, ARRAYSIZE(cfg->regStartupWhite));
}

static BOOLEAN EqualIgnoreCaseN(_In_ PCWSTR a, _In_ PCWSTR b, _In_ USHORT bytes)
{
    UNICODE_STRING sa, sb;
    sa.Buffer = (PWCH)a;
    sa.Length = bytes;
    sa.MaximumLength = bytes;
    sb.Buffer = (PWCH)b;
    sb.Length = bytes;
    sb.MaximumLength = bytes;
    return RtlEqualUnicodeString(&sa, &sb, TRUE);
}

static BOOLEAN PathContainsToken(_In_ PCUNICODE_STRING path, _In_ const ZTG_TOKEN_TABLE* table)
{
    if (!path || !path->Buffer || path->Length == 0 || !table || table->count == 0) {
        return FALSE;
    }

    for (ULONG t = 0; t < table->count; t++) {
        USHORT needle = table->lengths[t];
        if (needle == 0 || path->Length < needle) {
            continue;
        }
        USHORT limit = path->Length - needle;
        for (USHORT i = 0; i <= limit; i += sizeof(WCHAR)) {
            if (EqualIgnoreCaseN((PCWSTR)((PUCHAR)path->Buffer + i), table->tokens[t], needle)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN UnicodeContains(_In_ PCUNICODE_STRING hay, _In_ PCWSTR needle)
{
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, needle);
    if (!hay || !hay->Buffer || hay->Length < n.Length) {
        return FALSE;
    }
    USHORT limit = hay->Length - n.Length;
    for (USHORT i = 0; i <= limit; i += sizeof(WCHAR)) {
        if (EqualIgnoreCaseN((PCWSTR)((PUCHAR)hay->Buffer + i), n.Buffer, n.Length)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN NameEndsWith(_In_ PCUNICODE_STRING path, _In_ PCWSTR name)
{
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, name);
    if (!path || !path->Buffer || path->Length < n.Length) {
        return FALSE;
    }
    return EqualIgnoreCaseN(
        (PCWSTR)((PUCHAR)path->Buffer + path->Length - n.Length),
        n.Buffer,
        n.Length);
}

static BOOLEAN NameInList(_In_ PCUNICODE_STRING path, _In_reads_(count) const WCHAR** names, _In_ ULONG count)
{
    for (ULONG i = 0; i < count; i++) {
        if (NameEndsWith(path, names[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN ExtBlocked(_In_ PCUNICODE_STRING path)
{
    if (!path || path->Length < 2 * sizeof(WCHAR) || g_Runtime.denyExt.count == 0) {
        return FALSE;
    }

    USHORT chars = path->Length / sizeof(WCHAR);
    USHORT dot = 0;
    for (USHORT i = chars; i > 0; i--) {
        WCHAR c = path->Buffer[i - 1];
        if (c == L'.') {
            dot = (USHORT)(i - 1);
            break;
        }
        if (c == L'\\' || c == L'/') {
            return FALSE;
        }
    }
    if (dot == 0 && path->Buffer[0] != L'.') {
        return FALSE;
    }

    UNICODE_STRING ext;
    ext.Buffer = &path->Buffer[dot];
    ext.Length = path->Length - (dot * sizeof(WCHAR));
    ext.MaximumLength = ext.Length;

    for (ULONG t = 0; t < g_Runtime.denyExt.count; t++) {
        UNICODE_STRING blocked;
        blocked.Buffer = g_Runtime.denyExt.tokens[t];
        blocked.Length = g_Runtime.denyExt.lengths[t];
        blocked.MaximumLength = blocked.Length;
        if (RtlEqualUnicodeString(&ext, &blocked, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsPathOnRemovableMedia(_In_ PCUNICODE_STRING path)
{
    static const WCHAR prefix[] = L"\\Device\\";
    PDEVICE_OBJECT deviceObject = NULL;
    PFILE_OBJECT fileObject = NULL;
    UNICODE_STRING dev;
    WCHAR devName[80];
    USHORT chars, end;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !path || !path->Buffer) {
        return FALSE;
    }

    chars = path->Length / sizeof(WCHAR);
    if (chars < 10) {
        return FALSE;
    }
    for (ULONG k = 0; k < 8; k++) {
        if (path->Buffer[k] != prefix[k]) {
            return FALSE;
        }
    }

    end = 8;
    while (end < chars && path->Buffer[end] != L'\\') {
        end++;
    }
    if (end >= chars || end > ARRAYSIZE(devName)) {
        return FALSE;
    }

    RtlCopyMemory(devName, path->Buffer, end * sizeof(WCHAR));
    dev.Buffer = devName;
    dev.Length = (USHORT)(end * sizeof(WCHAR));
    dev.MaximumLength = dev.Length;

    if (!NT_SUCCESS(IoGetDeviceObjectPointer(&dev, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject))) {
        return FALSE;
    }

    BOOLEAN isRemovable = (deviceObject->Characteristics & FILE_REMOVABLE_MEDIA) ? TRUE : FALSE;
    ObDereferenceObject(fileObject);
    return isRemovable;
}

static BOOLEAN IsUsbBlocked(_In_ PCUNICODE_STRING path)
{
    if (!g_Config.blockUsbExec) {
        return FALSE;
    }
    if (PathContainsToken(path, &g_Runtime.usbWhite)) {
        return FALSE;
    }
    return IsPathOnRemovableMedia(path);
}

static BOOLEAN IsSystemImage(_In_ PCUNICODE_STRING path)
{
    return UnicodeContains(path, L"\\windows\\system32\\") ||
           UnicodeContains(path, L"\\windows\\syswow64\\") ||
           UnicodeContains(path, L"\\windows\\winsxs\\") ||
           UnicodeContains(path, L"\\program files\\") ||
           UnicodeContains(path, L"\\program files (x86)\\");
}

static BOOLEAN IsUntrustedPath(_In_ PCUNICODE_STRING path)
{
    if (!path || IsSystemImage(path)) {
        return FALSE;
    }
    return UnicodeContains(path, L"\\downloads\\") ||
           UnicodeContains(path, L"\\appdata\\local\\temp\\") ||
           UnicodeContains(path, L"\\windows\\temp\\") ||
           UnicodeContains(path, L"\\appdata\\roaming\\") ||
           UnicodeContains(path, L"\\desktop\\") ||
           UnicodeContains(path, L"\\public\\") ||
           UnicodeContains(path, L"\\recycle.bin");
}

static BOOLEAN CmdSuspicious(_In_opt_ PCUNICODE_STRING cmd)
{
    if (!cmd || !cmd->Buffer) {
        return FALSE;
    }
    for (ULONG i = 0; i < ARRAYSIZE(g_SusCmd); i++) {
        if (UnicodeContains(cmd, g_SusCmd[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN CmdRansom(_In_opt_ PCUNICODE_STRING cmd)
{
    if (!cmd || !cmd->Buffer) {
        return FALSE;
    }
    for (ULONG i = 0; i < ARRAYSIZE(g_RansomCmd); i++) {
        if (UnicodeContains(cmd, g_RansomCmd[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN ParentIsOfficeOrBrowser(_In_ HANDLE parentPid)
{
    PEPROCESS proc = NULL;
    PUNICODE_STRING image = NULL;
    BOOLEAN hit = FALSE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(parentPid, &proc))) {
        return FALSE;
    }
    if (NT_SUCCESS(SeLocateProcessImageName(proc, &image)) && image) {
        hit = NameInList(image, g_OfficeBrowsers, ARRAYSIZE(g_OfficeBrowsers));
        ExFreePool(image);
    }
    ObDereferenceObject(proc);
    return hit;
}

static BOOLEAN ProcessNameIsLsass(_In_ PEPROCESS process)
{
    PCHAR name = PsGetProcessImageFileName(process);
    static const CHAR target[] = "lsass.exe";
    ULONG i;
    if (!name) {
        return FALSE;
    }
    for (i = 0; i < sizeof(target) - 1; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z') {
            c = (CHAR)(c + 32);
        }
        if (c != target[i]) {
            return FALSE;
        }
    }
    return name[i] == 0;
}

static VOID PushEvent(_In_ ULONG type, _In_opt_ PCUNICODE_STRING path, _In_ HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);

    LONG head = g_Ring.head;
    LONG next = (head + 1) % ZTG_RING_SIZE;
    if (next == g_Ring.tail) {
        g_Ring.tail = (g_Ring.tail + 1) % ZTG_RING_SIZE;
        InterlockedIncrement((volatile LONG*)&g_Stats.queueDropped);
    }

    ZTG_EVENT* ev = &g_Ring.events[head];
    RtlZeroMemory(ev, sizeof(*ev));
    ev->type = type;
    ev->pid = (ULONG)(ULONG_PTR)pid;
    ev->tick = KeQueryInterruptTime();
    if (path && path->Buffer && path->Length) {
        ULONG copy = path->Length;
        if (copy > (ZTG_MAX_EVENT_PATH - 1) * sizeof(WCHAR)) {
            copy = (ZTG_MAX_EVENT_PATH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(ev->path, path->Buffer, copy);
        ev->path[copy / sizeof(WCHAR)] = L'\0';
    }
    g_Ring.head = next;
    KeReleaseSpinLock(&g_RingLock, irql);
}

static ULONG DrainEvents(_Out_writes_bytes_(bufBytes) ZTG_EVENT* out, _In_ ULONG bufBytes)
{
    ULONG maxCount = bufBytes / sizeof(ZTG_EVENT);
    if (maxCount == 0) {
        return 0;
    }
    if (maxCount > ZTG_MAX_EVENTS_OUT) {
        maxCount = ZTG_MAX_EVENTS_OUT;
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);
    ULONG n = 0;
    while (n < maxCount && g_Ring.tail != g_Ring.head) {
        out[n++] = g_Ring.events[g_Ring.tail];
        g_Ring.tail = (g_Ring.tail + 1) % ZTG_RING_SIZE;
    }
    KeReleaseSpinLock(&g_RingLock, irql);
    return n;
}

VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo || !CreateInfo->ImageFileName) {
        return;
    }

    if (PathContainsToken(CreateInfo->ImageFileName, &g_Runtime.white)) {
        InterlockedIncrement64((volatile LONG64*)&g_Stats.allowedWhite);
        return;
    }

    BOOLEAN blocked = PathContainsToken(CreateInfo->ImageFileName, &g_Runtime.black);
    ULONG evType = ZTG_EVENT_PROCESS;

    if (!blocked && g_Config.enableExtBlock) {
        blocked = ExtBlocked(CreateInfo->ImageFileName);
    }
    if (!blocked) {
        blocked = IsUsbBlocked(CreateInfo->ImageFileName);
    }
    if (!blocked && g_Config.enableUntrustedPath && IsUntrustedPath(CreateInfo->ImageFileName)) {
        blocked = TRUE;
        evType = ZTG_EVENT_BEHAVIOR;
    }
    if (!blocked && g_Config.blockRansomTools && CmdRansom(CreateInfo->CommandLine)) {
        blocked = TRUE;
        evType = ZTG_EVENT_RANSOM;
    }
    if (!blocked && g_Config.enableLolBins &&
        NameInList(CreateInfo->ImageFileName, g_LolBins, ARRAYSIZE(g_LolBins))) {
        BOOLEAN fromSystem = IsSystemImage(CreateInfo->ImageFileName);
        BOOLEAN sus = CmdSuspicious(CreateInfo->CommandLine);
        BOOLEAN badParent = FALSE;
        if (g_Config.enableBehavior && CreateInfo->ParentProcessId) {
            badParent = ParentIsOfficeOrBrowser(CreateInfo->ParentProcessId);
        }
        if (!fromSystem || sus || badParent) {
            blocked = TRUE;
            evType = ZTG_EVENT_LOLBIN;
        }
    }
    if (!blocked && g_Config.enableBehavior && CreateInfo->ParentProcessId &&
        ParentIsOfficeOrBrowser(CreateInfo->ParentProcessId) &&
        !IsSystemImage(CreateInfo->ImageFileName)) {
        blocked = TRUE;
        evType = ZTG_EVENT_BEHAVIOR;
    }

    if (blocked) {
        if (evType == ZTG_EVENT_LOLBIN) {
            InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedLolBins);
        } else if (evType == ZTG_EVENT_BEHAVIOR) {
            InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedBehavior);
        } else if (evType == ZTG_EVENT_RANSOM) {
            InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedRansom);
        } else {
            InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedProcesses);
        }
        PushEvent(evType, CreateInfo->ImageFileName, ProcessId);
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!g_Config.blockDLLHijack || !FullImageName || !ImageInfo || !ImageInfo->ImageBase) {
        return;
    }
    if (!PathContainsToken(FullImageName, &g_Runtime.black) &&
        !(g_Config.enableUntrustedPath && IsUntrustedPath(FullImageName))) {
        return;
    }

    InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedImages);
    PushEvent(ZTG_EVENT_IMAGE, FullImageName, ProcessId);

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            __leave;
        }
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageInfo->ImageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            __leave;
        }
        PUCHAR entry = (PUCHAR)ImageInfo->ImageBase + nt->OptionalHeader.AddressOfEntryPoint;
        UCHAR patch[ZTG_PATCH_SIZE] = { 0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3 };
        PMDL mdl = IoAllocateMdl(entry, sizeof(patch), FALSE, FALSE, NULL);
        if (!mdl) {
            __leave;
        }
        __try {
            MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
            PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
            if (mapped) {
                RtlCopyMemory(mapped, patch, sizeof(patch));
                MmUnmapLockedPages(mapped, mdl);
            }
            MmUnlockPages(mdl);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        IoFreeMdl(mdl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static BOOLEAN ContainsPersistKey(_In_ PCUNICODE_STRING keyPath)
{
    if (!keyPath) {
        return FALSE;
    }
    for (ULONG n = 0; n < ARRAYSIZE(g_PersistKeys); n++) {
        if (UnicodeContains(keyPath, g_PersistKeys[n])) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS BlockPersist(_In_ PUNICODE_STRING keyPath)
{
    if (!keyPath || !ContainsPersistKey(keyPath)) {
        return STATUS_SUCCESS;
    }
    if (PathContainsToken(keyPath, &g_Runtime.regWhite)) {
        return STATUS_SUCCESS;
    }
    InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedPersist);
    InterlockedIncrement64((volatile LONG64*)&g_Stats.blockedRegistry);
    PushEvent(ZTG_EVENT_PERSIST, keyPath, PsGetCurrentProcessId());
    return STATUS_ACCESS_DENIED;
}

NTSTATUS RegProtectCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (!g_Config.enablePersistProtect) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PUNICODE_STRING keyPath = NULL;
    PUNICODE_STRING allocated = NULL;

    switch (notifyClass) {
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (info) {
            keyPath = info->CompleteName;
        }
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (info) {
            keyPath = info->NewName;
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info && info->Object) {
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object, NULL, &allocated, 0))) {
                keyPath = allocated;
            }
        }
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info && info->Object) {
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object, NULL, &allocated, 0))) {
                keyPath = allocated;
            }
        }
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    NTSTATUS status = BlockPersist(keyPath);
    if (allocated) {
        CmCallbackReleaseKeyObjectIDEx(allocated);
    }
    return status;
}

OB_PREOP_CALLBACK_STATUS MemProtectCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (OperationInformation->ObjectType != *PsProcessType || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK* access = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    ACCESS_MASK danger = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    PEPROCESS target = (PEPROCESS)OperationInformation->Object;
    BOOLEAN lsass = FALSE;

    if (g_Config.enableLsassProtect) {
        lsass = ProcessNameIsLsass(target);
        if (lsass) {
            danger |= PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
                      PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION;
        }
    }

    if ((*access & danger) == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (PsGetProcessId(target) != PsGetCurrentProcessId()) {
        *access &= ~danger;
        InterlockedIncrement64((volatile LONG64*)&g_Stats.strippedHandles);
        if (lsass) {
            InterlockedIncrement64((volatile LONG64*)&g_Stats.protectedLsass);
            UNICODE_STRING ls = RTL_CONSTANT_STRING(L"lsass.exe");
            PushEvent(ZTG_EVENT_LSASS, &ls, PsGetProcessId(target));
        }
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ZTG_SET_CONFIG:
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ZTG_CONFIG_V2)) {
            KIRQL irql;
            KeAcquireSpinLock(&g_ConfigLock, &irql);
            RtlCopyMemory(&g_Config, Irp->AssociatedIrp.SystemBuffer, sizeof(ZTG_CONFIG_V2));
            RtlZeroMemory(g_Config.reserved, sizeof(g_Config.reserved));
            RebuildRuntime(&g_Config);
            KeReleaseSpinLock(&g_ConfigLock, irql);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_ZTG_GET_VERSION:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG)) {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = ZTG_PROTOCOL_VERSION;
            info = sizeof(ULONG);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_ZTG_GET_STATS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ZTG_STATS)) {
            ZTG_STATS snap = g_Stats;
            snap.version = ZTG_PROTOCOL_VERSION;
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &snap, sizeof(snap));
            info = sizeof(snap);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_ZTG_GET_EVENTS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ZTG_EVENT)) {
            ULONG n = DrainEvents((ZTG_EVENT*)Irp->AssociatedIrp.SystemBuffer,
                                  stack->Parameters.DeviceIoControl.OutputBufferLength);
            info = n * sizeof(ZTG_EVENT);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS RegisterCallbacks(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ProcessNotify = TRUE;

    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ImageNotify = TRUE;

    UNICODE_STRING regAltitude;
    RtlInitUnicodeString(&regAltitude, L"321000");
    status = CmRegisterCallbackEx(RegProtectCallback, &regAltitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    OB_OPERATION_REGISTRATION opReg = { 0 };
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = MemProtectCallback;

    OB_CALLBACK_REGISTRATION cbReg = { 0 };
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321000");
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;
    status = ObRegisterCallbacks(&cbReg, &g_ObHandle);
    return status;
}

static VOID UnregisterCallbacks(VOID)
{
    if (g_ObHandle) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = NULL;
    }
    if (g_RegCookie.QuadPart) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
    }
    if (g_ImageNotify) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        g_ImageNotify = FALSE;
    }
    if (g_ProcessNotify) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        g_ProcessNotify = FALSE;
    }
}

NTSTATUS CreateCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, ZTG_SYM_NAME);
    UnregisterCallbacks();
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName, symLink;
    NTSTATUS status;

    KeInitializeSpinLock(&g_ConfigLock);
    KeInitializeSpinLock(&g_RingLock);
    g_Stats.version = ZTG_PROTOCOL_VERSION;
    g_Config.enableExtBlock = TRUE;
    g_Config.blockUsbExec = TRUE;
    g_Config.enableLolBins = TRUE;
    g_Config.enableBehavior = TRUE;
    g_Config.enableLsassProtect = TRUE;
    g_Config.enablePersistProtect = TRUE;
    g_Config.blockRansomTools = TRUE;
    g_Config.enableUntrustedPath = TRUE;
    g_Config.enableCanaryProtect = TRUE;

    RtlInitUnicodeString(&deviceName, ZTG_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, ZTG_SYM_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = RegisterCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        UnregisterCallbacks();
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
        return status;
    }
    return STATUS_SUCCESS;
}
