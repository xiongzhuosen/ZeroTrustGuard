#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <winioctl.h>
#include <shellapi.h>
#include <commctrl.h>
#include <shlobj.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <wchar.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <fwpmu.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <vssym32.h>

#include "resource.h"
#include "ZtgShared.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define REG_KEY L"SOFTWARE\\ZeroTrustGuard"
#define CONFIG_SEC 30
#define KEY_BYTES 10
#define CMD_BUFFER_SIZE 4096
#define WM_TRAY (WM_APP + 1)
#define WM_ZTG_LOG (WM_APP + 2)
#define WM_ZTG_EVT (WM_APP + 3)
#define IDT_STATS 1
#define IDT_EVENTS 2
#define IDT_HEARTBEAT 3
#define NAV_COUNT 10
#define IDC_SIDEBAR_BASE 4000
#define IDC_SAVE 4100
#define IDC_BROWSE_LOG 4101
#define IDC_TEST_CLOUD 4102
#define IDC_TEST_VT 4103
#define IDC_HUNT 4104
#define IDC_QUAR_RESTORE 4105
#define IDC_QUAR_PURGE 4106
#define IDC_SCAN_FILE 4107
#define IDC_CANARY_PLANT 4108
#define IDC_EVT_LIST 4200
#define IDC_LOG_VIEW 4201
#define IDC_QUAR_LIST 4202

static const GUID ZTG_WFP_PROVIDER_GUID =
    { 0xa5422d3a, 0x291d, 0x4e15, { 0x91, 0x7a, 0xa1, 0x67, 0xa6, 0xb5, 0x3b, 0x4b } };

typedef struct {
    WCHAR whiteDirs[512];
    WCHAR blackDirs[512];
    WCHAR denyExts[128];
    WCHAR usbWhitelist[512];
    WCHAR blackPorts[128];
    WCHAR whitePorts[128];
    WCHAR logPath[MAX_PATH];
    WCHAR regStartupWhite[256];
    BOOL  enableTOTP;
    BYTE  totpSecret[10];
    char  vtApiKey[65];
    WCHAR webhookUrl[512];
    WCHAR tenantId[64];
    BOOL  cloudEnabled;
    BOOL  vtEnabled;
    int   logLevel;
    BOOL  logCleanupEnabled;
    int   logRetainDays;
    int   logMaxMB;
    BOOL  enableNotify;
    BOOL  enableSound;
    BOOL  enableHighRiskPrompts;
    BOOL  enableSysmonWatcher;
    BOOL  enableWDAC;
    BOOL  blockDLLHijack;
    BOOL  blockClipboardHijack;
    BOOL  blockKeyboardRecord;
    BOOL  disableNTLM;
    BOOL  disableSMB1;
    BOOL  forceDoH;
    BOOL  disableBTIR;
    BOOL  disablePromisc;
    BOOL  disableCamMic;
    BOOL  disableVSS;
    BOOL  lockBiosUpdate;
    BOOL  blockHIDKeylog;
    BOOL  enableSpectreMitigation;
    BOOL  blockUsbExec;
    BOOL  enableExtBlock;
    BOOL  enableLolBins;
    BOOL  enableBehavior;
    BOOL  enableLsassProtect;
    BOOL  enablePersistProtect;
    BOOL  blockRansomTools;
    BOOL  enableUntrustedPath;
    BOOL  enableCanaryProtect;
    BOOL  enableDownloadGuard;
} CONFIG;

typedef PVOID EVT_HANDLE;
typedef DWORD(WINAPI* EVT_SUBSCRIBE_CALLBACK)(int, PVOID, EVT_HANDLE);
typedef EVT_HANDLE(WINAPI* PFN_EVT_SUBSCRIBE)(EVT_HANDLE, HANDLE, LPCWSTR, LPCWSTR, EVT_HANDLE, PVOID, EVT_SUBSCRIBE_CALLBACK, DWORD);
typedef BOOL(WINAPI* PFN_EVT_CLOSE)(EVT_HANDLE);
typedef BOOL(WINAPI* PFN_EVT_RENDER)(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef EVT_HANDLE(WINAPI* PFN_EVT_OPEN_LOG)(EVT_HANDLE, LPCWSTR, DWORD);

static CONFIG gCfg;
static HANDLE gDrv = INVALID_HANDLE_VALUE;
static HANDLE gEvExit = NULL;
static CRITICAL_SECTION gLogLock;
static CRITICAL_SECTION gVtLock;
static CRITICAL_SECTION gCloudLock;
static NOTIFYICONDATAW gTray;
static HHOOK gKeyboardHook = NULL;
static BOOL gDriverOk = FALSE;
static HWND gMain = NULL;
static int gNav = 0;
static HFONT gFontUi = NULL;
static HFONT gFontTitle = NULL;
static HFONT gFontSmall = NULL;
static HBRUSH gBrBg = NULL;
static HBRUSH gBrCard = NULL;
static HBRUSH gBrSide = NULL;
static HBRUSH gBrAccent = NULL;
static HBRUSH gBrEdit = NULL;
static COLORREF gColBg = RGB(16, 18, 22);
static COLORREF gColSide = RGB(22, 24, 29);
static COLORREF gColCard = RGB(28, 31, 38);
static COLORREF gColAccent = RGB(47, 158, 140);
static COLORREF gColText = RGB(232, 234, 237);
static COLORREF gColMuted = RGB(154, 160, 172);
static COLORREF gColOk = RGB(63, 185, 80);
static COLORREF gColWarn = RGB(210, 153, 34);
static COLORREF gColBad = RGB(248, 81, 73);
static HANDLE gClipboardWatcherThread = NULL;
static HANDLE gKeyboardWatcherThread = NULL;
static HANDLE gSysmonWatcherThread = NULL;
static HANDLE gProcWatchThread = NULL;
static HANDLE gEventPumpThread = NULL;
static HANDLE gDownloadGuardThread = NULL;
static HANDLE gCanaryThread = NULL;
static HANDLE gPersistHuntThread = NULL;
static ULONGLONG gUserQuarantined = 0;
static ULONGLONG gUserDownloadBlocked = 0;
static ULONGLONG gUserPersistFound = 0;
static ZTG_STATS gStats = { 0 };
static ULONGLONG gVtLast[4] = { 0 };
static int gVtIdx = 0;
static time_t gVtBlockedUntil = 0;
static PFN_EVT_SUBSCRIBE g_pfnEvtSubscribe = NULL;
static PFN_EVT_CLOSE g_pfnEvtClose = NULL;
static PFN_EVT_RENDER g_pfnEvtRender = NULL;
static HWND gEdits[24];
static HWND gChecks[32];
static HWND gEvtList = NULL;
static HWND gLogView = NULL;
static HWND gQuarList = NULL;
static HWND gStatus = NULL;

static void Log(const wchar_t* fmt, ...);
static void SendConfigToDriver(void);
static void ApplySystemHardening(void);
static void ApplyPortFilterRules(void);
static void ScanFileWithVT(LPCWSTR filePath);
static void CloudPostJson(const char* jsonUtf8);
static void CloudEmitEvent(const wchar_t* kind, const wchar_t* path);
static void LoadCfg(void);
static void SaveCfg(void);
static BOOL ConnectDriver(void);
static BOOL InstallAndStartDriver(void);
static void StartMonitorThreads(void);
static void StopMonitorThreads(void);
static BOOL QuarantineFile(LPCWSTR filePath);
static void RefreshQuarantineList(void);
static void PlantCanaries(void);
static void HuntPersistence(void);
static INT_PTR CALLBACK TotpPromptDlgProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK LowLevelKeyboardProc(int, WPARAM, LPARAM);
static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

static BOOL ZTG_IsUserAnAdmin(void)
{
    BOOL admin = FALSE;
    HANDLE token = NULL;
    PSID sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
            CheckTokenMembership(token, sid, &admin);
            FreeSid(sid);
        }
        CloseHandle(token);
    }
    return admin;
}

static BOOL EnsureAppdataPath(wchar_t* pathBuffer, size_t bufferSize)
{
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, pathBuffer))) {
        return FALSE;
    }
    PathAppendW(pathBuffer, L"ZeroTrustGuard");
    DWORD attribs = GetFileAttributesW(pathBuffer);
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        PSECURITY_DESCRIPTOR pSD = NULL;
        SECURITY_ATTRIBUTES sa = { sizeof(sa) };
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &pSD, NULL)) {
            return FALSE;
        }
        sa.lpSecurityDescriptor = pSD;
        BOOL ok = CreateDirectoryW(pathBuffer, &sa);
        LocalFree(pSD);
        if (!ok && GetLastError() != ERROR_ALREADY_EXISTS) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL EnsureLogPath(void)
{
    if (!gCfg.logPath[0]) {
        return FALSE;
    }
    DWORD attribs = GetFileAttributesW(gCfg.logPath);
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        return SHCreateDirectoryExW(NULL, gCfg.logPath, NULL) == ERROR_SUCCESS;
    }
    return (attribs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static void Log(const wchar_t* fmt, ...)
{
    if (gCfg.logLevel <= 0 || !EnsureLogPath()) {
        return;
    }
    EnterCriticalSection(&gLogLock);
    wchar_t path[MAX_PATH];
    StringCchCopyW(path, MAX_PATH, gCfg.logPath);
    PathAppendW(path, L"ZeroTrustGuard.log");
    FILE* fp = _wfopen(path, L"a, ccs=UTF-8");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        if (gCfg.logMaxMB > 0 && size > (long long)gCfg.logMaxMB * 1024 * 1024) {
            fclose(fp);
            wchar_t rolled[MAX_PATH];
            SYSTEMTIME st;
            GetLocalTime(&st);
            StringCchPrintfW(rolled, MAX_PATH, L"%s\\ZeroTrust_%04d%02d%02d_%02d%02d%02d.log",
                gCfg.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            _wrename(path, rolled);
            fp = _wfopen(path, L"w, ccs=UTF-8");
        }
        if (fp) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fwprintf(fp, L"[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            va_list ap;
            va_start(ap, fmt);
            vfwprintf(fp, fmt, ap);
            va_end(ap);
            fwprintf(fp, L"\n");
            fclose(fp);
        }
    }
    LeaveCriticalSection(&gLogLock);
    if (gMain) {
        wchar_t* copy = (wchar_t*)malloc(1024 * sizeof(wchar_t));
        if (copy) {
            va_list ap;
            va_start(ap, fmt);
            StringCchVPrintfW(copy, 1024, fmt, ap);
            va_end(ap);
            if (!PostMessageW(gMain, WM_ZTG_LOG, 0, (LPARAM)copy)) {
                free(copy);
            }
        }
    }
}

static uint32_t HOTP(const BYTE* key, size_t keyLen, uint64_t counter)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[20];
    uint32_t result = 0;
    BYTE counterData[8];
    for (int i = 7; i >= 0; --i, counter >>= 8) {
        counterData[i] = (BYTE)(counter & 0xFF);
    }
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0))) {
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, counterData, sizeof(counterData), 0))) {
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash, sizeof(hash), 0))) {
        goto cleanup;
    }
    uint32_t offset = hash[19] & 0x0F;
    uint32_t binCode = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
    result = binCode % 1000000;
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

static void GetTOTP(wchar_t* buffer, size_t bufferSize)
{
    uint64_t counter = (uint64_t)(time(NULL) / CONFIG_SEC);
    uint32_t code = HOTP(gCfg.totpSecret, KEY_BYTES, counter);
    StringCchPrintfW(buffer, bufferSize, L"%06u", code);
}

static void LoadCfg(void)
{
    memset(&gCfg, 0, sizeof(gCfg));
    gCfg.logLevel = 1;
    gCfg.logRetainDays = 30;
    gCfg.logMaxMB = 100;
    gCfg.logCleanupEnabled = TRUE;
    gCfg.enableNotify = TRUE;
    gCfg.vtEnabled = TRUE;
    gCfg.cloudEnabled = TRUE;
    gCfg.blockUsbExec = TRUE;
    gCfg.enableExtBlock = TRUE;
    gCfg.enableLolBins = TRUE;
    gCfg.enableBehavior = TRUE;
    gCfg.enableLsassProtect = TRUE;
    gCfg.enablePersistProtect = TRUE;
    gCfg.blockRansomTools = TRUE;
    gCfg.enableUntrustedPath = TRUE;
    gCfg.enableCanaryProtect = TRUE;
    gCfg.enableDownloadGuard = TRUE;
    StringCchCopyW(gCfg.denyExts, ARRAYSIZE(gCfg.denyExts), L".exe;.dll;.sys;.bat;.cmd;.ps1;.vbs;.js;.jse;.wsf;.hta;.scr;.pif");
    StringCchCopyW(gCfg.tenantId, ARRAYSIZE(gCfg.tenantId), L"local");
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD cb = sizeof(gCfg);
        RegQueryValueExW(hKey, L"Config_v3", NULL, NULL, (LPBYTE)&gCfg, &cb);
        BYTE encryptedSecret[256];
        cb = sizeof(encryptedSecret);
        if (RegQueryValueExW(hKey, L"TOTPSecret_Enc", NULL, NULL, encryptedSecret, &cb) == ERROR_SUCCESS) {
            DATA_BLOB in = { cb, encryptedSecret }, out;
            if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                if (out.cbData == sizeof(gCfg.totpSecret)) {
                    memcpy(gCfg.totpSecret, out.pbData, sizeof(gCfg.totpSecret));
                }
                LocalFree(out.pbData);
            }
        }
        RegCloseKey(hKey);
    }
    if (!gCfg.logPath[0]) {
        EnsureAppdataPath(gCfg.logPath, MAX_PATH);
        PathAppendW(gCfg.logPath, L"logs");
    }
}

static void SaveCfg(void)
{
    HKEY hKey = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa) };
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &pSD, NULL)) {
        return;
    }
    sa.lpSecurityDescriptor = pSD;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY, 0, NULL, 0, KEY_WRITE, &sa, &hKey, NULL) == ERROR_SUCCESS) {
        CONFIG snap = gCfg;
        DATA_BLOB in = { sizeof(snap.totpSecret), snap.totpSecret }, out;
        if (CryptProtectData(&in, L"ZeroTrustGuard TOTP Secret", NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out)) {
            RegSetValueExW(hKey, L"TOTPSecret_Enc", 0, REG_BINARY, out.pbData, out.cbData);
            LocalFree(out.pbData);
            SecureZeroMemory(snap.totpSecret, sizeof(snap.totpSecret));
            RegSetValueExW(hKey, L"Config_v3", 0, REG_BINARY, (LPBYTE)&snap, sizeof(snap));
        } else {
            Log(L"DPAPI encrypt failed (%d)", GetLastError());
        }
        RegCloseKey(hKey);
    }
    if (pSD) LocalFree(pSD);
}

static BOOL HandleFirstRunAndEULA(void)
{
    wchar_t marker[MAX_PATH];
    if (!EnsureAppdataPath(marker, MAX_PATH)) {
        return FALSE;
    }
    PathAppendW(marker, L"eula_accepted.txt");
    if (GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }
    const wchar_t* eula =
        L"欢迎使用 ZeroTrustGuard 4.0\n\n"
        L"1. 本软件按原样提供。内核行为引擎、隔离、下载守护与系统强化可能影响系统行为。\n"
        L"2. 启用 VirusTotal 会将文件哈希或文件上传到 VirusTotal。\n"
        L"3. 启用反馈云端会将拦截事件与统计以 JSON 发送到您配置的 Webhook。\n"
        L"点击“是”表示同意并继续。";
    if (MessageBoxW(NULL, eula, L"最终用户许可协议", MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) != IDYES) {
        return FALSE;
    }
    HANDLE h = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(h);
    return TRUE;
}

static BOOL InstallAndStartDriver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;
    wchar_t driverPath[MAX_PATH];
    GetSystemDirectoryW(driverPath, MAX_PATH);
    PathAppendW(driverPath, L"drivers\\ZeroTrustGuardDrv.sys");
    if (GetFileAttributesW(driverPath) == INVALID_FILE_ATTRIBUTES) {
        wchar_t local[MAX_PATH];
        GetModuleFileNameW(NULL, local, MAX_PATH);
        PathRemoveFileSpecW(local);
        PathAppendW(local, L"ZeroTrustGuardDrv.sys");
        if (GetFileAttributesW(local) != INVALID_FILE_ATTRIBUTES) {
            CopyFileW(local, driverPath, FALSE);
        }
    }
    SC_HANDLE svc = CreateServiceW(scm, L"ZeroTrustGuardDrv", L"ZeroTrustGuard Kernel Driver",
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driverPath, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        if (GetLastError() != ERROR_SERVICE_EXISTS) {
            CloseServiceHandle(scm);
            return FALSE;
        }
        svc = OpenServiceW(scm, L"ZeroTrustGuardDrv", SERVICE_START);
        if (!svc) {
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    BOOL ok = StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static BOOL ConnectDriver(void)
{
    if (gDrv != INVALID_HANDLE_VALUE) {
        CloseHandle(gDrv);
        gDrv = INVALID_HANDLE_VALUE;
    }
    gDrv = CreateFileW(ZTG_USER_SYM, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (gDrv == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    DWORD ret = 0, ver = 0;
    if (!DeviceIoControl(gDrv, IOCTL_ZTG_GET_VERSION, NULL, 0, &ver, sizeof(ver), &ret, NULL) || ver < 3) {
        CloseHandle(gDrv);
        gDrv = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    Log(L"driver connected, protocol %u", ver);
    return TRUE;
}

static void SendConfigToDriver(void)
{
    if (gDrv == INVALID_HANDLE_VALUE) return;
    ZTG_CONFIG_V2 cfg = { 0 };
    StringCchCopyW(cfg.whiteDirs, ARRAYSIZE(cfg.whiteDirs), gCfg.whiteDirs);
    StringCchCopyW(cfg.blackDirs, ARRAYSIZE(cfg.blackDirs), gCfg.blackDirs);
    StringCchCopyW(cfg.denyExts, ARRAYSIZE(cfg.denyExts), gCfg.denyExts);
    StringCchCopyW(cfg.usbWhitelist, ARRAYSIZE(cfg.usbWhitelist), gCfg.usbWhitelist);
    StringCchCopyW(cfg.logPath, ARRAYSIZE(cfg.logPath), gCfg.logPath);
    StringCchCopyW(cfg.regStartupWhite, ARRAYSIZE(cfg.regStartupWhite), gCfg.regStartupWhite);
    cfg.blockDLLHijack = gCfg.blockDLLHijack ? TRUE : FALSE;
    cfg.blockUsbExec = gCfg.blockUsbExec ? TRUE : FALSE;
    cfg.enableExtBlock = gCfg.enableExtBlock ? TRUE : FALSE;
    cfg.enableLolBins = gCfg.enableLolBins ? TRUE : FALSE;
    cfg.enableBehavior = gCfg.enableBehavior ? TRUE : FALSE;
    cfg.enableLsassProtect = gCfg.enableLsassProtect ? TRUE : FALSE;
    cfg.enablePersistProtect = gCfg.enablePersistProtect ? TRUE : FALSE;
    cfg.blockRansomTools = gCfg.blockRansomTools ? TRUE : FALSE;
    cfg.enableUntrustedPath = gCfg.enableUntrustedPath ? TRUE : FALSE;
    cfg.enableCanaryProtect = gCfg.enableCanaryProtect ? TRUE : FALSE;
    DWORD ret = 0;
    if (!DeviceIoControl(gDrv, IOCTL_ZTG_SET_CONFIG, &cfg, sizeof(cfg), NULL, 0, &ret, NULL)) {
        Log(L"send config failed (%d)", GetLastError());
    }
}

static void RefreshStats(void)
{
    if (gDrv == INVALID_HANDLE_VALUE) return;
    ZTG_STATS s = { 0 };
    DWORD ret = 0;
    if (DeviceIoControl(gDrv, IOCTL_ZTG_GET_STATS, NULL, 0, &s, sizeof(s), &ret, NULL) && ret >= sizeof(s)) {
        gStats = s;
    }
}

static BOOL JsonEscape(char* dst, size_t dstSize, const wchar_t* src)
{
    char utf8[1024];
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1, utf8, sizeof(utf8), NULL, NULL);
    if (n <= 0) return FALSE;
    size_t o = 0;
    for (int i = 0; utf8[i] && o + 2 < dstSize; i++) {
        unsigned char c = (unsigned char)utf8[i];
        if (c == '"' || c == '\\') {
            if (o + 3 >= dstSize) break;
            dst[o++] = '\\';
            dst[o++] = (char)c;
        } else if (c < 0x20) {
            continue;
        } else {
            dst[o++] = (char)c;
        }
    }
    dst[o] = 0;
    return TRUE;
}

static BOOL HttpExchange(LPCWSTR host, INTERNET_PORT port, LPCWSTR method, LPCWSTR path,
    LPCWSTR extraHeaders, const void* body, DWORD bodyLen, char* out, DWORD outSize, DWORD* statusCode)
{
    BOOL ok = FALSE;
    HINTERNET ses = WinHttpOpen(L"ZeroTrustGuard/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return FALSE;
    DWORD timeout = 30000;
    WinHttpSetTimeouts(ses, timeout, timeout, timeout, timeout);
    HINTERNET con = WinHttpConnect(ses, host, port, 0);
    if (!con) { WinHttpCloseHandle(ses); return FALSE; }
    HINTERNET req = WinHttpOpenRequest(con, method, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return FALSE; }
    if (WinHttpSendRequest(req, extraHeaders, extraHeaders ? (DWORD)-1 : 0, (LPVOID)body, bodyLen, bodyLen, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &code, &sz, NULL);
        if (statusCode) *statusCode = code;
        DWORD total = 0;
        if (out && outSize) {
            out[0] = 0;
            for (;;) {
                DWORD avail = 0, got = 0;
                if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
                if (total + avail + 1 > outSize) avail = outSize - total - 1;
                if (avail == 0) break;
                if (!WinHttpReadData(req, out + total, avail, &got) || got == 0) break;
                total += got;
                out[total] = 0;
            }
        }
        ok = TRUE;
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return ok;
}

static void LogVtHttpError(DWORD status, const char* body)
{
    if (status == 401) {
        if (body && strstr(body, "WrongCredentials")) {
            Log(L"VT: API 密钥不正确 (WrongCredentialsError)");
        } else if (body && strstr(body, "UserNotActive")) {
            Log(L"VT: 账户未激活 (UserNotActiveError)");
        } else {
            Log(L"VT: 需要有效 API Key (AuthenticationRequiredError)");
        }
    } else if (status == 403) {
        Log(L"VT: 当前密钥无权执行该操作 (ForbiddenError)");
    } else if (status == 404) {
        Log(L"VT: 资源不存在 (NotFoundError)");
    } else if (status == 409) {
        Log(L"VT: 资源已存在 (AlreadyExistsError)");
    } else if (status == 424) {
        Log(L"VT: 依赖请求失败 (FailedDependencyError)");
    } else if (status == 429) {
        if (body && strstr(body, "QuotaExceeded")) {
            Log(L"VT: 配额已用尽，每日 00:00 UTC 重置 (QuotaExceededError)");
        } else {
            Log(L"VT: 请求过于频繁 (TooManyRequestsError)");
        }
    } else if (status == 400) {
        Log(L"VT: 请求无效或参数错误 (BadRequest/InvalidArgument)");
    } else if (status == 503) {
        Log(L"VT: 临时服务器错误，可稍后重试 (TransientError)");
    } else if (status == 504) {
        Log(L"VT: 操作超时 (DeadlineExceededError)");
    } else {
        Log(L"VT: HTTP %u", status);
    }
}

static BOOL Sha256FileHex(LPCWSTR path, char* hex, DWORD hexSize)
{
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    BOOL ok = FALSE;
    PBYTE buf = (PBYTE)malloc(64 * 1024);
    if (!buf) { CloseHandle(hFile); return FALSE; }
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) &&
        BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0))) {
        DWORD rd = 0;
        BOOL readOk = TRUE;
        while (ReadFile(hFile, buf, 64 * 1024, &rd, NULL) && rd) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hash, buf, rd, 0))) {
                readOk = FALSE;
                break;
            }
        }
        if (readOk && BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0)) && hexSize >= 65) {
            for (int i = 0; i < 32; i++) {
                sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
            }
            ok = TRUE;
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(buf);
    CloseHandle(hFile);
    return ok;
}

static void ParseVtStats(const char* json)
{
    const char* mal = strstr(json, "\"malicious\"");
    const char* sus = strstr(json, "\"suspicious\"");
    const char* und = strstr(json, "\"undetected\"");
    int m = 0, s = 0, u = 0;
    if (mal) sscanf_s(mal, "\"malicious\": %d", &m);
    if (sus) sscanf_s(sus, "\"suspicious\": %d", &s);
    if (und) sscanf_s(und, "\"undetected\": %d", &u);
    Log(L"VT: malicious=%d suspicious=%d undetected=%d", m, s, u);
    if (gCfg.enableNotify && m > 0) {
        gTray.uFlags = NIF_INFO;
        StringCchCopyW(gTray.szInfoTitle, ARRAYSIZE(gTray.szInfoTitle), L"ZeroTrustGuard");
        StringCchPrintfW(gTray.szInfo, ARRAYSIZE(gTray.szInfo), L"VirusTotal 检出恶意 %d", m);
        Shell_NotifyIconW(NIM_MODIFY, &gTray);
    }
}

static BOOL VtLookupHash(const char* sha256, char* out, DWORD outSize, DWORD* status)
{
    wchar_t path[128];
    StringCchPrintfW(path, ARRAYSIZE(path), L"/api/v3/files/%hs", sha256);
    wchar_t headers[160];
    StringCchPrintfW(headers, ARRAYSIZE(headers), L"x-apikey: %hs\r\nAccept: application/json\r\n", gCfg.vtApiKey);
    return HttpExchange(L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, L"GET", path, headers, NULL, 0, out, outSize, status);
}

static BOOL VtUploadFile(LPCWSTR filePath, char* out, DWORD outSize, DWORD* status)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart <= 0 || li.QuadPart > 32 * 1024 * 1024) {
        CloseHandle(hFile);
        Log(L"VT: skip upload, size not eligible");
        return FALSE;
    }
    DWORD fileLen = (DWORD)li.QuadPart;
    BYTE* fileBuf = (BYTE*)malloc(fileLen);
    if (!fileBuf) { CloseHandle(hFile); return FALSE; }
    DWORD got = 0;
    ReadFile(hFile, fileBuf, fileLen, &got, NULL);
    CloseHandle(hFile);

    const char* boundary = "----ZTGBoundary7MA4YWxkTrZu0gW";
    char head[1024];
    char nameUtf8[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, PathFindFileNameW(filePath), -1, nameUtf8, sizeof(nameUtf8), NULL, NULL);
    sprintf_s(head, sizeof(head),
        "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary, nameUtf8);
    char tail[128];
    sprintf_s(tail, sizeof(tail), "\r\n--%s--\r\n", boundary);
    DWORD headLen = (DWORD)strlen(head);
    DWORD tailLen = (DWORD)strlen(tail);
    DWORD total = headLen + got + tailLen;
    BYTE* body = (BYTE*)malloc(total);
    if (!body) { free(fileBuf); return FALSE; }
    memcpy(body, head, headLen);
    memcpy(body + headLen, fileBuf, got);
    memcpy(body + headLen + got, tail, tailLen);
    free(fileBuf);

    wchar_t headers[256];
    StringCchPrintfW(headers, ARRAYSIZE(headers),
        L"x-apikey: %hs\r\nContent-Type: multipart/form-data; boundary=%hs\r\n", gCfg.vtApiKey, boundary);
    BOOL ok = HttpExchange(L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, L"POST", L"/api/v3/files",
        headers, body, total, out, outSize, status);
    free(body);
    return ok;
}

typedef struct {
    wchar_t path[MAX_PATH];
} VT_JOB;

static DWORD WINAPI ScanFileWithVTThread(LPVOID param)
{
    VT_JOB* job = (VT_JOB*)param;
    char sha[65] = { 0 };
    if (!Sha256FileHex(job->path, sha, sizeof(sha))) {
        Log(L"VT: hash failed for %s", job->path);
        free(job);
        return 0;
    }
    char resp[16384] = { 0 };
    DWORD status = 0;
    if (VtLookupHash(sha, resp, sizeof(resp), &status)) {
        if (status == 200) {
            ParseVtStats(resp);
            CloudEmitEvent(L"virustotal", job->path);
            free(job);
            return 0;
        }
        if (status == 404) {
            Log(L"VT: hash unknown, uploading %s", job->path);
            memset(resp, 0, sizeof(resp));
            if (VtUploadFile(job->path, resp, sizeof(resp), &status) && status >= 200 && status < 300) {
                Log(L"VT: upload accepted, hash %hs", sha);
            } else {
                LogVtHttpError(status, resp);
            }
            free(job);
            return 0;
        }
        LogVtHttpError(status, resp);
    } else {
        Log(L"VT: network failure");
    }
    free(job);
    return 0;
}

static void ScanFileWithVT(LPCWSTR filePath)
{
    if (!gCfg.vtEnabled || !gCfg.vtApiKey[0] || !filePath || !filePath[0]) return;
    EnterCriticalSection(&gVtLock);
    if (time(NULL) < gVtBlockedUntil) {
        LeaveCriticalSection(&gVtLock);
        return;
    }
    ULONGLONG now = GetTickCount64();
    if (gVtLast[gVtIdx] && now - gVtLast[gVtIdx] < 1000) {
        gVtBlockedUntil = time(NULL) + 60;
        Log(L"VT rate limited for 60s");
        LeaveCriticalSection(&gVtLock);
        return;
    }
    gVtLast[gVtIdx] = now;
    gVtIdx = (gVtIdx + 1) % 4;
    LeaveCriticalSection(&gVtLock);

    VT_JOB* job = (VT_JOB*)malloc(sizeof(VT_JOB));
    if (!job) return;
    StringCchCopyW(job->path, MAX_PATH, filePath);
    HANDLE th = CreateThread(NULL, 0, ScanFileWithVTThread, job, 0, NULL);
    if (th) CloseHandle(th);
    else free(job);
}

static void CloudPostJson(const char* jsonUtf8)
{
    if (!gCfg.cloudEnabled || !gCfg.webhookUrl[0] || !jsonUtf8) return;
    URL_COMPONENTSW uc = { sizeof(uc) };
    wchar_t host[256] = { 0 }, path[1024] = { 0 };
    uc.lpszHostName = host;
    uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = ARRAYSIZE(path);
    if (!WinHttpCrackUrl(gCfg.webhookUrl, 0, 0, &uc) || !host[0]) {
        Log(L"cloud webhook URL invalid");
        return;
    }
    DWORD status = 0;
    char resp[1024] = { 0 };
    LPCWSTR extra = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    EnterCriticalSection(&gCloudLock);
    BOOL ok = HttpExchange(host, uc.nPort ? uc.nPort : INTERNET_DEFAULT_HTTPS_PORT, L"POST",
        path[0] ? path : L"/", extra, jsonUtf8, (DWORD)strlen(jsonUtf8), resp, sizeof(resp), &status);
    LeaveCriticalSection(&gCloudLock);
    if (!ok) {
        Log(L"cloud webhook network failure");
    } else if (status < 200 || status >= 300) {
        Log(L"cloud webhook HTTP %u", status);
    }
}

static void CloudEmitEvent(const wchar_t* kind, const wchar_t* path)
{
    char k[64], p[1024], t[128];
    JsonEscape(k, sizeof(k), kind);
    JsonEscape(p, sizeof(p), path ? path : L"");
    JsonEscape(t, sizeof(t), gCfg.tenantId);
    char json[1536];
    sprintf_s(json, sizeof(json),
        "{\"source\":\"ZeroTrustGuard\",\"version\":\"4.0.0\",\"tenant\":\"%s\",\"type\":\"%s\",\"path\":\"%s\","
        "\"blocked_process\":%llu,\"blocked_image\":%llu,\"blocked_registry\":%llu,\"stripped_handles\":%llu,"
        "\"blocked_lolbin\":%llu,\"blocked_behavior\":%llu,\"blocked_persist\":%llu,\"protected_lsass\":%llu,"
        "\"blocked_ransom\":%llu,\"quarantined\":%llu}",
        t, k, p,
        (unsigned long long)gStats.blockedProcesses,
        (unsigned long long)gStats.blockedImages,
        (unsigned long long)gStats.blockedRegistry,
        (unsigned long long)gStats.strippedHandles,
        (unsigned long long)gStats.blockedLolBins,
        (unsigned long long)gStats.blockedBehavior,
        (unsigned long long)gStats.blockedPersist,
        (unsigned long long)gStats.protectedLsass,
        (unsigned long long)gStats.blockedRansom,
        (unsigned long long)gUserQuarantined);
    CloudPostJson(json);
}

static DWORD WINAPI ClipboardWatcherThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    HWND hwnd = CreateWindowExW(0, L"STATIC", L"ztg-clip", WS_POPUP, 0, 0, 0, 0, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!hwnd || !AddClipboardFormatListener(hwnd)) return 1;
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (WaitForSingleObject(gEvExit, 0) == WAIT_OBJECT_0) break;
        if (msg.message == WM_CLIPBOARDUPDATE && OpenClipboard(hwnd)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                const WCHAR* text = (const WCHAR*)GlobalLock(hData);
                if (text) {
                    size_t len = wcslen(text);
                    BOOL suspicious = FALSE;
                    if (len >= 26 && len <= 62 && !wcschr(text, L' ')) {
                        if (wcsncmp(text, L"bc1", 3) == 0 || wcsncmp(text, L"0x", 2) == 0 ||
                            text[0] == L'1' || text[0] == L'3' || text[0] == L'T' || text[0] == L'L') {
                            suspicious = TRUE;
                        }
                    }
                    if (suspicious) {
                        EmptyClipboard();
                        Log(L"clipboard hijack blocked");
                        CloudEmitEvent(L"clipboard", L"");
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    RemoveClipboardFormatListener(hwnd);
    DestroyWindow(hwnd);
    return 0;
}

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* k = (KBDLLHOOKSTRUCT*)lParam;
        if (k->flags & LLKHF_INJECTED) {
            return 1;
        }
    }
    return CallNextHookEx(gKeyboardHook, nCode, wParam, lParam);
}

static DWORD WINAPI KeyboardWatcherThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    gKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandleW(NULL), 0);
    if (!gKeyboardHook) return 1;
    while (MsgWaitForMultipleObjects(1, &gEvExit, FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    UnhookWindowsHookEx(gKeyboardHook);
    gKeyboardHook = NULL;
    return 0;
}

static DWORD WINAPI ProcWatchThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    DWORD lastPids[512] = { 0 };
    int lastCount = 0;
    while (WaitForSingleObject(gEvExit, 4000) != WAIT_OBJECT_0) {
        if (!gCfg.enableExtBlock || !gCfg.denyExts[0]) continue;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe = { sizeof(pe) };
        DWORD cur[512];
        int curCount = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID <= 4) continue;
                BOOL seen = FALSE;
                for (int i = 0; i < lastCount; i++) {
                    if (lastPids[i] == pe.th32ProcessID) { seen = TRUE; break; }
                }
                if (curCount < 512) cur[curCount++] = pe.th32ProcessID;
                if (seen) continue;
                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (!hp) continue;
                WCHAR path[MAX_PATH] = { 0 };
                DWORD len = MAX_PATH;
                if (QueryFullProcessImageNameW(hp, 0, path, &len)) {
                    const wchar_t* ext = PathFindExtensionW(path);
                    if (ext && ext[0]) {
                        wchar_t copy[128];
                        StringCchCopyW(copy, ARRAYSIZE(copy), gCfg.denyExts);
                        wchar_t* ctx = NULL;
                        wchar_t* tok = wcstok_s(copy, L";", &ctx);
                        while (tok) {
                            if (_wcsicmp(ext, tok) == 0) {
                                Log(L"usermode blocked %s", path);
                                TerminateProcess(hp, 1);
                                ScanFileWithVT(path);
                                CloudEmitEvent(L"process", path);
                                break;
                            }
                            tok = wcstok_s(NULL, L";", &ctx);
                        }
                    }
                }
                CloseHandle(hp);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        memcpy(lastPids, cur, curCount * sizeof(DWORD));
        lastCount = curCount;
    }
    return 0;
}

static DWORD WINAPI SysmonEventCallback(int action, PVOID ctx, EVT_HANDLE ev)
{
    UNREFERENCED_PARAMETER(ctx);
    if (action != 1 || !g_pfnEvtRender) return 0;
    DWORD need = 0;
    g_pfnEvtRender(NULL, ev, 1, 0, NULL, &need, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;
    LPWSTR buf = (LPWSTR)malloc(need);
    if (!buf) return 0;
    if (g_pfnEvtRender(NULL, ev, 1, need, buf, &need, NULL)) {
        WCHAR* id = wcsstr(buf, L"<EventID>");
        if (id) Log(L"Sysmon event %d", _wtoi(id + 9));
    }
    free(buf);
    return 0;
}

static DWORD WINAPI SysmonWatcherThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    if (!g_pfnEvtSubscribe || !g_pfnEvtClose) return 1;
    EVT_HANDLE sub = g_pfnEvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational", L"*", NULL, NULL,
        (EVT_SUBSCRIBE_CALLBACK)SysmonEventCallback, 1);
    if (!sub) return 1;
    WaitForSingleObject(gEvExit, INFINITE);
    g_pfnEvtClose(sub);
    return 0;
}

static BOOL NtPathToDos(LPCWSTR nt, wchar_t* dos, size_t dosChars)
{
    if (!nt || !dos || dosChars < 4) return FALSE;
    if (wcsncmp(nt, L"\\??\\", 4) == 0) {
        StringCchCopyW(dos, dosChars, nt + 4);
        return TRUE;
    }
    if (wcsncmp(nt, L"\\\\?\\", 4) == 0) {
        StringCchCopyW(dos, dosChars, nt + 4);
        return TRUE;
    }
    StringCchCopyW(dos, dosChars, nt);
    return TRUE;
}

static BOOL EnsureQuarantineDir(wchar_t* out, size_t outChars)
{
    if (!EnsureAppdataPath(out, outChars)) return FALSE;
    PathAppendW(out, L"quarantine");
    if (GetFileAttributesW(out) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(out, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    }
    return TRUE;
}

static BOOL XorCopyFile(LPCWSTR src, LPCWSTR dst)
{
    HANDLE in = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (in == INVALID_HANDLE_VALUE) return FALSE;
    HANDLE out = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        CloseHandle(in);
        return FALSE;
    }
    BYTE buf[8192];
    DWORD rd = 0, wr = 0;
    BOOL ok = TRUE;
    while (ReadFile(in, buf, sizeof(buf), &rd, NULL) && rd) {
        for (DWORD i = 0; i < rd; i++) buf[i] ^= 0x5A;
        if (!WriteFile(out, buf, rd, &wr, NULL) || wr != rd) {
            ok = FALSE;
            break;
        }
    }
    CloseHandle(in);
    CloseHandle(out);
    return ok;
}

static BOOL QuarantineFile(LPCWSTR filePath)
{
    if (!filePath || !filePath[0]) return FALSE;
    wchar_t dos[MAX_PATH];
    if (!NtPathToDos(filePath, dos, MAX_PATH)) return FALSE;
    if (GetFileAttributesW(dos) == INVALID_FILE_ATTRIBUTES) return FALSE;
    wchar_t qdir[MAX_PATH];
    if (!EnsureQuarantineDir(qdir, MAX_PATH)) return FALSE;

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t qname[64];
    StringCchPrintfW(qname, ARRAYSIZE(qname), L"%04d%02d%02d_%02d%02d%02d_%04u.qtn",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetTickCount() & 0xFFFF);
    wchar_t qpath[MAX_PATH], meta[MAX_PATH];
    StringCchCopyW(qpath, MAX_PATH, qdir);
    PathAppendW(qpath, qname);
    StringCchCopyW(meta, MAX_PATH, qpath);
    StringCchCatW(meta, MAX_PATH, L".meta");

    if (!XorCopyFile(dos, qpath)) return FALSE;
    HANDLE mh = CreateFileW(meta, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (mh != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(mh, dos, (DWORD)(wcslen(dos) * sizeof(WCHAR)), &wr, NULL);
        CloseHandle(mh);
    }
    SetFileAttributesW(dos, FILE_ATTRIBUTE_NORMAL);
    if (DeleteFileW(dos)) {
        InterlockedIncrement64((volatile LONGLONG*)&gUserQuarantined);
        Log(L"quarantined %s", dos);
        CloudEmitEvent(L"quarantine", dos);
        return TRUE;
    }
    return FALSE;
}

static void RefreshQuarantineList(void)
{
    if (!gQuarList) return;
    ListView_DeleteAllItems(gQuarList);
    wchar_t qdir[MAX_PATH], search[MAX_PATH];
    if (!EnsureQuarantineDir(qdir, MAX_PATH)) return;
    StringCchCopyW(search, MAX_PATH, qdir);
    PathAppendW(search, L"*.qtn");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t qpath[MAX_PATH], meta[MAX_PATH], orig[MAX_PATH] = L"(unknown)";
        StringCchCopyW(qpath, MAX_PATH, qdir);
        PathAppendW(qpath, fd.cFileName);
        StringCchCopyW(meta, MAX_PATH, qpath);
        StringCchCatW(meta, MAX_PATH, L".meta");
        HANDLE mh = CreateFileW(meta, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (mh != INVALID_HANDLE_VALUE) {
            DWORD rd = 0;
            ReadFile(mh, orig, sizeof(orig) - sizeof(WCHAR), &rd, NULL);
            orig[rd / sizeof(WCHAR)] = 0;
            CloseHandle(mh);
        }
        LVITEMW it = { 0 };
        it.mask = LVIF_TEXT;
        it.iItem = 0;
        it.pszText = fd.cFileName;
        int row = ListView_InsertItem(gQuarList, &it);
        ListView_SetItemText(gQuarList, row, 1, orig);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void RestoreSelectedQuarantine(void)
{
    if (!gQuarList) return;
    int sel = ListView_GetNextItem(gQuarList, -1, LVNI_SELECTED);
    if (sel < 0) return;
    wchar_t name[MAX_PATH], orig[MAX_PATH];
    ListView_GetItemText(gQuarList, sel, 0, name, MAX_PATH);
    ListView_GetItemText(gQuarList, sel, 1, orig, MAX_PATH);
    wchar_t qdir[MAX_PATH], qpath[MAX_PATH], meta[MAX_PATH];
    if (!EnsureQuarantineDir(qdir, MAX_PATH)) return;
    StringCchCopyW(qpath, MAX_PATH, qdir);
    PathAppendW(qpath, name);
    StringCchCopyW(meta, MAX_PATH, qpath);
    StringCchCatW(meta, MAX_PATH, L".meta");
    if (XorCopyFile(qpath, orig)) {
        DeleteFileW(qpath);
        DeleteFileW(meta);
        Log(L"restored quarantine to %s", orig);
        RefreshQuarantineList();
    }
}

static void PurgeSelectedQuarantine(void)
{
    if (!gQuarList) return;
    int sel = ListView_GetNextItem(gQuarList, -1, LVNI_SELECTED);
    if (sel < 0) return;
    wchar_t name[MAX_PATH];
    ListView_GetItemText(gQuarList, sel, 0, name, MAX_PATH);
    wchar_t qdir[MAX_PATH], qpath[MAX_PATH], meta[MAX_PATH];
    if (!EnsureQuarantineDir(qdir, MAX_PATH)) return;
    StringCchCopyW(qpath, MAX_PATH, qdir);
    PathAppendW(qpath, name);
    StringCchCopyW(meta, MAX_PATH, qpath);
    StringCchCatW(meta, MAX_PATH, L".meta");
    DeleteFileW(qpath);
    DeleteFileW(meta);
    Log(L"purged quarantine %s", name);
    RefreshQuarantineList();
}

static BOOL HasInternetZone(LPCWSTR path)
{
    wchar_t ads[MAX_PATH + 32];
    StringCchPrintfW(ads, ARRAYSIZE(ads), L"%s:Zone.Identifier", path);
    HANDLE h = CreateFileW(ads, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    char buf[256] = { 0 };
    DWORD rd = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &rd, NULL);
    CloseHandle(h);
    return strstr(buf, "ZoneId=3") || strstr(buf, "ZoneId=4");
}

static BOOL IsRiskyDownloadExt(LPCWSTR path)
{
    static const wchar_t* exts[] = {
        L".exe", L".dll", L".sys", L".scr", L".pif", L".com", L".bat", L".cmd",
        L".ps1", L".vbs", L".js", L".jse", L".wsf", L".hta", L".msi", L".msp",
        L".lnk", L".iso", L".img", L".jar"
    };
    const wchar_t* ext = PathFindExtensionW(path);
    if (!ext || !ext[0]) return FALSE;
    for (int i = 0; i < ARRAYSIZE(exts); i++) {
        if (_wcsicmp(ext, exts[i]) == 0) return TRUE;
    }
    return FALSE;
}

static void GuardNewDownload(LPCWSTR dir, LPCWSTR file)
{
    wchar_t full[MAX_PATH];
    StringCchCopyW(full, MAX_PATH, dir);
    PathAppendW(full, file);
    if (!IsRiskyDownloadExt(full)) return;
    Log(L"download seen %s", full);
    ScanFileWithVT(full);
    if (HasInternetZone(full) || IsRiskyDownloadExt(full)) {
        if (QuarantineFile(full)) {
            InterlockedIncrement64((volatile LONGLONG*)&gUserDownloadBlocked);
            CloudEmitEvent(L"download", full);
        }
    }
}

static DWORD WINAPI WatchDirThread(LPVOID param)
{
    wchar_t dir[MAX_PATH];
    StringCchCopyW(dir, MAX_PATH, (LPCWSTR)param);
    free(param);
    HANDLE hDir = CreateFileW(dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return 1;
    BYTE buf[4096];
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    while (WaitForSingleObject(gEvExit, 0) != WAIT_OBJECT_0) {
        DWORD got = 0;
        ResetEvent(ov.hEvent);
        if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &got, &ov, NULL)) {
            break;
        }
        HANDLE waiters[2] = { gEvExit, ov.hEvent };
        DWORD w = WaitForMultipleObjects(2, waiters, FALSE, 4000);
        if (w == WAIT_OBJECT_0) break;
        if (w != WAIT_OBJECT_0 + 1) continue;
        if (!GetOverlappedResult(hDir, &ov, &got, FALSE) || got == 0) continue;
        BYTE* p = buf;
        for (;;) {
            FILE_NOTIFY_INFORMATION* n = (FILE_NOTIFY_INFORMATION*)p;
            wchar_t name[MAX_PATH] = { 0 };
            DWORD nchars = n->FileNameLength / sizeof(WCHAR);
            if (nchars >= MAX_PATH) nchars = MAX_PATH - 1;
            memcpy(name, n->FileName, nchars * sizeof(WCHAR));
            if (n->Action == FILE_ACTION_ADDED || n->Action == FILE_ACTION_RENAMED_NEW_NAME || n->Action == FILE_ACTION_MODIFIED) {
                GuardNewDownload(dir, name);
            }
            if (n->NextEntryOffset == 0) break;
            p += n->NextEntryOffset;
        }
    }
    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    return 0;
}

static DWORD WINAPI DownloadGuardThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    wchar_t profile[MAX_PATH], pub[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_CURRENT, profile))) {
        PathAppendW(profile, L"Downloads");
        wchar_t* copy = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
        if (copy) {
            StringCchCopyW(copy, MAX_PATH, profile);
            HANDLE th = CreateThread(NULL, 0, WatchDirThread, copy, 0, NULL);
            if (th) CloseHandle(th); else free(copy);
        }
    }
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DOCUMENTS, NULL, SHGFP_TYPE_CURRENT, pub))) {
        PathRemoveFileSpecW(pub);
        PathAppendW(pub, L"Downloads");
        wchar_t* copy = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
        if (copy) {
            StringCchCopyW(copy, MAX_PATH, pub);
            HANDLE th = CreateThread(NULL, 0, WatchDirThread, copy, 0, NULL);
            if (th) CloseHandle(th); else free(copy);
        }
    }
    WaitForSingleObject(gEvExit, INFINITE);
    return 0;
}

static void PlantCanaries(void)
{
    const int folders[] = { CSIDL_DESKTOPDIRECTORY, CSIDL_PERSONAL, CSIDL_PROFILE };
    const wchar_t* names[] = {
        L"ztg_canary_invoice.docx",
        L"ztg_canary_finance.xlsx",
        L"README_IMPORTANT.ztgcanary"
    };
    BYTE payload[] = { 'Z', 'T', 'G', 'C', 'A', 'N', 'A', 'R', 'Y', 0 };
    for (int f = 0; f < ARRAYSIZE(folders); f++) {
        wchar_t dir[MAX_PATH];
        if (FAILED(SHGetFolderPathW(NULL, folders[f], NULL, SHGFP_TYPE_CURRENT, dir))) continue;
        if (folders[f] == CSIDL_PROFILE) PathAppendW(dir, L"Downloads");
        for (int n = 0; n < ARRAYSIZE(names); n++) {
            wchar_t path[MAX_PATH];
            StringCchCopyW(path, MAX_PATH, dir);
            PathAppendW(path, names[n]);
            HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(h, payload, sizeof(payload), &wr, NULL);
                CloseHandle(h);
            }
        }
    }
    Log(L"canary files planted");
}

static BOOL NameIsCanary(LPCWSTR name)
{
    return name && (wcsstr(name, L"ztg_canary") || wcsstr(name, L".ztgcanary"));
}

static DWORD WINAPI WatchCanaryDir(LPVOID param)
{
    wchar_t dir[MAX_PATH];
    StringCchCopyW(dir, MAX_PATH, (LPCWSTR)param);
    free(param);
    HANDLE hDir = CreateFileW(dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return 1;
    BYTE buf[4096];
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    while (WaitForSingleObject(gEvExit, 0) != WAIT_OBJECT_0) {
        DWORD got = 0;
        ResetEvent(ov.hEvent);
        if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &got, &ov, NULL)) {
            if (WaitForSingleObject(gEvExit, 1000) == WAIT_OBJECT_0) break;
            continue;
        }
        HANDLE waiters[2] = { gEvExit, ov.hEvent };
        DWORD w = WaitForMultipleObjects(2, waiters, FALSE, 4000);
        if (w == WAIT_OBJECT_0) break;
        if (w != WAIT_OBJECT_0 + 1) continue;
        if (!GetOverlappedResult(hDir, &ov, &got, FALSE) || got == 0) continue;
        BYTE* p = buf;
        for (;;) {
            FILE_NOTIFY_INFORMATION* n = (FILE_NOTIFY_INFORMATION*)p;
            wchar_t name[MAX_PATH] = { 0 };
            DWORD nchars = n->FileNameLength / sizeof(WCHAR);
            if (nchars >= MAX_PATH) nchars = MAX_PATH - 1;
            memcpy(name, n->FileName, nchars * sizeof(WCHAR));
            if (NameIsCanary(name) && n->Action != FILE_ACTION_ADDED) {
                Log(L"canary touched: %s\\%s", dir, name);
                CloudEmitEvent(L"ransom", name);
                if (gCfg.enableNotify) {
                    gTray.uFlags = NIF_INFO;
                    StringCchCopyW(gTray.szInfoTitle, ARRAYSIZE(gTray.szInfoTitle), L"ZeroTrustGuard");
                    StringCchCopyW(gTray.szInfo, ARRAYSIZE(gTray.szInfo), L"勒索诱饵被触碰，已告警");
                    Shell_NotifyIconW(NIM_MODIFY, &gTray);
                }
            }
            if (n->NextEntryOffset == 0) break;
            p += n->NextEntryOffset;
        }
    }
    if (ov.hEvent) CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    return 0;
}

static DWORD WINAPI CanaryThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    PlantCanaries();
    const int folders[] = { CSIDL_DESKTOPDIRECTORY, CSIDL_PERSONAL, CSIDL_PROFILE };
    for (int i = 0; i < ARRAYSIZE(folders); i++) {
        wchar_t dir[MAX_PATH];
        if (FAILED(SHGetFolderPathW(NULL, folders[i], NULL, SHGFP_TYPE_CURRENT, dir))) continue;
        if (folders[i] == CSIDL_PROFILE) PathAppendW(dir, L"Downloads");
        wchar_t* copy = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
        if (!copy) continue;
        StringCchCopyW(copy, MAX_PATH, dir);
        HANDLE th = CreateThread(NULL, 0, WatchCanaryDir, copy, 0, NULL);
        if (th) CloseHandle(th); else free(copy);
    }
    WaitForSingleObject(gEvExit, INFINITE);
    return 0;
}

static void HuntOneKey(HKEY root, LPCWSTR sub, LPCWSTR label)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    DWORD index = 0;
    wchar_t name[256], data[1024];
    for (;;) {
        DWORD nlen = ARRAYSIZE(name), dlen = sizeof(data), type = 0;
        LONG rc = RegEnumValueW(k, index++, name, &nlen, NULL, &type, (LPBYTE)data, &dlen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            Log(L"persist %s %s=%s", label, name, data);
            InterlockedIncrement64((volatile LONGLONG*)&gUserPersistFound);
            CloudEmitEvent(L"persist-hunt", data);
        }
    }
    RegCloseKey(k);
}

static void HuntIfeo(void)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_READ, &k) != ERROR_SUCCESS) return;
    DWORD index = 0;
    wchar_t sub[256];
    for (;;) {
        DWORD nlen = ARRAYSIZE(sub);
        LONG rc = RegEnumKeyExW(k, index++, sub, &nlen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        wchar_t path[512];
        StringCchPrintfW(path, ARRAYSIZE(path),
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", sub);
        HuntOneKey(HKEY_LOCAL_MACHINE, path, L"IFEO");
    }
    RegCloseKey(k);
}

static void HuntStartupFolder(int csidl, LPCWSTR label)
{
    wchar_t startup[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, startup))) return;
    wchar_t search[MAX_PATH];
    StringCchCopyW(search, MAX_PATH, startup);
    PathAppendW(search, L"*.*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.') continue;
        Log(L"persist %s %s", label, fd.cFileName);
        InterlockedIncrement64((volatile LONGLONG*)&gUserPersistFound);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void HuntPersistence(void)
{
    gUserPersistFound = 0;
    HuntOneKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM Run");
    HuntOneKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU Run");
    HuntOneKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM RunOnce");
    HuntOneKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Winlogon");
    HuntOneKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit");
    HuntIfeo();
    HuntStartupFolder(CSIDL_STARTUP, L"Startup");
    HuntStartupFolder(CSIDL_COMMON_STARTUP, L"CommonStartup");
    Log(L"persist hunt complete, hits=%llu", gUserPersistFound);
}

static DWORD WINAPI PersistHuntThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    while (WaitForSingleObject(gEvExit, 180000) != WAIT_OBJECT_0) {
        if (gCfg.enablePersistProtect) HuntPersistence();
    }
    return 0;
}

static DWORD WINAPI EventPumpThread(LPVOID lp)
{
    UNREFERENCED_PARAMETER(lp);
    while (WaitForSingleObject(gEvExit, 800) != WAIT_OBJECT_0) {
        if (gDrv == INVALID_HANDLE_VALUE) continue;
        ZTG_EVENT ev[ZTG_MAX_EVENTS_OUT];
        DWORD ret = 0;
        if (!DeviceIoControl(gDrv, IOCTL_ZTG_GET_EVENTS, NULL, 0, ev, sizeof(ev), &ret, NULL) || ret < sizeof(ZTG_EVENT)) {
            continue;
        }
        ULONG n = ret / sizeof(ZTG_EVENT);
        for (ULONG i = 0; i < n; i++) {
            const wchar_t* kind = L"event";
            if (ev[i].type == ZTG_EVENT_PROCESS) kind = L"process";
            else if (ev[i].type == ZTG_EVENT_IMAGE) kind = L"image";
            else if (ev[i].type == ZTG_EVENT_REGISTRY) kind = L"registry";
            else if (ev[i].type == ZTG_EVENT_LOLBIN) kind = L"lolbin";
            else if (ev[i].type == ZTG_EVENT_BEHAVIOR) kind = L"behavior";
            else if (ev[i].type == ZTG_EVENT_LSASS) kind = L"lsass";
            else if (ev[i].type == ZTG_EVENT_PERSIST) kind = L"persist";
            else if (ev[i].type == ZTG_EVENT_RANSOM) kind = L"ransom";
            Log(L"kernel %s pid=%u: %s", kind, ev[i].pid, ev[i].path);
            if (ev[i].type == ZTG_EVENT_PROCESS || ev[i].type == ZTG_EVENT_IMAGE ||
                ev[i].type == ZTG_EVENT_LOLBIN || ev[i].type == ZTG_EVENT_BEHAVIOR ||
                ev[i].type == ZTG_EVENT_RANSOM) {
                ScanFileWithVT(ev[i].path);
                QuarantineFile(ev[i].path);
            }
            CloudEmitEvent(kind, ev[i].path);
            if (gMain) {
                ZTG_EVENT* copy = (ZTG_EVENT*)malloc(sizeof(ZTG_EVENT));
                if (copy) {
                    *copy = ev[i];
                    if (!PostMessageW(gMain, WM_ZTG_EVT, 0, (LPARAM)copy)) free(copy);
                }
            }
        }
    }
    return 0;
}

static BOOL WriteRegDword(HKEY root, const wchar_t* sub, const wchar_t* name, DWORD data)
{
    HKEY k = NULL;
    if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS) return FALSE;
    BOOL ok = RegSetValueExW(k, name, 0, REG_DWORD, (BYTE*)&data, sizeof(data)) == ERROR_SUCCESS;
    RegCloseKey(k);
    return ok;
}

static BOOL DeleteRegValue(HKEY root, const wchar_t* sub, const wchar_t* name)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return TRUE;
    RegDeleteValueW(k, name);
    RegCloseKey(k);
    return TRUE;
}

static BOOL RunSysCmdSafe(const wchar_t* cmd)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t buf[CMD_BUFFER_SIZE];
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (wcslen(cmd) >= CMD_BUFFER_SIZE) return FALSE;
    StringCchCopyW(buf, ARRAYSIZE(buf), cmd);
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return FALSE;
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

static void ApplyPortFilterRules(void)
{
    HANDLE engine = NULL;
    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine) != ERROR_SUCCESS) return;
    FWPM_FILTER_ENUM_TEMPLATE0 tmpl = { 0 };
    tmpl.providerKey = (GUID*)&ZTG_WFP_PROVIDER_GUID;
    HANDLE eh = NULL;
    if (FwpmFilterCreateEnumHandle0(engine, &tmpl, &eh) == ERROR_SUCCESS) {
        FWPM_FILTER0** filters = NULL;
        UINT32 n = 0;
        if (FwpmFilterEnum0(engine, eh, 0xFFFFFFFF, &filters, &n) == ERROR_SUCCESS && n) {
            for (UINT32 i = 0; i < n; i++) {
                if (filters[i]) FwpmFilterDeleteByKey0(engine, &filters[i]->filterKey);
            }
            FwpmFreeMemory0((void**)&filters);
        }
        FwpmFilterDestroyEnumHandle0(engine, eh);
    }
    if (FwpmTransactionBegin0(engine, 0) != ERROR_SUCCESS) {
        FwpmEngineClose0(engine);
        return;
    }
    if (gCfg.blackPorts[0]) {
        wchar_t copy[ARRAYSIZE(gCfg.blackPorts)];
        StringCchCopyW(copy, ARRAYSIZE(copy), gCfg.blackPorts);
        wchar_t* ctx = NULL;
        wchar_t* tok = wcstok_s(copy, L";,", &ctx);
        while (tok) {
            UINT16 port = (UINT16)_wtoi(tok);
            if (port) {
                FWPM_FILTER0 f = { 0 };
                FWPM_FILTER_CONDITION0 c[2] = { 0 };
                f.displayData.name = L"ZeroTrustGuard Port Block";
                f.action.type = FWP_ACTION_BLOCK;
                f.providerKey = (GUID*)&ZTG_WFP_PROVIDER_GUID;
                f.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
                f.weight.type = FWP_UINT8;
                f.weight.uint8 = 0xF;
                f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                c[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                c[0].matchType = FWP_MATCH_EQUAL;
                c[0].conditionValue.type = FWP_UINT8;
                c[0].conditionValue.uint8 = IPPROTO_TCP;
                c[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                c[1].matchType = FWP_MATCH_EQUAL;
                c[1].conditionValue.type = FWP_UINT16;
                c[1].conditionValue.uint16 = port;
                f.filterCondition = c;
                f.numFilterConditions = 2;
                FwpmFilterAdd0(engine, &f, NULL, NULL);
                c[0].conditionValue.uint8 = IPPROTO_UDP;
                FwpmFilterAdd0(engine, &f, NULL, NULL);
            }
            tok = wcstok_s(NULL, L";,", &ctx);
        }
    }
    if (FwpmTransactionCommit0(engine) != ERROR_SUCCESS) FwpmTransactionAbort0(engine);
    FwpmEngineClose0(engine);
}

static void ApplySystemHardening(void)
{
    if (gCfg.disableSMB1) WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1", 0);
    else DeleteRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1");
    if (gCfg.disableNTLM) WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel", 5);
    else DeleteRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel");
    if (gCfg.forceDoH) WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh", 2);
    else DeleteRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh");
    if (gCfg.enableSpectreMitigation) {
        WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"FeatureSettingsOverride", 3);
        WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"FeatureSettingsOverrideMask", 3);
    } else {
        DeleteRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"FeatureSettingsOverride");
        DeleteRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"FeatureSettingsOverrideMask");
    }
    WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VSS", L"Start", gCfg.disableVSS ? 4 : 3);
    WriteRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bthserv", L"Start", gCfg.disableBTIR ? 4 : 3);
    if (gCfg.disableCamMic) {
        WriteRegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", L"LetAppsAccessCamera", 2);
        WriteRegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", L"LetAppsAccessMicrophone", 2);
    } else {
        DeleteRegValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", L"LetAppsAccessCamera");
        DeleteRegValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", L"LetAppsAccessMicrophone");
    }
    if (gCfg.lockBiosUpdate) WriteRegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"ExcludeWUDriversInQualityUpdate", 1);
    else DeleteRegValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"ExcludeWUDriversInQualityUpdate");
    if (gCfg.blockHIDKeylog) WriteRegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions", L"DenyUnspecified", 1);
    else DeleteRegValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions", L"DenyUnspecified");
    if (gCfg.enableWDAC) {
        wchar_t policy[MAX_PATH], citool[MAX_PATH], sys[MAX_PATH];
        GetModuleFileNameW(NULL, policy, MAX_PATH);
        PathRemoveFileSpecW(policy);
        PathAppendW(policy, L"WDAC_policy.bin");
        GetSystemDirectoryW(sys, MAX_PATH);
        StringCchPrintfW(citool, MAX_PATH, L"%s\\CiTool.exe", sys);
        if (GetFileAttributesW(policy) != INVALID_FILE_ATTRIBUTES && GetFileAttributesW(citool) != INVALID_FILE_ATTRIBUTES) {
            wchar_t cmd[MAX_PATH * 2];
            StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%s\" -p --file \"%s\"", citool, policy);
            RunSysCmdSafe(cmd);
        }
    }
}

static void CleanupOldLogs(void)
{
    if (!gCfg.logCleanupEnabled || gCfg.logRetainDays <= 0) return;
    wchar_t search[MAX_PATH];
    StringCchPrintfW(search, MAX_PATH, L"%s\\ZeroTrust_*.log", gCfg.logPath);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now;
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    do {
        ULARGE_INTEGER file;
        file.LowPart = fd.ftLastWriteTime.dwLowDateTime;
        file.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        ULONGLONG days = (now.QuadPart - file.QuadPart) / (10000000ULL * 3600 * 24);
        if (days > (ULONGLONG)gCfg.logRetainDays) {
            wchar_t full[MAX_PATH];
            StringCchPrintfW(full, MAX_PATH, L"%s\\%s", gCfg.logPath, fd.cFileName);
            DeleteFileW(full);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static BOOL InitEvtApi(void)
{
    HMODULE m = LoadLibraryW(L"wevtapi.dll");
    if (!m) return FALSE;
    g_pfnEvtSubscribe = (PFN_EVT_SUBSCRIBE)GetProcAddress(m, "EvtSubscribe");
    g_pfnEvtClose = (PFN_EVT_CLOSE)GetProcAddress(m, "EvtClose");
    g_pfnEvtRender = (PFN_EVT_RENDER)GetProcAddress(m, "EvtRender");
    return g_pfnEvtSubscribe && g_pfnEvtClose && g_pfnEvtRender;
}

static void StartMonitorThreads(void)
{
    if (gCfg.blockClipboardHijack) gClipboardWatcherThread = CreateThread(NULL, 0, ClipboardWatcherThread, NULL, 0, NULL);
    if (gCfg.blockKeyboardRecord) gKeyboardWatcherThread = CreateThread(NULL, 0, KeyboardWatcherThread, NULL, 0, NULL);
    if (gCfg.enableSysmonWatcher && g_pfnEvtSubscribe) gSysmonWatcherThread = CreateThread(NULL, 0, SysmonWatcherThread, NULL, 0, NULL);
    gProcWatchThread = CreateThread(NULL, 0, ProcWatchThread, NULL, 0, NULL);
    gEventPumpThread = CreateThread(NULL, 0, EventPumpThread, NULL, 0, NULL);
    if (gCfg.enableDownloadGuard) gDownloadGuardThread = CreateThread(NULL, 0, DownloadGuardThread, NULL, 0, NULL);
    if (gCfg.enableCanaryProtect) gCanaryThread = CreateThread(NULL, 0, CanaryThread, NULL, 0, NULL);
    if (gCfg.enablePersistProtect) gPersistHuntThread = CreateThread(NULL, 0, PersistHuntThread, NULL, 0, NULL);
}

static void StopMonitorThreads(void)
{
    SetEvent(gEvExit);
    HANDLE th[] = {
        gClipboardWatcherThread, gKeyboardWatcherThread, gSysmonWatcherThread,
        gProcWatchThread, gEventPumpThread, gDownloadGuardThread, gCanaryThread, gPersistHuntThread
    };
    for (int i = 0; i < ARRAYSIZE(th); i++) {
        if (th[i]) {
            WaitForSingleObject(th[i], 1500);
            CloseHandle(th[i]);
        }
    }
}

static HWND MakeEdit(HWND parent, int id, int x, int y, int w, int h, BOOL pass)
{
    DWORD style = WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER;
    if (pass) style |= ES_PASSWORD;
    HWND e = CreateWindowExW(0, L"EDIT", L"", style, x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(e, WM_SETFONT, (WPARAM)gFontUi, TRUE);
    return e;
}

static HWND MakeCheck(HWND parent, int id, const wchar_t* text, int x, int y, int w)
{
    HWND c = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x, y, w, 22, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)gFontUi, TRUE);
    return c;
}

static HWND MakeBtn(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h)
{
    HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(b, WM_SETFONT, (WPARAM)gFontUi, TRUE);
    return b;
}

static void HideSettings(HWND h)
{
    for (int i = 0; i < ARRAYSIZE(gEdits); i++) if (gEdits[i]) ShowWindow(gEdits[i], SW_HIDE);
    for (int i = 0; i < ARRAYSIZE(gChecks); i++) if (gChecks[i]) ShowWindow(gChecks[i], SW_HIDE);
    if (gEvtList) ShowWindow(gEvtList, SW_HIDE);
    if (gLogView) ShowWindow(gLogView, SW_HIDE);
    if (gQuarList) ShowWindow(gQuarList, SW_HIDE);
    HWND extra[] = {
        GetDlgItem(h, IDC_BROWSE_LOG), GetDlgItem(h, IDC_TEST_CLOUD), GetDlgItem(h, IDC_TEST_VT),
        GetDlgItem(h, IDC_HUNT), GetDlgItem(h, IDC_QUAR_RESTORE), GetDlgItem(h, IDC_QUAR_PURGE),
        GetDlgItem(h, IDC_SCAN_FILE), GetDlgItem(h, IDC_CANARY_PLANT)
    };
    for (int i = 0; i < ARRAYSIZE(extra); i++) if (extra[i]) ShowWindow(extra[i], SW_HIDE);
}

static void LayoutPage(HWND h)
{
    HideSettings(h);
    int x = 236, y = 88;
    switch (gNav) {
    case 0:
        if (gEvtList) SetWindowPos(gEvtList, NULL, x, 268, 820, 372, SWP_NOZORDER | SWP_SHOWWINDOW);
        {
            HWND b = GetDlgItem(h, IDC_SCAN_FILE);
            if (b) SetWindowPos(b, NULL, x + 680, 236, 140, 28, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        break;
    case 1:
        if (gEdits[0]) { SetWindowPos(gEdits[0], NULL, x, y + 24, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[1]) { SetWindowPos(gEdits[1], NULL, x, y + 84, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[2]) { SetWindowPos(gEdits[2], NULL, x, y + 144, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[3]) { SetWindowPos(gEdits[3], NULL, x, y + 204, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        break;
    case 2:
        if (gEdits[4]) { SetWindowPos(gEdits[4], NULL, x, y + 24, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[5]) { SetWindowPos(gEdits[5], NULL, x, y + 84, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        break;
    case 3:
        if (gEdits[6]) { SetWindowPos(gEdits[6], NULL, x, y + 24, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gChecks[0]) { SetWindowPos(gChecks[0], NULL, x, y + 70, 400, 22, SWP_NOZORDER | SWP_SHOWWINDOW); }
        break;
    case 4:
        if (gEdits[7]) { SetWindowPos(gEdits[7], NULL, x, y + 24, 520, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[8]) { SetWindowPos(gEdits[8], NULL, x, y + 84, 800, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[9]) { SetWindowPos(gEdits[9], NULL, x, y + 144, 260, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gChecks[1]) { SetWindowPos(gChecks[1], NULL, x, y + 190, 280, 22, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gChecks[2]) { SetWindowPos(gChecks[2], NULL, x + 300, y + 190, 280, 22, SWP_NOZORDER | SWP_SHOWWINDOW); }
        {
            HWND b2 = GetDlgItem(h, IDC_TEST_CLOUD);
            HWND b3 = GetDlgItem(h, IDC_TEST_VT);
            if (b2) SetWindowPos(b2, NULL, x, y + 230, 140, 32, SWP_NOZORDER | SWP_SHOWWINDOW);
            if (b3) SetWindowPos(b3, NULL, x + 160, y + 230, 160, 32, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        break;
    case 5:
        if (gChecks[3]) { SetWindowPos(gChecks[3], NULL, x, y + 24, 360, 22, SWP_NOZORDER | SWP_SHOWWINDOW); }
        break;
    case 6:
        for (int i = 4; i <= 20; i++) {
            if (gChecks[i]) {
                int col = (i - 4) / 9;
                int row = (i - 4) % 9;
                SetWindowPos(gChecks[i], NULL, x + col * 400, y + row * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
        }
        if (gChecks[22]) SetWindowPos(gChecks[22], NULL, x + 400, y + 8 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[23]) SetWindowPos(gChecks[23], NULL, x, y + 9 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[24]) SetWindowPos(gChecks[24], NULL, x + 400, y + 9 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[25]) SetWindowPos(gChecks[25], NULL, x, y + 10 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[26]) SetWindowPos(gChecks[26], NULL, x + 400, y + 10 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[27]) SetWindowPos(gChecks[27], NULL, x, y + 11 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[28]) SetWindowPos(gChecks[28], NULL, x + 400, y + 11 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[29]) SetWindowPos(gChecks[29], NULL, x, y + 12 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[30]) SetWindowPos(gChecks[30], NULL, x + 400, y + 12 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        if (gChecks[31]) SetWindowPos(gChecks[31], NULL, x, y + 13 * 28, 380, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
        break;
    case 7:
        if (gEdits[10]) { SetWindowPos(gEdits[10], NULL, x, y + 24, 660, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[11]) { SetWindowPos(gEdits[11], NULL, x, y + 84, 80, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[12]) { SetWindowPos(gEdits[12], NULL, x + 200, y + 84, 80, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gEdits[13]) { SetWindowPos(gEdits[13], NULL, x + 400, y + 84, 80, 26, SWP_NOZORDER | SWP_SHOWWINDOW); }
        if (gChecks[21]) { SetWindowPos(gChecks[21], NULL, x, y + 126, 240, 22, SWP_NOZORDER | SWP_SHOWWINDOW); }
        {
            HWND b1 = GetDlgItem(h, IDC_BROWSE_LOG);
            if (b1) SetWindowPos(b1, NULL, x + 680, y + 22, 90, 28, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        if (gLogView) SetWindowPos(gLogView, NULL, x, y + 170, 820, 430, SWP_NOZORDER | SWP_SHOWWINDOW);
        break;
    case 8:
        if (gQuarList) SetWindowPos(gQuarList, NULL, x, y + 50, 820, 430, SWP_NOZORDER | SWP_SHOWWINDOW);
        {
            HWND r = GetDlgItem(h, IDC_QUAR_RESTORE);
            HWND p = GetDlgItem(h, IDC_QUAR_PURGE);
            if (r) SetWindowPos(r, NULL, x, y + 8, 120, 30, SWP_NOZORDER | SWP_SHOWWINDOW);
            if (p) SetWindowPos(p, NULL, x + 136, y + 8, 120, 30, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        RefreshQuarantineList();
        break;
    case 9:
        {
            HWND hunt = GetDlgItem(h, IDC_HUNT);
            HWND can = GetDlgItem(h, IDC_CANARY_PLANT);
            if (hunt) SetWindowPos(hunt, NULL, x, y + 8, 160, 32, SWP_NOZORDER | SWP_SHOWWINDOW);
            if (can) SetWindowPos(can, NULL, x + 176, y + 8, 160, 32, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        if (gLogView) SetWindowPos(gLogView, NULL, x, y + 56, 820, 540, SWP_NOZORDER | SWP_SHOWWINDOW);
        break;
    }
    InvalidateRect(h, NULL, TRUE);
}

static void CollectFromUi(HWND h)
{
    UNREFERENCED_PARAMETER(h);
    if (gEdits[0]) GetWindowTextW(gEdits[0], gCfg.whiteDirs, ARRAYSIZE(gCfg.whiteDirs));
    if (gEdits[1]) GetWindowTextW(gEdits[1], gCfg.blackDirs, ARRAYSIZE(gCfg.blackDirs));
    if (gEdits[2]) GetWindowTextW(gEdits[2], gCfg.denyExts, ARRAYSIZE(gCfg.denyExts));
    if (gEdits[3]) GetWindowTextW(gEdits[3], gCfg.regStartupWhite, ARRAYSIZE(gCfg.regStartupWhite));
    if (gEdits[4]) GetWindowTextW(gEdits[4], gCfg.whitePorts, ARRAYSIZE(gCfg.whitePorts));
    if (gEdits[5]) GetWindowTextW(gEdits[5], gCfg.blackPorts, ARRAYSIZE(gCfg.blackPorts));
    if (gEdits[6]) GetWindowTextW(gEdits[6], gCfg.usbWhitelist, ARRAYSIZE(gCfg.usbWhitelist));
    if (gEdits[7]) GetWindowTextA(gEdits[7], gCfg.vtApiKey, ARRAYSIZE(gCfg.vtApiKey));
    if (gEdits[8]) GetWindowTextW(gEdits[8], gCfg.webhookUrl, ARRAYSIZE(gCfg.webhookUrl));
    if (gEdits[9]) GetWindowTextW(gEdits[9], gCfg.tenantId, ARRAYSIZE(gCfg.tenantId));
    if (gEdits[10]) GetWindowTextW(gEdits[10], gCfg.logPath, ARRAYSIZE(gCfg.logPath));
    if (gEdits[11]) gCfg.logLevel = GetDlgItemInt(gMain, GetDlgCtrlID(gEdits[11]), NULL, FALSE);
    if (gEdits[12]) gCfg.logRetainDays = GetDlgItemInt(gMain, GetDlgCtrlID(gEdits[12]), NULL, FALSE);
    if (gEdits[13]) gCfg.logMaxMB = GetDlgItemInt(gMain, GetDlgCtrlID(gEdits[13]), NULL, FALSE);
    if (gChecks[0]) gCfg.blockUsbExec = Button_GetCheck(gChecks[0]) == BST_CHECKED;
    if (gChecks[1]) gCfg.vtEnabled = Button_GetCheck(gChecks[1]) == BST_CHECKED;
    if (gChecks[2]) gCfg.cloudEnabled = Button_GetCheck(gChecks[2]) == BST_CHECKED;
    if (gChecks[3]) gCfg.enableTOTP = Button_GetCheck(gChecks[3]) == BST_CHECKED;
    if (gChecks[4]) gCfg.enableNotify = Button_GetCheck(gChecks[4]) == BST_CHECKED;
    if (gChecks[5]) gCfg.enableSound = Button_GetCheck(gChecks[5]) == BST_CHECKED;
    if (gChecks[6]) gCfg.enableHighRiskPrompts = Button_GetCheck(gChecks[6]) == BST_CHECKED;
    if (gChecks[7]) gCfg.enableSysmonWatcher = Button_GetCheck(gChecks[7]) == BST_CHECKED;
    if (gChecks[8]) gCfg.enableWDAC = Button_GetCheck(gChecks[8]) == BST_CHECKED;
    if (gChecks[9]) gCfg.blockDLLHijack = Button_GetCheck(gChecks[9]) == BST_CHECKED;
    if (gChecks[10]) gCfg.blockClipboardHijack = Button_GetCheck(gChecks[10]) == BST_CHECKED;
    if (gChecks[11]) gCfg.blockKeyboardRecord = Button_GetCheck(gChecks[11]) == BST_CHECKED;
    if (gChecks[12]) gCfg.disableNTLM = Button_GetCheck(gChecks[12]) == BST_CHECKED;
    if (gChecks[13]) gCfg.disableSMB1 = Button_GetCheck(gChecks[13]) == BST_CHECKED;
    if (gChecks[14]) gCfg.forceDoH = Button_GetCheck(gChecks[14]) == BST_CHECKED;
    if (gChecks[15]) gCfg.disableBTIR = Button_GetCheck(gChecks[15]) == BST_CHECKED;
    if (gChecks[16]) gCfg.disablePromisc = Button_GetCheck(gChecks[16]) == BST_CHECKED;
    if (gChecks[17]) gCfg.disableCamMic = Button_GetCheck(gChecks[17]) == BST_CHECKED;
    if (gChecks[18]) gCfg.disableVSS = Button_GetCheck(gChecks[18]) == BST_CHECKED;
    if (gChecks[19]) gCfg.lockBiosUpdate = Button_GetCheck(gChecks[19]) == BST_CHECKED;
    if (gChecks[20]) gCfg.blockHIDKeylog = Button_GetCheck(gChecks[20]) == BST_CHECKED;
    if (gChecks[21]) gCfg.logCleanupEnabled = Button_GetCheck(gChecks[21]) == BST_CHECKED;
    if (gChecks[22]) gCfg.enableSpectreMitigation = Button_GetCheck(gChecks[22]) == BST_CHECKED;
    if (gChecks[23]) gCfg.enableExtBlock = Button_GetCheck(gChecks[23]) == BST_CHECKED;
    if (gChecks[24]) gCfg.enableLolBins = Button_GetCheck(gChecks[24]) == BST_CHECKED;
    if (gChecks[25]) gCfg.enableBehavior = Button_GetCheck(gChecks[25]) == BST_CHECKED;
    if (gChecks[26]) gCfg.enableLsassProtect = Button_GetCheck(gChecks[26]) == BST_CHECKED;
    if (gChecks[27]) gCfg.enablePersistProtect = Button_GetCheck(gChecks[27]) == BST_CHECKED;
    if (gChecks[28]) gCfg.blockRansomTools = Button_GetCheck(gChecks[28]) == BST_CHECKED;
    if (gChecks[29]) gCfg.enableUntrustedPath = Button_GetCheck(gChecks[29]) == BST_CHECKED;
    if (gChecks[30]) gCfg.enableCanaryProtect = Button_GetCheck(gChecks[30]) == BST_CHECKED;
    if (gChecks[31]) gCfg.enableDownloadGuard = Button_GetCheck(gChecks[31]) == BST_CHECKED;
}

static void PushToUi(void)
{
    if (gEdits[0]) SetWindowTextW(gEdits[0], gCfg.whiteDirs);
    if (gEdits[1]) SetWindowTextW(gEdits[1], gCfg.blackDirs);
    if (gEdits[2]) SetWindowTextW(gEdits[2], gCfg.denyExts);
    if (gEdits[3]) SetWindowTextW(gEdits[3], gCfg.regStartupWhite);
    if (gEdits[4]) SetWindowTextW(gEdits[4], gCfg.whitePorts);
    if (gEdits[5]) SetWindowTextW(gEdits[5], gCfg.blackPorts);
    if (gEdits[6]) SetWindowTextW(gEdits[6], gCfg.usbWhitelist);
    if (gEdits[7]) SetWindowTextA(gEdits[7], gCfg.vtApiKey);
    if (gEdits[8]) SetWindowTextW(gEdits[8], gCfg.webhookUrl);
    if (gEdits[9]) SetWindowTextW(gEdits[9], gCfg.tenantId);
    if (gEdits[10]) SetWindowTextW(gEdits[10], gCfg.logPath);
    if (gEdits[11]) SetWindowTextW(gEdits[11], L"");
    wchar_t tmp[32];
    if (gEdits[11]) { StringCchPrintfW(tmp, 32, L"%d", gCfg.logLevel); SetWindowTextW(gEdits[11], tmp); }
    if (gEdits[12]) { StringCchPrintfW(tmp, 32, L"%d", gCfg.logRetainDays); SetWindowTextW(gEdits[12], tmp); }
    if (gEdits[13]) { StringCchPrintfW(tmp, 32, L"%d", gCfg.logMaxMB); SetWindowTextW(gEdits[13], tmp); }
    if (gChecks[0]) Button_SetCheck(gChecks[0], gCfg.blockUsbExec);
    if (gChecks[1]) Button_SetCheck(gChecks[1], gCfg.vtEnabled);
    if (gChecks[2]) Button_SetCheck(gChecks[2], gCfg.cloudEnabled);
    if (gChecks[3]) Button_SetCheck(gChecks[3], gCfg.enableTOTP);
    if (gChecks[4]) Button_SetCheck(gChecks[4], gCfg.enableNotify);
    if (gChecks[5]) Button_SetCheck(gChecks[5], gCfg.enableSound);
    if (gChecks[6]) Button_SetCheck(gChecks[6], gCfg.enableHighRiskPrompts);
    if (gChecks[7]) Button_SetCheck(gChecks[7], gCfg.enableSysmonWatcher);
    if (gChecks[8]) Button_SetCheck(gChecks[8], gCfg.enableWDAC);
    if (gChecks[9]) Button_SetCheck(gChecks[9], gCfg.blockDLLHijack);
    if (gChecks[10]) Button_SetCheck(gChecks[10], gCfg.blockClipboardHijack);
    if (gChecks[11]) Button_SetCheck(gChecks[11], gCfg.blockKeyboardRecord);
    if (gChecks[12]) Button_SetCheck(gChecks[12], gCfg.disableNTLM);
    if (gChecks[13]) Button_SetCheck(gChecks[13], gCfg.disableSMB1);
    if (gChecks[14]) Button_SetCheck(gChecks[14], gCfg.forceDoH);
    if (gChecks[15]) Button_SetCheck(gChecks[15], gCfg.disableBTIR);
    if (gChecks[16]) Button_SetCheck(gChecks[16], gCfg.disablePromisc);
    if (gChecks[17]) Button_SetCheck(gChecks[17], gCfg.disableCamMic);
    if (gChecks[18]) Button_SetCheck(gChecks[18], gCfg.disableVSS);
    if (gChecks[19]) Button_SetCheck(gChecks[19], gCfg.lockBiosUpdate);
    if (gChecks[20]) Button_SetCheck(gChecks[20], gCfg.blockHIDKeylog);
    if (gChecks[21]) Button_SetCheck(gChecks[21], gCfg.logCleanupEnabled);
    if (gChecks[22]) Button_SetCheck(gChecks[22], gCfg.enableSpectreMitigation);
    if (gChecks[23]) Button_SetCheck(gChecks[23], gCfg.enableExtBlock);
    if (gChecks[24]) Button_SetCheck(gChecks[24], gCfg.enableLolBins);
    if (gChecks[25]) Button_SetCheck(gChecks[25], gCfg.enableBehavior);
    if (gChecks[26]) Button_SetCheck(gChecks[26], gCfg.enableLsassProtect);
    if (gChecks[27]) Button_SetCheck(gChecks[27], gCfg.enablePersistProtect);
    if (gChecks[28]) Button_SetCheck(gChecks[28], gCfg.blockRansomTools);
    if (gChecks[29]) Button_SetCheck(gChecks[29], gCfg.enableUntrustedPath);
    if (gChecks[30]) Button_SetCheck(gChecks[30], gCfg.enableCanaryProtect);
    if (gChecks[31]) Button_SetCheck(gChecks[31], gCfg.enableDownloadGuard);
}

static BOOL GuardSettings(HWND h)
{
    if (!gCfg.enableTOTP) return TRUE;
    if (gCfg.totpSecret[0] == 0) {
        BCRYPT_ALG_HANDLE rng = NULL;
        if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
            BCryptGenRandom(rng, gCfg.totpSecret, KEY_BYTES, 0);
            BCryptCloseAlgorithmProvider(rng, 0);
            SaveCfg();
            wchar_t code[8], msg[256];
            GetTOTP(code, 8);
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"新 TOTP 已生成。当前验证码: %s\n请立即写入验证器，此提示只出现一次。", code);
            MessageBoxW(h, msg, L"启用 TOTP", MB_ICONINFORMATION);
        }
    }
    return DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_TOTP_PROMPT), h, TotpPromptDlgProc, 0) == IDOK;
}

static void DrawRoundCard(HDC hdc, RECT r, HBRUSH br)
{
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(48, 54, 61));
    HGDIOBJ oldP = SelectObject(hdc, pen);
    HGDIOBJ oldB = SelectObject(hdc, br);
    RoundRect(hdc, r.left, r.top, r.right, r.bottom, 10, 10);
    SelectObject(hdc, oldB);
    SelectObject(hdc, oldP);
    DeleteObject(pen);
}

static void PaintMain(HWND h, HDC hdc)
{
    RECT rc;
    GetClientRect(h, &rc);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
    HGDIOBJ old = SelectObject(mem, bmp);
    FillRect(mem, &rc, gBrBg);
    RECT side = { 0, 0, 208, rc.bottom };
    FillRect(mem, &side, gBrSide);
    SetBkMode(mem, TRANSPARENT);
    SelectObject(mem, gFontTitle);
    SetTextColor(mem, gColText);
    TextOutW(mem, 18, 18, L"ZeroTrust", 9);
    SelectObject(mem, gFontSmall);
    SetTextColor(mem, gColAccent);
    TextOutW(mem, 18, 46, L"GUARD  4.0", 10);

    const wchar_t* nav[] = {
        L"总览", L"策略", L"端口", L"USB", L"云端",
        L"TOTP", L"强化", L"日志", L"隔离", L"狩猎"
    };
    for (int i = 0; i < NAV_COUNT; i++) {
        RECT nr = { 10, 76 + i * 40, 198, 110 + i * 40 };
        if (i == gNav) DrawRoundCard(mem, nr, gBrAccent);
        SetTextColor(mem, i == gNav ? RGB(255, 255, 255) : gColMuted);
        SelectObject(mem, gFontUi);
        DrawTextW(mem, nav[i], -1, &nr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    RECT top = { 220, 12, rc.right - 14, 68 };
    DrawRoundCard(mem, top, gBrCard);
    SelectObject(mem, gFontTitle);
    SetTextColor(mem, gColText);
    TextOutW(mem, 240, 24, L"行为防护中心", 6);
    SelectObject(mem, gFontSmall);
    SetTextColor(mem, gDriverOk ? gColOk : gColBad);
    TextOutW(mem, 820, 30, gDriverOk ? L"内核已连接" : L"仅用户态防护", gDriverOk ? 5 : 6);

    if (gNav == 0) {
        struct { const wchar_t* t; ULONGLONG v; COLORREF c; } cards[] = {
            { L"进程", gStats.blockedProcesses, gColBad },
            { L"LOLBin", gStats.blockedLolBins, gColWarn },
            { L"行为", gStats.blockedBehavior, gColAccent },
            { L"LSASS", gStats.protectedLsass, gColOk },
            { L"持久化", gStats.blockedPersist, gColWarn },
            { L"隔离", gUserQuarantined, gColOk },
        };
        for (int i = 0; i < 6; i++) {
            int col = i % 3, row = i / 3;
            RECT cr = { 220 + col * 274, 80 + row * 78, 482 + col * 274, 150 + row * 78 };
            DrawRoundCard(mem, cr, gBrCard);
            SetTextColor(mem, gColMuted);
            SelectObject(mem, gFontSmall);
            TextOutW(mem, cr.left + 14, cr.top + 10, cards[i].t, (int)wcslen(cards[i].t));
            wchar_t n[32];
            StringCchPrintfW(n, 32, L"%llu", cards[i].v);
            SetTextColor(mem, cards[i].c);
            SelectObject(mem, gFontTitle);
            TextOutW(mem, cr.left + 14, cr.top + 32, n, (int)wcslen(n));
        }
        SelectObject(mem, gFontUi);
        SetTextColor(mem, gColMuted);
        TextOutW(mem, 236, 246, L"实时拦截", 4);
    } else {
        SelectObject(mem, gFontUi);
        SetTextColor(mem, gColMuted);
        const wchar_t* hints[] = {
            L"",
            L"白名单 / 黑名单 / 禁止扩展名 / Run 键白名单，多项用分号分隔",
            L"白名单端口（备用）与黑名单端口（TCP/UDP 出站阻断）",
            L"USB 设备白名单。启用后，可移动介质上的执行会被内核拦截",
            L"VirusTotal 原生 API 与 Webhook 反馈云端。先查哈希，未知再上传",
            L"设置中心与高风险操作使用 TOTP 保护",
            L"系统强化与行为引擎开关。部分项需重启生效",
            L"日志目录、级别、滚动与保留",
            L"XOR 隔离舱。可还原或彻底清除样本",
            L"持久化狩猎与勒索诱饵。点击按钮立即执行"
        };
        RECT hintRc = { 236, 76, 1060, 108 };
        DrawTextW(mem, hints[gNav], -1, &hintRc, DT_LEFT | DT_WORDBREAK);
        if (gNav == 1) {
            TextOutW(mem, 248, 116, L"白名单路径", 5);
            TextOutW(mem, 248, 176, L"黑名单路径", 5);
            TextOutW(mem, 248, 236, L"禁止扩展名", 5);
            TextOutW(mem, 248, 296, L"注册表 Run 白名单", 10);
        } else if (gNav == 2) {
            TextOutW(mem, 248, 116, L"白名单端口", 5);
            TextOutW(mem, 248, 176, L"黑名单端口", 5);
        } else if (gNav == 3) {
            TextOutW(mem, 248, 116, L"USB 白名单", 6);
        } else if (gNav == 4) {
            TextOutW(mem, 248, 116, L"VirusTotal API Key", 18);
            TextOutW(mem, 248, 176, L"反馈云端 Webhook URL", 16);
            TextOutW(mem, 248, 236, L"租户 ID", 5);
        } else if (gNav == 7) {
            TextOutW(mem, 248, 116, L"日志目录", 4);
            TextOutW(mem, 248, 176, L"级别", 2);
            TextOutW(mem, 448, 176, L"保留天数", 4);
            TextOutW(mem, 648, 176, L"最大 MB", 5);
        }
    }

    BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
}

static void CreateUi(HWND h)
{
    gEdits[0] = MakeEdit(h, 5001, 0, 0, 10, 10, FALSE);
    gEdits[1] = MakeEdit(h, 5002, 0, 0, 10, 10, FALSE);
    gEdits[2] = MakeEdit(h, 5003, 0, 0, 10, 10, FALSE);
    gEdits[3] = MakeEdit(h, 5004, 0, 0, 10, 10, FALSE);
    gEdits[4] = MakeEdit(h, 5005, 0, 0, 10, 10, FALSE);
    gEdits[5] = MakeEdit(h, 5006, 0, 0, 10, 10, FALSE);
    gEdits[6] = MakeEdit(h, 5007, 0, 0, 10, 10, FALSE);
    gEdits[7] = MakeEdit(h, 5008, 0, 0, 10, 10, TRUE);
    gEdits[8] = MakeEdit(h, 5009, 0, 0, 10, 10, FALSE);
    gEdits[9] = MakeEdit(h, 5010, 0, 0, 10, 10, FALSE);
    gEdits[10] = MakeEdit(h, 5011, 0, 0, 10, 10, FALSE);
    gEdits[11] = MakeEdit(h, 5012, 0, 0, 10, 10, FALSE);
    gEdits[12] = MakeEdit(h, 5013, 0, 0, 10, 10, FALSE);
    gEdits[13] = MakeEdit(h, 5014, 0, 0, 10, 10, FALSE);
    gChecks[0] = MakeCheck(h, 5100, L"拦截可移动介质执行", 0, 0, 300);
    gChecks[1] = MakeCheck(h, 5101, L"启用 VirusTotal 云扫描", 0, 0, 300);
    gChecks[2] = MakeCheck(h, 5102, L"启用 Webhook 反馈云端", 0, 0, 300);
    gChecks[3] = MakeCheck(h, 5103, L"启用 TOTP 保护设置", 0, 0, 300);
    gChecks[4] = MakeCheck(h, 5104, L"桌面通知", 0, 0, 300);
    gChecks[5] = MakeCheck(h, 5105, L"声音提示", 0, 0, 300);
    gChecks[6] = MakeCheck(h, 5106, L"高风险操作确认", 0, 0, 300);
    gChecks[7] = MakeCheck(h, 5107, L"Sysmon 事件监控", 0, 0, 300);
    gChecks[8] = MakeCheck(h, 5108, L"WDAC 代码完整性", 0, 0, 300);
    gChecks[9] = MakeCheck(h, 5109, L"阻止 DLL 劫持", 0, 0, 300);
    gChecks[10] = MakeCheck(h, 5110, L"阻止剪贴板劫持", 0, 0, 300);
    gChecks[11] = MakeCheck(h, 5111, L"拦截注入键盘事件", 0, 0, 300);
    gChecks[12] = MakeCheck(h, 5112, L"禁用 NTLM", 0, 0, 300);
    gChecks[13] = MakeCheck(h, 5113, L"禁用 SMBv1", 0, 0, 300);
    gChecks[14] = MakeCheck(h, 5114, L"强制 DoH", 0, 0, 300);
    gChecks[15] = MakeCheck(h, 5115, L"禁用蓝牙服务", 0, 0, 300);
    gChecks[16] = MakeCheck(h, 5116, L"禁用混杂模式", 0, 0, 300);
    gChecks[17] = MakeCheck(h, 5117, L"禁用摄像头/麦克风", 0, 0, 300);
    gChecks[18] = MakeCheck(h, 5118, L"禁用 VSS", 0, 0, 300);
    gChecks[19] = MakeCheck(h, 5119, L"锁定 BIOS 更新", 0, 0, 300);
    gChecks[20] = MakeCheck(h, 5120, L"限制 HID 设备安装", 0, 0, 300);
    gChecks[21] = MakeCheck(h, 5121, L"自动清理旧日志", 0, 0, 300);
    gChecks[22] = MakeCheck(h, 5122, L"Spectre/Meltdown 缓解", 0, 0, 300);
    gChecks[23] = MakeCheck(h, 5123, L"按扩展名拦截进程", 0, 0, 300);
    gChecks[24] = MakeCheck(h, 5124, L"拦截 LOLBin 滥用", 0, 0, 300);
    gChecks[25] = MakeCheck(h, 5125, L"Office/浏览器子进程行为", 0, 0, 300);
    gChecks[26] = MakeCheck(h, 5126, L"保护 LSASS", 0, 0, 300);
    gChecks[27] = MakeCheck(h, 5127, L"拦截持久化写入", 0, 0, 300);
    gChecks[28] = MakeCheck(h, 5128, L"拦截影子副本破坏", 0, 0, 300);
    gChecks[29] = MakeCheck(h, 5129, L"拦截不可信路径执行", 0, 0, 300);
    gChecks[30] = MakeCheck(h, 5130, L"勒索诱饵监控", 0, 0, 300);
    gChecks[31] = MakeCheck(h, 5131, L"下载目录守护", 0, 0, 300);
    MakeBtn(h, IDC_SAVE, L"保存并应用", 920, 22, 128, 30);
    MakeBtn(h, IDC_BROWSE_LOG, L"浏览", 0, 0, 90, 28);
    MakeBtn(h, IDC_TEST_CLOUD, L"测试 Webhook", 0, 0, 140, 32);
    MakeBtn(h, IDC_TEST_VT, L"测试 VirusTotal", 0, 0, 160, 32);
    MakeBtn(h, IDC_HUNT, L"立即狩猎", 0, 0, 160, 32);
    MakeBtn(h, IDC_QUAR_RESTORE, L"还原", 0, 0, 120, 30);
    MakeBtn(h, IDC_QUAR_PURGE, L"清除", 0, 0, 120, 30);
    MakeBtn(h, IDC_SCAN_FILE, L"扫描文件", 0, 0, 140, 32);
    MakeBtn(h, IDC_CANARY_PLANT, L"投放诱饵", 0, 0, 160, 32);
    gEvtList = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        0, 0, 10, 10, h, (HMENU)IDC_EVT_LIST, GetModuleHandleW(NULL), NULL);
    ListView_SetExtendedListViewStyle(gEvtList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SendMessageW(gEvtList, WM_SETFONT, (WPARAM)gFontUi, TRUE);
    LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
    col.pszText = L"类型"; col.cx = 90; ListView_InsertColumn(gEvtList, 0, &col);
    col.pszText = L"PID"; col.cx = 70; ListView_InsertColumn(gEvtList, 1, &col);
    col.pszText = L"路径"; col.cx = 640; ListView_InsertColumn(gEvtList, 2, &col);
    gQuarList = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        0, 0, 10, 10, h, (HMENU)IDC_QUAR_LIST, GetModuleHandleW(NULL), NULL);
    ListView_SetExtendedListViewStyle(gQuarList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SendMessageW(gQuarList, WM_SETFONT, (WPARAM)gFontUi, TRUE);
    col.pszText = L"样本"; col.cx = 220; ListView_InsertColumn(gQuarList, 0, &col);
    col.pszText = L"原始路径"; col.cx = 580; ListView_InsertColumn(gQuarList, 1, &col);
    gLogView = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
        0, 0, 10, 10, h, (HMENU)IDC_LOG_VIEW, GetModuleHandleW(NULL), NULL);
    SendMessageW(gLogView, WM_SETFONT, (WPARAM)gFontSmall, TRUE);
    PushToUi();
    LayoutPage(h);
}

INT_PTR CALLBACK TotpPromptDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (msg) {
    case WM_INITDIALOG:
        SetFocus(GetDlgItem(hDlg, IDC_TOTP_CODE));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t a[8], b[8];
            GetDlgItemTextW(hDlg, IDC_TOTP_CODE, a, 8);
            GetTOTP(b, 8);
            if (wcscmp(a, b) == 0) EndDialog(hDlg, IDOK);
            else {
                MessageBoxW(hDlg, L"动态码错误", L"验证失败", MB_ICONERROR);
                SetDlgItemTextW(hDlg, IDC_TOTP_CODE, L"");
            }
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
    }
    return FALSE;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        gMain = h;
        BOOL dark = TRUE;
        DwmSetWindowAttribute(h, 20, &dark, sizeof(dark));
        CreateUi(h);
        SetTimer(h, IDT_STATS, 1500, NULL);
        SetTimer(h, IDT_HEARTBEAT, 300000, NULL);
        memset(&gTray, 0, sizeof(gTray));
        gTray.cbSize = sizeof(gTray);
        gTray.hWnd = h;
        gTray.uID = 1;
        gTray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        gTray.uCallbackMessage = WM_TRAY;
        gTray.hIcon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_ICON_32));
        StringCchCopyW(gTray.szTip, ARRAYSIZE(gTray.szTip), L"ZeroTrustGuard");
        Shell_NotifyIconW(NIM_ADD, &gTray);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        PaintMain(h, hdc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)w;
        SetTextColor(hdc, gColText);
        SetBkColor(hdc, gColCard);
        return (LRESULT)gBrCard;
    }
    case WM_LBUTTONDOWN: {
        int x = GET_X_LPARAM(l), y = GET_Y_LPARAM(l);
        if (x < 208 && y >= 76 && y < 76 + NAV_COUNT * 40) {
            int n = (y - 76) / 40;
            if (n != gNav) {
                if (n != 0 && !GuardSettings(h)) break;
                gNav = n;
                LayoutPage(h);
            }
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_SAVE:
            if (!GuardSettings(h)) break;
            CollectFromUi(h);
            SaveCfg();
            SendConfigToDriver();
            ApplySystemHardening();
            ApplyPortFilterRules();
            Log(L"settings applied");
            CloudEmitEvent(L"config", L"applied");
            MessageBoxW(h, L"已保存并应用到驱动 / WFP / 系统强化 / 云端。", L"ZeroTrustGuard", MB_ICONINFORMATION);
            break;
        case IDC_BROWSE_LOG: {
            BROWSEINFOW bi = { 0 };
            wchar_t path[MAX_PATH];
            bi.hwndOwner = h;
            bi.lpszTitle = L"选择日志目录";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, path) && gEdits[10]) SetWindowTextW(gEdits[10], path);
                CoTaskMemFree(pidl);
            }
            break;
        }
        case IDC_TEST_CLOUD:
            CollectFromUi(h);
            CloudEmitEvent(L"heartbeat", L"manual-test");
            MessageBoxW(h, L"已向 Webhook 发送测试心跳。", L"云端", MB_OK);
            break;
        case IDC_TEST_VT: {
            CollectFromUi(h);
            wchar_t self[MAX_PATH];
            GetModuleFileNameW(NULL, self, MAX_PATH);
            ScanFileWithVT(self);
            MessageBoxW(h, L"已对当前程序发起 VirusTotal 哈希查询。", L"VirusTotal", MB_OK);
            break;
        }
        case IDC_HUNT:
            HuntPersistence();
            MessageBoxW(h, L"持久化狩猎完成，结果写入日志。", L"狩猎", MB_OK);
            break;
        case IDC_QUAR_RESTORE:
            RestoreSelectedQuarantine();
            break;
        case IDC_QUAR_PURGE:
            PurgeSelectedQuarantine();
            break;
        case IDC_SCAN_FILE: {
            wchar_t file[MAX_PATH] = { 0 };
            OPENFILENAMEW ofn = { sizeof(ofn) };
            ofn.hwndOwner = h;
            ofn.lpstrFile = file;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"All\0*.*\0";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                ScanFileWithVT(file);
                Log(L"manual scan %s", file);
            }
            break;
        }
        case IDC_CANARY_PLANT:
            PlantCanaries();
            MessageBoxW(h, L"已在桌面、文档、下载目录投放诱饵。", L"诱饵", MB_OK);
            break;
        }
        return 0;
    case WM_TIMER:
        if (w == IDT_STATS) {
            RefreshStats();
            InvalidateRect(h, NULL, FALSE);
        } else if (w == IDT_HEARTBEAT) {
            RefreshStats();
            CloudEmitEvent(L"heartbeat", L"periodic");
        }
        return 0;
    case WM_ZTG_LOG:
        if (l) {
            if (gLogView) {
                int len = GetWindowTextLengthW(gLogView);
                SendMessageW(gLogView, EM_SETSEL, len, len);
                SendMessageW(gLogView, EM_REPLACESEL, FALSE, l);
                SendMessageW(gLogView, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
            }
            free((void*)l);
        }
        return 0;
    case WM_ZTG_EVT:
        if (l) {
            ZTG_EVENT* e = (ZTG_EVENT*)l;
            if (gEvtList) {
                const wchar_t* k = L"event";
                if (e->type == ZTG_EVENT_PROCESS) k = L"进程";
                else if (e->type == ZTG_EVENT_IMAGE) k = L"映像";
                else if (e->type == ZTG_EVENT_REGISTRY) k = L"注册表";
                else if (e->type == ZTG_EVENT_LOLBIN) k = L"LOLBin";
                else if (e->type == ZTG_EVENT_BEHAVIOR) k = L"行为";
                else if (e->type == ZTG_EVENT_LSASS) k = L"LSASS";
                else if (e->type == ZTG_EVENT_PERSIST) k = L"持久化";
                else if (e->type == ZTG_EVENT_RANSOM) k = L"勒索";
                LVITEMW it = { 0 };
                it.mask = LVIF_TEXT;
                it.iItem = 0;
                it.pszText = (LPWSTR)k;
                int row = ListView_InsertItem(gEvtList, &it);
                wchar_t pid[16];
                StringCchPrintfW(pid, ARRAYSIZE(pid), L"%u", e->pid);
                ListView_SetItemText(gEvtList, row, 1, pid);
                ListView_SetItemText(gEvtList, row, 2, e->path);
            }
            free(e);
        }
        return 0;
    case WM_TRAY:
        if (l == WM_LBUTTONDBLCLK) {
            ShowWindow(h, SW_RESTORE);
            SetForegroundWindow(h);
        }
        return 0;
    case WM_SIZE:
        if (w == SIZE_MINIMIZED) ShowWindow(h, SW_HIDE);
        return 0;
    case WM_DESTROY:
        KillTimer(h, IDT_STATS);
        KillTimer(h, IDT_HEARTBEAT);
        Shell_NotifyIconW(NIM_DELETE, &gTray);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show)
{
    UNREFERENCED_PARAMETER(prev);
    UNREFERENCED_PARAMETER(cmd);
    if (!ZTG_IsUserAnAdmin()) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = path;
        sei.nShow = SW_SHOWNORMAL;
        ShellExecuteExW(&sei);
        return 1;
    }
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    InitializeCriticalSection(&gLogLock);
    InitializeCriticalSection(&gVtLock);
    InitializeCriticalSection(&gCloudLock);
    gEvExit = CreateEventW(NULL, TRUE, FALSE, NULL);
    LoadCfg();
    if (!HandleFirstRunAndEULA()) return 0;
    EnsureLogPath();
    Log(L"ZeroTrustGuard 4.0 starting");
    InitEvtApi();
    CleanupOldLogs();
    ApplySystemHardening();
    ApplyPortFilterRules();
    gDriverOk = InstallAndStartDriver() && ConnectDriver();
    if (gDriverOk) SendConfigToDriver();
    else Log(L"kernel driver unavailable, user-mode protection only");
    StartMonitorThreads();

    gFontUi = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    gFontTitle = CreateFontW(24, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    gFontSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    gBrBg = CreateSolidBrush(gColBg);
    gBrCard = CreateSolidBrush(gColCard);
    gBrSide = CreateSolidBrush(gColSide);
    gBrAccent = CreateSolidBrush(gColAccent);
    gBrEdit = CreateSolidBrush(RGB(15, 23, 42));

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON_32));
    wc.hIconSm = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON_16));
    wc.lpszClassName = L"ZeroTrustGuardMain";
    wc.hbrBackground = gBrBg;
    RegisterClassExW(&wc);

    HWND wnd = CreateWindowExW(0, wc.lpszClassName, L"ZeroTrustGuard",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1140, 780, NULL, NULL, inst, NULL);
    ShowWindow(wnd, show);
    UpdateWindow(wnd);
    CloudEmitEvent(L"heartbeat", L"startup");

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    StopMonitorThreads();
    if (gDrv != INVALID_HANDLE_VALUE) CloseHandle(gDrv);
    DeleteCriticalSection(&gLogLock);
    DeleteCriticalSection(&gVtLock);
    DeleteCriticalSection(&gCloudLock);
    CloseHandle(gEvExit);
    return 0;
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    UNREFERENCED_PARAMETER(cmd);
    return wWinMain(inst, prev, GetCommandLineW(), show);
}
