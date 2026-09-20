# ZeroTrustGuard 4.0

Windows 零信任行为防护：用户态控制台 + 内核驱动。现代化界面，内核行为引擎，原生 VirusTotal API，Webhook 反馈云端。

## 布局

```
include/ZtgShared.h          用户态 / 内核共享协议 (v4)
src/app/ZeroTrustGuard.c     用户态控制台
src/drv/ZeroTrustGuardDrv.c  WDM 内核驱动
.github/workflows/           Windows 原生云端编译
tools/build.ps1              本地 / CI 统一入口
```

## 编译

在装有 Visual Studio 2022 (C++ 桌面) 的 Windows 上：

```powershell
.\tools\build.ps1 -Configuration Release -Platform x64
```

产物在 `out\x64\Release\`。内核驱动需要同时安装 [Windows Driver Kit](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk)。未装 WDK 时脚本仍会编出 `ZeroTrustGuard.exe`。

### GitHub Actions 云端编译

推送到 `main` / `master`，或在 Actions 里手动跑 **Windows Native Build**。Runner 是 `windows-2022`，使用本机 MSVC。

成功后从 Artifacts 下载 `ZeroTrustGuard-windows-x64`。

## 能力

内核（IRP / 回调热路径，策略预解析）：

- 进程创建拦截：黑名单、扩展名、USB 可移动介质、不可信路径
- LOLBin 拦截：PowerShell / mshta / rundll32 / certutil 等，结合命令行与父进程
- 行为：Office / 浏览器拉起非系统映像
- 勒索：拦截 `vssadmin delete shadows`、`wbadmin delete`、`bcdedit recoveryenabled no` 等
- 持久化：Run / RunOnce / Winlogon / IFEO / AppInit / LSA / Print Monitor / 计划任务
- LSASS：剥离跨进程 VM / 线程 / 句柄权限
- DLL 劫持：黑名单或不可信路径映像入口修补为 `STATUS_ACCESS_DENIED`

用户态：

- 下载目录守护：Downloads 新增可执行 / 脚本即哈希扫描并隔离
- XOR 隔离舱：还原或彻底清除
- 勒索诱饵：桌面 / 文档 / 下载投放 canary，触碰即告警
- 持久化狩猎：Run 键、Winlogon、启动文件夹
- 剪贴板加密货币劫持、注入键盘拦截、Sysmon、WFP 端口阻断、系统强化
- VirusTotal v3：先查 SHA-256，未知再上传
- Webhook：拦截事件与计数器 JSON POST

Webhook 示例：

```json
{
  "source": "ZeroTrustGuard",
  "version": "4.0.0",
  "tenant": "local",
  "type": "lolbin",
  "path": "\\??\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "blocked_process": 1,
  "blocked_lolbin": 1,
  "blocked_behavior": 0,
  "blocked_persist": 0,
  "protected_lsass": 0,
  "blocked_ransom": 0,
  "quarantined": 1
}
```

`type` 取值：`process` / `image` / `registry` / `lolbin` / `behavior` / `lsass` / `persist` / `ransom` / `clipboard` / `download` / `quarantine` / `config` / `heartbeat` / `virustotal`。

## 运行

1. 以管理员启动 `ZeroTrustGuard.exe`
2. 测试签名环境加载 `ZeroTrustGuardDrv.sys`（生产环境需正式 EV 证书签名）
3. 在「云端」填入 VirusTotal API Key 和 Webhook URL
4. 「保存并应用」把策略下发给驱动、WFP 和系统强化

测试签名（本机一次性）：

```powershell
bcdedit /set testsigning on
```
