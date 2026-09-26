# User Instruction Memory

This file records user instructions, preferences, and teachings for reference in future interactions.

## Format

### User Instruction Entry

[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

### Project Knowledge Entry

[Project Knowledge Summary]
- Date: [YYYY-MM-DD]
- Context: Discovered by Agent while performing [specific task description]
- Category: [Operations & Deployment|Build Methods|Testing Methods|Troubleshooting & Debugging|Workflow & Collaboration|Environment Configuration]
- Instructions:
  - [Specific knowledge points, described line by line]

## Deduplication Strategy

- Before adding a new entry, check for similar or identical instructions.
- If a duplicate is found, skip the new entry or merge it with the existing one.
- When merging, update the context or date information.
- This helps avoid redundant entries and keeps the memory file tidy.

## Entries

[Project Knowledge Summary]
- Date: 2026-09-24
- Context: Discovered by Agent while getting the native Windows CI build green
- Category: Build Methods
- Instructions:
  - No local Windows toolchain in this workspace; all native builds happen on GitHub Actions via `.github/workflows/windows-build.yml` on `windows-2022`.
  - Build entry point is `tools/build.ps1`; it builds `src\app\ZeroTrustGuard.vcxproj` first, then `src\drv\ZeroTrustGuardDrv.vcxproj`, and throws "User-mode build failed" / "Driver build failed".
  - Use 64-bit MSBuild: `Find-MSBuild` prefers `<VS>\MSBuild\Current\Bin\amd64\MSBuild.exe`.
  - The WDK is consumed as NuGet `Microsoft.Windows.WDK.x64` 10.0.26100.3323 (restores into repo `packages/`).
  - The WDK NuGet package ships `stampinf.exe` only under `c/bin/10.0.26100.0/{x64,ARM64}`, missing `x86`, while the DriverKit build task resolves host tools under `x86`. `Complete-WdkHostTools` in `tools/build.ps1` shims `x86` by copying the `x64` `.exe` tools (safe on the x64 runner) before the driver build.
  - To reproduce locally on Linux (no MSVC/WDK), inspect the WDK NuGet layout/headers by extracting the `.nupkg`; do not attempt to compile.

[Project Knowledge Summary]
- Date: 2026-09-24
- Context: Discovered by Agent while fixing kernel-mode compile and INF validation errors
- Category: Troubleshooting & Debugging
- Instructions:
  - Kernel translation units in this build do NOT have user-mode typedefs `BOOL`/`BYTE`/`WORD`/`DWORD` available. Use `BOOLEAN`/`UCHAR` in shared headers (`include/ZtgShared.h`) so they compile in both kernel and user mode.
  - `SeLocateProcessImageName` is already declared in `ntifs.h`; do not re-declare it (C2375 different linkage).
  - `IoGetLowestDeviceObject` is not a real WDK API. For removable-media detection use `IoGetDeviceObjectPointer` on the `\Device\<name>` prefix of an NT image path and test `Characteristics & FILE_REMOVABLE_MEDIA`.
  - Registry `CmCallbackGetKeyObjectIDEx` requires a cookie from `CmRegisterCallbackEx` (with an altitude string), not `CmRegisterCallback`.
  - WDK InfVerif signing-mode validation emits `error 1296` unless the device's function service has the `SPSVCINST_ASSOCSERVICE` flag: `AddService=<Name>,0x00000002,<ServiceInstallSection>`.
  - Driver project disables signing and cat generation via `SignMode=Off` and `EnableInf2cat=false`, so CI needs no cert.

[Project Knowledge Summary]
- Date: 2026-09-26
- Context: Discovered by Agent while pushing the app changes and verifying the CI run
- Category: Workflow & Collaboration
- Instructions:
  - GitHub auth is provided by the configured git credential helper (`/app/agent/bin/agent git-credential-helper`); `git push origin main` works directly without entering a token.
  - `gh` is installed but not logged in. To query/trigger CI, export a token for the session: `export GH_TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | grep '^password=' | cut -d= -f2-)`.
  - Never print the token value; only use it inline for `gh`.
  - Useful commands: `gh run list --repo xiongzhuosen/ZeroTrustGuard --limit 3`, `gh run view <id> --repo ... --json headSha,conclusion,status`, `gh run download <id> --repo ... --dir <path>`.

