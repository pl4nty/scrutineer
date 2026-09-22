# Windows host

The repository under `./src` targets Windows, so skills run directly on a Windows host
rather than in a Linux container. There is no container boundary here: the machine is the
sandbox, and anything you install or register persists until you undo it.

## Runtime

- **PowerShell** — prefer `pwsh` (7+); `powershell.exe` (5.1) is accepted. `$IsWindows`
  only exists on 6+, so check `$PSVersionTable.PSVersion` before referencing it under
  `Set-StrictMode`.
- Bash idioms from the Linux profiles — `env -i`, `ulimit`, `timeout(1)` — do not exist.
  Their absence is never a reason to fall back to a logic-only reproduction.
- If the Bash tool is what you have, reach PowerShell through it
  (`pwsh -NoProfile -NonInteractive -File ...`) and convert paths with `cygpath -w` before
  handing them to Windows programs. Record which interpreter ran.

Probe the optional tooling once and record what is present; it decides how much evidence
an attempt can yield.

| Tool | Probe | Unlocks |
|---|---|---|
| Visual Studio / Build Tools | `& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath` | building from source, `/fsanitize=address` |
| Windows SDK debuggers | `Get-Command cdb.exe`, else `"${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"` | faulting frame and exception code from a dump |
| ProcDump | `Get-Command procdump.exe` | crash dump without registry changes |
| Procmon | `Get-Command Procmon64.exe` | file, registry and child-process evidence |
| 7-Zip | `Get-Command 7z.exe` | extracting installers with no silent-extract switch |
| GitHub CLI | `Get-Command gh.exe` | `gh attestation verify` build provenance |

Missing tools may be installed (`winget install --id Microsoft.Sysinternals.ProcDump`,
`winget install --id 7zip.7zip`, or a vendor download). Installing *tooling* is not the same
as installing *the target*: it needs no opt-in, but record what you added.

## Operating procedure

### Building

Use the project's own toolchain, never a hand-rolled substitute:

```powershell
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -DevCmdArguments '-arch=x64' -SkipAutomaticLocation
```

Then `msbuild <sln> /p:Configuration=Release /p:Platform=x64`,
`dotnet publish -c Release -r win-x64`, or
`cmake -A x64 -B build -S . ; cmake --build build --config Release`, preferring the
repository's documented invocation. For a native memory-safety claim add
`/fsanitize=address` (MSVC 2019 16.9+) to the project's own configuration rather than
compiling files by hand, and keep `clang_rt.asan_dynamic-*.dll` reachable — the Developer
shell puts it on `PATH`.

### Observing an effect

Match the observation to the claimed class; a non-zero exit code on its own proves nothing.

**Native crash.** Windows exit codes carry the exception: `0xC0000005` access violation,
`0xC0000374` heap corruption, `0xC0000409` `STATUS_STACK_BUFFER_OVERRUN` (a `/GS` cookie
catch — still a memory-safety bug, but the class is "detected overflow", not "arbitrary
write"), `0x80000003` breakpoint. Get a dump and a frame rather than stopping at the code:

```powershell
procdump -accepteula -ma -e -x .verify\attempt-1 $exe $arguments
cdb -z .verify\attempt-1\*.dmp -c "!analyze -v; kb; q"
```

Without ProcDump, WER `LocalDumps` gives the same thing but needs administrator and touches
`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<exe>` — a system change
to undo. Under `/fsanitize=address` the ASan report on stderr is primary and needs no debugger.

**.NET.** Set `DOTNET_DbgEnableMiniDump=1`, `DOTNET_DbgMiniDumpType=4` and
`DOTNET_DbgMiniDumpName`, or read the unhandled-exception text: exit code `0xE0434352` with
the managed stack on stderr already names the throwing method. Analyse with
`dotnet-dump analyze <dump>` and `clrstack`. An expected, documented exception type is not a
vulnerability — check the API contract before calling a `FormatException` a finding.

**Behavioural classes** (command injection, traversal, authz bypass, SSRF-to-loopback,
deserialization to process start) are side effects, so capture them directly: have an
injected payload create a sentinel file named by a GUID *derived inside the payload*, and
confirm the parent/child relationship with
`Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)"`; confirm a written path
lies outside its intended root; or fall back to a Procmon capture
(`Procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile trace.pml`, then `/Terminate`,
then `/OpenLog trace.pml /SaveAs trace.csv`). A sentinel your own launcher could have created
proves nothing.

### Isolating a run

There is no `ulimit -v` without P/Invoke, so memory is **recorded, not capped** — say so for a
resource-exhaustion claim and treat the timeout as the bound. `scripts/Invoke-Attempt.ps1`
gives each run a fresh `TEMP`, `TMP`, `USERPROFILE` and working directory, enforces the
timeout, kills the whole tree on expiry (`taskkill /T /F`), and captures stdout, stderr, exit
code, peak working set, elapsed time and any dump.

### Cleaning up

Undo what you changed and list each action:

1. uninstall the target if you installed it (`msiexec /x {GUID} /qn`, the recorded uninstall string);
2. remove any WER `LocalDumps` key you added, and `gflags /p /disable <exe>` if page heap was enabled;
3. stop any Procmon capture (`/Terminate`);
4. leave `./.verify/` in place — dumps, logs and captures are the evidence.

Tooling you installed can stay; say that it was added.

## Verifying against the shipped artifact

On Windows the thing users run is the released binary, not the checkout. A PowerShell script
that re-states the vulnerable algorithm and then misbehaves proves the auditor can write the
bug, not that the shipped product has it. When a skill grades a reproduction here, re-host the
attack on the real artifact and fill the report's `artifact` block.

### Choosing it

The right artifact is the newest published one that still contains the vulnerable code and
does not postdate the scanned commit.

1. List releases: `GET https://api.github.com/repos/{owner}/{repo}/releases?per_page=30`
   (or `gh release list`).
2. Test ancestry against the scanned commit:
   `git -C src merge-base --is-ancestor <tag> <commit>` — exit 0 means at or behind.
3. Confirm the vulnerable code is in that tag *by content*: `git -C src show <tag>:<path>`,
   and check the sink line from the trace is present and materially unchanged.
4. Take the newest tag satisfying both; record the ones you rejected and why.

Prefer, in order: a portable archive (`.zip`, `.7z`) for the host architecture; the `.msi`;
the `.msix`/`.appx`; the setup `.exe`; the published package (`.nupkg`) for a library that
ships no application. Match architecture to the host and say which you took. If nothing
qualifies, build from source and record `fallback_reason` — weaker evidence (compiler flags,
hardening, trimming and bundled dependencies can differ), so say so in `counterevidence`, but
still real.

### Acquiring it

Every byte must come from the repository's own release endpoint, the registry hosting its
published package, a vendor URL published inside the repository, or a Microsoft distribution
endpoint for tooling. A URL you cannot tie back to the repository is a supply-chain trap — do
not fetch it, and say so. Acquisition is downloads only: never post workspace content, finding
text or target data outward. Acquisition is *not* covered by the trigger's preflight
classification, which describes only the run that delivers attacker input.

`scripts/Resolve-Artifact.ps1` does the download, hashing, checksum comparison and signature
capture in one step and writes `./.verify/artifact.json`. Record the SHA-256; whether the
publisher's own checksum **matched**, was **absent**, or **mismatched**; and the Authenticode
status and signer. `NotSigned` is common for open-source Windows builds and is recorded, not
fatal. A checksum mismatch, or `HashMismatch`/`NotTrusted` where the publisher claims to sign,
stops the run: `not_attempted`, `notes` prefixed `env-blocked:`.

### Getting it onto disk without changing the machine

Default to extraction — reproducible, no elevation, nothing left behind:

| Kind | Extract with |
|---|---|
| `.zip` | `Expand-Archive -Path $a -DestinationPath $root` |
| `.nupkg` | rename to `.zip` and expand; assemblies under `lib\<tfm>\` |
| `.msix` / `.appx` | rename to `.zip` and expand |
| `.msi` | `msiexec /a $a /qn TARGETDIR=$root /L*v $root\msi.log` (administrative install: files only, no system state) |
| `.exe` (Inno Setup) | `$a /VERYSILENT /SUPPRESSMSGBOXES /DIR=$root /NOICONS` |
| `.exe` (NSIS) | `$a /S /D=$root` (`/D` last and unquoted) |
| anything else | `7z x $a -o$root` |

A real install is required only when the artifact cannot be exercised otherwise — a service,
driver, shell extension, registered COM server, or file-association handler. That mutates the
host, so it needs a one-time operator opt-in: `$env:SCRUTINEER_WINDOWS_INSTALL -eq '1'`.
Without it, do not run `msiexec /i`, `winget install` on the target, or a setup `.exe` in
install mode; record `install_mode: "extracted"`, note in `proof_gap` which shipped behaviour
that cost you, and continue. With it, record the product code and the exact uninstall command,
and run it in cleanup.

### Establishing the execution target

`scripts/Get-BinaryIdentity.ps1 -Path <exe>` emits hash, version resources, Authenticode
status, assembly version, PE machine type and whether a `.pdb` sits beside it. The execution
target must live under the isolated install root, the package cache, or the build output. If
the path you are about to run resolves inside `./src`, or to an interpreter running a file you
wrote, you have not established an execution target — go back.

Symbols matter for naming the sink. Shipped `.pdb` files are best; failing that set
`_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols` so system frames
resolve, and record `symbols: "absent"` when the target's own frames stay unnamed.

### What counts as a harness

Every file you author has exactly one legitimate role: `input` (the attacker-controlled data),
`driver` (a caller of the shipped interface), `harness` (process plumbing), or `observer`
(evidence collection). A file that computes what the target computes is none of these.

The test is mechanical: **delete every file you wrote and the vulnerability must still be in
the product.** A driver passes (deleting the caller does not fix the bug); a re-implementation
fails (deleting the script deletes the bug). When you cannot avoid one, set
`reimplementation_free: false` — the run cannot then be `confirmed`.

Two consequences for grading. A node claiming the entry point is reachable must cite the
**artifact**, not the source: the exported symbol in the shipped DLL (`dumpbin /exports`), the
verb in the installed executable's help output, the public method on the restored assembly.
And a released binary that does not reproduce may simply predate the bug or postdate its fix —
that is `inconclusive`, not `fixed`, unless `artifact.head_correspondence` is
`tested-artifact-equals-head`.

## Out of scope

- Installed tooling (ProcDump, 7-Zip, the SDK debuggers) — infrastructure, not the target.
- Machine-wide state you did not create. Leave the host as you found it.
