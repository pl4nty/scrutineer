# Windows profile

Scrutineer's [`verify`](../skills/verify/SKILL.md) skill re-runs whatever reproduction the audit
left on the finding. For a project that ships on Windows, that reproduction is often a Python or
PowerShell script that re-states the vulnerable algorithm and shows the re-statement misbehaving.
It proves the auditor can write the bug; it does not prove the shipped product has it.

The `windows` profile puts skills on a Windows host instead of a Linux container, and its guide
([`docker/profiles/windows/PROFILE.md`](../docker/profiles/windows/PROFILE.md)) carries the
procedure for grading against the artifact the publisher actually ships: the release binary, MSI,
MSIX or package, downloaded from its published location, identified by hash and signature,
extracted or installed, and driven through the interface it exposes.

This is the same mechanism as the per-ecosystem profiles — `ruby-ext` swaps in a
sanitizer-instrumented interpreter, `windows` swaps in the host — so no separate skill is
involved. `verify` fills the optional `artifact` block in its report when the profile guide says
to, and omits it everywhere else.

## When it applies

- The project distributes Windows binaries, or is a .NET/C++ library whose consumers run on Windows.
- Scrutineer runs on a Windows host. The containerised runner is Linux, so a Windows-targeted
  repository scanned from a Linux host stays on the ordinary source-tree verification.
- The host is disposable. Verification installs third-party software and executes
  attacker-controlled input against it. Run it in a VM you can roll back, never on a workstation
  you care about.

## Selecting it

Detection follows the same path as the other profiles: `brief` reports the repository's package
managers, languages and build systems, and a match on NuGet, the dotnet CLI or MSBuild resolves
the `windows` profile. Because that profile is host-backed rather than image-backed, resolving it
routes the scan to the host runner instead of building a container image.

Two overrides exist, as for any profile:

- `scrutineer.requires_profile: windows` in a skill's frontmatter pins that skill to this profile.
- `host_skills` in the config file names skills that always run on the host, regardless of the
  detected profile. Use it when detection cannot see what you know — a repository whose Windows
  surface is not visible to `brief`, for instance.

## Host setup

Required:

- Windows 10/11 or Server 2019+, in a VM with a snapshot to roll back to.
- PowerShell. `pwsh` 7 is preferred; Windows PowerShell 5.1 works and the bundled scripts avoid
  PowerShell 6+ syntax.
- Visual Studio 2022 or the Build Tools, for building when no release carries the vulnerable code.
  `vswhere.exe` under `%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\` is how the guide
  finds it.

Optional, each unlocking better evidence — the guide probes for them and records what was present:

| Tool | Install | Unlocks |
|---|---|---|
| Windows SDK debuggers (`cdb`) | `winget install Microsoft.WindowsSDK` | faulting frame and exception analysis from a crash dump |
| ProcDump | `winget install Microsoft.Sysinternals.ProcDump` | crash dumps without registry changes |
| Procmon | `winget install Microsoft.Sysinternals.ProcessMonitor` | file, registry and child-process evidence |
| 7-Zip | `winget install 7zip.7zip` | extracting installers with no silent-extract switch |
| GitHub CLI | `winget install GitHub.cli` | build-provenance verification |

## Installing the target

Extraction is the default and needs no opt-in: it is reproducible, needs no elevation, and leaves
nothing behind. A real install — for a service, driver, shell extension, COM server or
file-association handler — mutates the host, so it is gated on an explicit operator opt-in:

```powershell
$env:SCRUTINEER_WINDOWS_INSTALL = '1'
```

Without it the run continues with what extraction allows and records in `proof_gap` which shipped
behaviour that cost. With it, the uninstall command is recorded and executed during cleanup.

## Reading the result

A run on this profile fills `artifact` alongside the usual rubric: where the build came from and
how its identity was proved, what was executed, which files the agent authored and why, and any
change made to the machine. Two rules bind the grading:

- `public_interface_to_first_party_sink` passes only when the executed image is the shipped build,
  identified by hash, and the input entered through an interface that image exposes.
- `confirmed` additionally requires `artifact.reimplementation_free`; a confirmation that cannot
  name the shipped file it ran is not a confirmation.

One trap is worth knowing about. A released binary that does not reproduce may simply predate the
bug or postdate its fix, so a clean older release is `inconclusive`, not `fixed`, unless
`artifact.head_correspondence` is `tested-artifact-equals-head`.
