# Windows artifact validation (`verify-windows`)

Scrutineer's generic [`verify`](../skills/verify/SKILL.md) skill re-runs whatever reproduction the audit left on the finding. For a project that ships on Windows, that reproduction is often a Python or PowerShell script that re-states the vulnerable algorithm and shows the re-statement misbehaving. It proves the auditor can write the bug; it does not prove the shipped product has it.

`verify-windows` grades the same rubric against the artifact the publisher actually ships: the release binary, MSI, MSIX or package, downloaded from its published location, identified by hash and signature, extracted or installed, and driven through the interface it exposes. This page covers the host setup that makes that possible and the operational shape of a run.

## When it applies

Use it when all of these hold:

- The project distributes Windows binaries, or is a .NET/C++ library whose consumers run on Windows.
- Scrutineer runs on a Windows host with `--no-container`. The containerised runner is Linux; the skill detects a non-Windows host and reports `not_attempted` with an `env-blocked:` note rather than degrading into a logic-only reproduction.
- The host is disposable. Verification installs third-party software and executes attacker-controlled input against it. Run it in a VM you can roll back, never on a workstation you care about.

Everything else — including Windows projects scanned from a Linux host — stays on `verify`.

## Host setup

Required:

- Windows 10/11 or Server 2019+, in a VM with a snapshot to roll back to.
- PowerShell. `pwsh` 7 is preferred; Windows PowerShell 5.1 works and the bundled scripts avoid PowerShell 6+ syntax.
- Scrutineer started with `--no-container`, which runs the agent CLI directly on the host with no isolation. That is the whole point here — the agent needs the real Windows API surface — and it is also the reason the host must be disposable.
- Visual Studio 2022 or the Build Tools, for the source-build fallback. `vswhere.exe` under `%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\` is how the skill finds it.

Optional, each unlocking better evidence:

| Tool | Install | Unlocks |
|---|---|---|
| Windows SDK debuggers (`cdb`) | `winget install Microsoft.WindowsSDK` | faulting frame and exception analysis from a crash dump |
| ProcDump | `winget install Microsoft.Sysinternals.ProcDump` | crash dumps without touching the registry |
| Procmon | `winget install Microsoft.Sysinternals.ProcessMonitor` | file, registry and child-process evidence for injection, traversal and authz classes |
| 7-Zip | `winget install 7zip.7zip` | extracting installers with no silent-extract switch |
| GitHub CLI | `winget install GitHub.cli` | `gh attestation verify` build provenance on release assets |

The skill probes for each and records what was present; a missing tool lowers the confidence it can claim, it does not fail the run.

### Installing the target

By default the skill only *extracts* the artifact — `Expand-Archive`, `msiexec /a` (administrative install), an installer's own extract switch — so nothing about the machine changes. Some artifacts cannot be exercised that way: a Windows service, a driver, a shell extension, a registered COM server, a file-association handler. To let the skill run a real installer, set the opt-in before starting scrutineer:

```powershell
$env:SCRUTINEER_WINDOWS_INSTALL = '1'
```

Without it, the skill records what extraction cost it in `proof_gap` and carries on with the shipped behaviour it could still reach. With it, every install is recorded in the report's `artifact.system_changes` together with the uninstall command, which the skill runs in cleanup.

## Running it

The skill is finding-scoped and ships bundled (`-skills ./skills` picks up local edits). The finding page shows **Verify on Windows** alongside **Verify** in both the `new` and `enriched` states — a finding that generic verify already graded can be re-checked against the real artifact — but only when two things hold: the skill is installed and enabled on `/skills`, and scrutineer is running on Windows with skills executing on the host rather than in a container. On any other host the action is hidden rather than offered as a run that could only report `env-blocked`.

A running skill can enqueue it the same way it enqueues any finding-scoped skill:

```http
POST {api_base}/findings/{id}/skills/verify-windows/run
Authorization: Bearer {scan token}
```

Expect a run to take considerably longer than `verify`: it downloads and unpacks a release, may build from source, and runs three isolated attempts under a debugger. `scrutineer.max_turns` is set to 120 accordingly.

## Reading the result

The report is the `verify` shape plus an `artifact` block, and it is stored as the same append-only verification record with the same lifecycle effects (`confirmed` moves `new` to `enriched`; `fixed` on the default branch moves the finding to `fixed`). Three fields carry most of the weight:

- **`artifact.provenance`** — `released-binary`, `package-registry` or `source-build`. A confirmation cannot be `none`: if the skill could not obtain something real to run, it reports `inconclusive` or `not_attempted` instead.
- **`artifact.reimplementation_free`** — false the moment an authored file computes what the target computes. The mechanical test is that deleting every file the skill wrote must leave the vulnerability in the product. A false value cannot support `confirmed`.
- **`artifact.head_correspondence`** — a released binary that does not reproduce may simply predate the bug or postdate its fix. Only `tested-artifact-equals-head` can support a `fixed` verdict; a clean older release is `inconclusive` with the reason in `notes`.

The schema enforces all three, so a report that skips them fails validation rather than quietly recording a weaker result.

`artifact.authored_files` is the audit trail for the anti-re-implementation rule: every file the run wrote, classified as `input` (attacker data), `driver` (a caller of the shipped interface), `harness` (process plumbing) or `observer` (evidence collection). A file that parses the target's format or re-derives its escaping has no legitimate role in that list.

## Common outcomes that are not failures

- **`inconclusive` with "no shipped interface accepts this input"** — the finding was validated against a re-implementation and does not survive contact with the product. That is the result, not a broken run.
- **`blocked` attack-tree node citing the artifact** — the source exposes an entry point the shipped build trims, `internal`-scopes, or compiles out. Worth recording: it usually means the finding is real in source and unreachable in the release.
- **`not_attempted` with `env-blocked:`** — the host was not Windows, the release could not be obtained, or the build failed. Retryable; it is not evidence about the finding.
