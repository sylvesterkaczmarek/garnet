# Garnet #2349: Windows validation assets

Standalone `net10.0` harness for the actual `CertificateUtils.GetMachineCertificateByFile` implementation. No production project dependencies, NuGet packages, workflow, patch, or mock importer are included. The runner reads the checkout, exports the base with `git show`, and copies the candidate into separate temporary build directories **outside the checkout**. It records SHA-256 hashes of the exact source bytes and shared harness.

Use an elevated, **disposable `windows-2022` GitHub-hosted runner**, 64-bit PowerShell 7.2+, Git, and an already provisioned .NET 10 SDK. The coordinator supplies the workflow on the user's public fork and provisions the SDK (for example with `actions/setup-dotnet`). This script installs nothing. Keep these assets outside `RepoRoot`; the base Git object must already exist locally. No credentials, repository write token, network service, real certificate, or external account is needed.

```powershell
# Baseline preflight; no candidate implementation needed.
pwsh -NoProfile -File C:\validation-assets\Run-Validation.ps1 `
  -RepoRoot $env:GITHUB_WORKSPACE `
  -BaseSha 5cc8f3f50aa57ed694dfda928e4467593e073656 `
  -BaselineOnly `
  -OutputDirectory "$env:RUNNER_TEMP\garnet2349-preflight-results"

# Full comparison, after the coordinator has prepared the candidate source.
pwsh -NoProfile -File C:\validation-assets\Run-Validation.ps1 `
  -RepoRoot $env:GITHUB_WORKSPACE `
  -CandidateSourcePath "$env:GITHUB_WORKSPACE\libs\server\TLS\CertificateUtils.cs" `
  -BaseSha 5cc8f3f50aa57ed694dfda928e4467593e073656 `
  -OutputDirectory "$env:RUNNER_TEMP\garnet2349-comparison-results"
```

Each output directory must be new and outside `RepoRoot`. If omitted, a unique results directory is created under `RUNNER_TEMP` (or the process temp directory). The planned candidate preserves the default importer and retries `MachineKeySet` only on Windows for `CryptographicException.HResult == 0x80070002`; the harness does **not** manufacture that patch. The supplied source changed during preparation; both the captured candidate and the original base compiled locally. Exact locally compiled source hashes are in `LOCAL-VALIDATION.json`; every Windows run independently hashes its copied sources.

## What a run proves

The script creates one random temporary local account with ordinary Users membership. Its random synthetic password, account name, and separate synthetic PFX password stay in process memory/environment; GitHub masking commands register them before use. Nothing writes them to `GITHUB_ENV`, command-line arguments, transcripts, source, or result files. Do not enable PowerShell tracing/transcription or collect process dumps.

The harness obtains a `SafeAccessTokenHandle` using `LogonUserW(LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT)` and uses `WindowsIdentity.RunImpersonatedAsync`. It verifies the effective SID is the temporary SID and differs from the runner, that `HKU\SID` and `HKU\SID_Classes` are absent, that there is no `ProfileList\SID` registration, and that no account-named profile directory (including Windows suffix variants) exists under the configured profiles root. Checks run before/after each case and across TLS awaits. The JSON labels the profile SID separately from the effective SID and reports the runner's HKU hive presence. Registry/directory observations briefly revert to the runner so access denial cannot be misread as absence; imports, key signing, and TLS run under the tested identity. Failure to establish or retain this context is a nonzero failure, never a skip.

No profile is loaded/created, no service or task is installed, and no key-store ACL, security policy, trust store, or other global setting is edited. Only the fixture directory gets traversal/read permission for the temporary SID, and fixture files get read permission. The temporary account gets no administrator membership. The normal runner token remains unchanged.

One locally generated RSA self-signed certificate has SAN `localhost`/`127.0.0.1` and server-auth EKU. Identical fixture bytes are used in baseline and candidate, normal and profileless runs:

| Case | Baseline, normal | Baseline, profileless | Candidate, both identities |
|---|---|---|---|
| Password-protected PFX | Key + TLS pass | Import throws crypto `0x80070002` | Key + TLS pass |
| Separate PEM certificate/key | Key + TLS pass | Same exact import failure | Key + TLS pass |
| Combined PEM | Key + TLS pass | Same exact import failure | Key + TLS pass |
| Combined PEM renamed `.pfx` | Key + TLS pass | Same exact import failure | Key + TLS pass |
| Missing file | File-not-found | File-not-found | File-not-found |
| Wrong password / malformed PFX | Crypto rejection | Crypto rejection | Crypto rejection |
| Mismatched PEM key | Crypto/argument rejection | Crypto/argument rejection | Crypto/argument rejection |

A generic exception does not count as success. Fixture readability is checked separately. Negative controls must fail during import with the expected exception category; wrong-password, malformed-PFX and mismatched-key controls cannot pass merely by throwing `0x80070002`. Every successful positive import must expose the expected certificate/private key, sign and verify a random challenge, and complete a TLS 1.2 `TcpListener`/`SslStream` loopback handshake plus bidirectional payload. The client accepts only the temporary certificate's exact SHA-256 fingerprint; revocation checks and session resumption are disabled. No DNS lookup or remote connection is made by the tests.

Each case uses a fresh process to avoid `SslStream` credential-cache reuse between identities or formats. A full comparison runs 32 cases; preflight runs 16. TLS has a 15-second deadline plus 5 seconds for cancellation/disposal, and each case process has a 60-second watchdog. Builds have a 240-second watchdog. The runner terminates/reaps a timed-out child before cleanup; inability to reap is an infrastructure failure, never a completed validation. Normal paths await both TLS tasks. The account, fixtures, copied sources, binaries, and CLI state are removed in `finally`; cleanup errors override any passing result. Imported certificate/key handles are disposed; the harness does not set `PersistKeySet` or add certificates to stores.

## Results and exit codes

Upload **only** `summary.json`, `baseline.json`, and (for comparisons) `candidate.json` from the results directory. Per-build files are arrays of per-case summaries, including OS/.NET runtime, exact source/harness SHA-256, identity/profile snapshots, stage, expected/actual outcome, private-key/TLS results, exception types, HRESULTs, and native logon errors. Fingerprints are identifiers, not certificate contents. No certificate, private-key, password, exception-message, or stack data is emitted. Completed case results survive later test failures; the top-level summary is authoritative for completeness and cleanup.

| Exit | Meaning |
|---|---|
| `0` | All required cases passed and cleanup succeeded. **Preflight means baseline reproduced only; no candidate was tested.** Full comparison means all four baseline profileless failures reproduced and the candidate fixed all four while controls passed. |
| `1` | Validation failed: a control failed, identity changed during a case, or the candidate could not import/sign/handshake (including a failed machine-key fallback). |
| `2` | Inconclusive: baseline did not reproduce the exact import-stage `0x80070002` for every valid format, while controls/context checks passed. Never interpret this as evidence of a fix. |
| `3` | Infrastructure/context setup, build, timeout, missing/inconsistent summary, or cleanup failure. No validation claim. |

Failure takes precedence over inconclusive when both occur. All normal controls must pass in both builds, and all profileless checks must hold. No result is silently skipped. The script reports a safe failure phase and exception type/HRESULT rather than potentially sensitive exception text.

**Environment limitation:** `windows-2022` is Windows Server 2022; the original report was on Windows Server 2019. A pass establishes behavior only on the recorded runner/SDK/runtime. If the baseline succeeds, fails with another HRESULT, or the candidate's machine-key import also fails, this harness deliberately returns nonzero. It cannot claim Server 2019 reproduction or validation of the candidate's non-Windows retry guard.

Local preparation was limited to static review, PowerShell parsing, and compilation on macOS with the existing SDK from `/tmp/garnet2349-env.sh` (.NET SDK 10.0.403). **No Windows test has been run here.** The first local SDK invocation attempted development-certificate initialization and reported a macOS crypto error; subsequent invocations and the runner explicitly disable that initialization. No Mac user was created and no production checkout was changed.

API references: [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw), [profile loading under impersonation](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks), [RunImpersonatedAsync](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.runimpersonatedasync?view=net-10.0), and [.NET SslStream credential handling](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Security/src/System/Net/Security/SslStream.Protocol.cs).
