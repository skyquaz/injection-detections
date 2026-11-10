# injection-detections

[![rules](https://github.com/skyquaz/injection-detections/actions/workflows/rules.yml/badge.svg)](https://github.com/skyquaz/injection-detections/actions/workflows/rules.yml)

Sigma rules for Windows process injection, tested against real attack logs on every commit.

These rules are the event-log side of [procsweep](https://github.com/skyquaz/procsweep), which looks for the same artifacts in live process memory. Every rule is run with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) over the 278 Sysmon and Security logs in [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). The matches must equal a hand-reviewed baseline ([tests/expected.yml](tests/expected.yml)), so CI fails as soon as a change loses a detection or starts firing somewhere new.

## Rules

| Rule | Level | Logic | ATT&CK |
|---|---|---|---|
| [Remote Thread Started Outside Any Loaded Module](rules/create_remote_thread_unbacked_start.yml) | high | Sysmon 8 with an empty `StartModule`: the new thread starts in memory with no image file behind it | T1055 |
| [Process Opened With Injection Rights From Unbacked Code](rules/proc_access_unbacked_caller_injection_rights.yml) | high | Sysmon 10 with an `UNKNOWN(...)` frame in `CallTrace` and injection-capable `GrantedAccess`, excluding .NET JIT callers | T1055 |
| [Process Opened With Injection Rights From .NET JIT Code](rules/proc_access_unbacked_caller_codegen_host.yml) | low (hunting) | Same pattern when the caller is PowerShell, IIS, or the call stack runs through the .NET runtime | T1055 |
| [PowerShell Engine Loaded Into An Unusual Process](rules/image_load_powershell_engine_unusual_process.yml) | medium | Sysmon 7: `System.Management.Automation.dll` loaded by a process that is not a PowerShell host (unmanaged PowerShell injection) | T1059.001, T1055 |

Tags follow ATT&CK v20, where TA0005 is named Stealth.

## Results on EVTX-ATTACK-SAMPLES

| Rule | Level | Samples matched | Events matched |
|---|---|---|---|
| Remote Thread Started Outside Any Loaded Module | high | 8 | 101 |
| Process Opened With Injection Rights From Unbacked Code | high | 11 | 17 |
| Process Opened With Injection Rights From .NET JIT Code | low | 12 | 21 |
| PowerShell Engine Loaded Into An Unusual Process | medium | 1 | 1 |

Every match was reviewed by hand. They include Meterpreter migration and hashdump, PSInject, Invoke-ReflectivePEInjection, KeeThief, process hollowing, exploit shellcode in Internet Explorer and several UAC bypasses. The full list with one-line notes is in [tests/expected.yml](tests/expected.yml).

The remote-thread rule also stays quiet on the legitimate remote threads in the corpus: a debugger break-in (`ntdll!DbgUiRemoteBreakin`) and a thread started inside a loaded DLL both have a start module and are not reported.

## Why the process-access rule is split in two

81 of the 149 process-access events (Sysmon 10) in the corpus have an `UNKNOWN(...)` frame in their call stack, meaning some caller has no module behind it. Treating all of them as injection would be noisy:

- **43 only request read access**, for example `0x1410` from Meterpreter's process listing. They are discovery, not injection, so neither rule matches them.
- **21 come from JIT-compiled .NET code.** PowerShell and ASP.NET produce `UNKNOWN` frames every time a script or web app starts a child process. These go to the low-severity hunting rule. Two of them come from PowerShell processes for which Sysmon could not resolve `SourceImage` at all; they are still recognised because the call stack runs through the .NET runtime (`mscorwks.dll`, `clr.dll` or `coreclr.dll`).
- **17 come from native code with no module.** That is shellcode, a reflectively loaded payload or an exploit, and it is what the high-severity rule reports.

procsweep makes the same distinction in memory, where executable heaps in code-generating processes are reported at a lower severity.

## Running it locally

```
pip install sigma-cli pyyaml
sigma check --fail-on-issues rules

git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES samples
# download chainsaw and mappings/sigma-event-logs-all.yml from https://github.com/WithSecureLabs/chainsaw/releases
python tests/evaluate.py --chainsaw path/to/chainsaw --mapping sigma-event-logs-all.yml --data samples --print-hits
```

## Limitations

- The corpus contains attack recordings only. The rules have no measured false-positive rate on benign enterprise telemetry yet; the `falsepositives` field of each rule lists the expected sources.
- The rules need a Sysmon configuration that logs events 7, 8 and 10 for the relevant processes. Many configurations filter event 10 heavily because of its volume.
- Process hollowing, herpaderping and doppelgänging are not covered. They are better caught with Sysmon event 25 (ProcessTampering), for which the corpus has no samples.

## Credits

Test data: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden (GPL-3.0, downloaded at test time and not redistributed here). Evaluation engine: [Chainsaw](https://github.com/WithSecureLabs/chainsaw) by WithSecure. Rule format: [Sigma](https://github.com/SigmaHQ/sigma).

## License

MIT, see [LICENSE](LICENSE).
