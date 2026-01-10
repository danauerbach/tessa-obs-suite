#!/usr/bin/env bash
set -euo pipefail

LOCKFILE="/tmp/`basename $0`.lock"

exec 200>"$LOCKFILE"
flock -n 200 || { echo "Another instance is already running." >&2; exit 1; }


usage() {
  cat >&2 <<'EOF'
Usage: script.sh <WG> <STATION>

WG:       Wave Glider Code / WB#
STATION:  Station code (uppercase letters/digits; must start with a letter; 2-8 chars)

Examples:
  script.sh wg1 TES1
  script.sh wg2 XTES3
EOF
  exit 2
}

# Require exactly two positional args
[[ $# -eq 2 ]] || usage

WG="${1,,}"       # lowercase
STATION="${2^^}"  # uppercase

SRC_ROOT="/mnt/XDATA/tessa"
DST_ROOT="${TESSA_HUB_DATA_ROOT}/ms"
DST_PATH="${DST_ROOT}/${WG}/${STATION}"

umask 0002
# mkdir -p "$DST_ROOT/.rsync-partial"
# chmod 2775 "$DST_ROOT/.rsync-partial"

rsync -rt \
--partial \
--log-file="${DST_PATH}/rsync-changes.log" \
--delay-updates \
--timeout=30 \
--itemize-changes \
--chown=tessa:tessadata \
--chmod=D2775,F0664 \
tessa-"${WG}":"${SRC_ROOT}/${STATION}" "${DST_ROOT}/${WG}/"


### CRONTAB ENTRY:
### */5 * * * * root flock -n /run/tessa-rsync.lock /usr/local/sbin/tessa-rsync-pull.sh >>/var/log/tessa-rsync-pull.log 2>&1


./peg2ms.py -d ${WG} ${STATION} "${DST_PATH}"