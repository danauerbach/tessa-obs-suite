#!/usr/bin/env bash
set -euo pipefail

LOCKFILE="/tmp/`basename $0`.lock"

exec 200>"$LOCKFILE"
flock -n 200 || { echo "Another instance is already running." >&2; exit 1; }


usage() {
  cat >&2 <<'EOF'
Usage: process_pegs.bash <WG> 

WG:       Wave Glider ID / must match ENV VAR TESSA_WG_ID uniquely configured on each waveglider

Examples:
  process_pegs.bash wg1
  process_pegs.bash wg2
EOF
  exit 2
}

# Require exactly two positional args
[[ $# -eq 2 ]] || usage

WG="${1^^}"       # lowercase
STATION="${2^^}"  # uppercase

WG_ROOT="${TESSA_HUB_DATA_ROOT}/${WG}"
STA_ROOT="${WG_ROOT}/${STATION}"
MS_TMP_PATH="${STA_ROOT}/mstmp"

umask 0002


### CRONTAB ENTRY:
### */5 * * * * root flock -n /run/tessa-rsync.lock /usr/local/sbin/tessa-rsync-pull.sh >>/var/log/tessa-rsync-pull.log 2>&1

MS_FILE="${MS_TMP_PATH}/$(date -u +'%Y-%m-%dT%H-%M-%S.%3N').ms"

cd /home/tessa/dev/tessa
source venv/bin/activate

cd tessa-obs-suite
./peg2ms.py "${STA_ROOT}" "${MS_FILE}"

mkdir -p "${MS_TMP_PATH}/archived/"

for msf in "${MS_TMP_PATH}"/*.ms; do
    [ -e "$msf" ] || continue
    dataselect -v -A "${TESSA_HUB_DATA_ROOT}/ms/%n/%s/%Y/%j/%n.%s.%l.%c.%Y.%j.ms" -Ps "${msf}"
    mv "$msf" "${MS_TMP_PATH}/archived/"
done
