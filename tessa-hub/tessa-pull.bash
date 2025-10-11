#!/bin/bash

set -o nounset   # abort on unbound variable
set -o pipefail  # don't hide errors within pipes

export PATH=$PATH:/usr/local/bin/:usr/local/tessa/bin/:/home/tessa/dev/tessa/

s3sync_log_fn=`date +%Y-%m-%d-%H-%M-%S`_s3synclog.txt
s3sync_log_fullfn="${TESSA_WG_DATA_ROOT}/${s3sync_log_fn}"
echo "SYNC FILE LOG: ${s3sync_log_fullfn}"

aws s3 sync s3://tessa-wg-data ${TESSA_WG_DATA_ROOT} > ${s3sync_log_fullfn}

# exit and delete sync log file if no files found to be synced
if [ ! -s "$s3sync_log_fullfn" ]; then
  echo "No sync log info for: ${s3sync_log_fullfn}"
  rm -f "$s3sync_log_fullfn"
  exit 0
fi

/home/tessa/dev/tessa/tessa-obs-suite/tessa-hub/tessa-pull.py "${s3sync_log_fullfn}"

fnroot=$(basename "${s3sync_log_fullfn}" .txt)
filelist_fn="${TESSA_WG_DATA_ROOT}/${fnroot}_ds_list.txt"
echo "DATASELECT FILELIST: $filelist_fn"

echo
cat $filelist_fn
echo

dataselect -vv -A ${TESSA_HUB_DATA_ROOT}/ms/%n/%s/%Y/%j/%n.%s.%l.%c.%Y.%j.ms -Ps @$filelist_fn
