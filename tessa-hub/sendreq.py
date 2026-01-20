#!/usr/bin/env python3
import argparse
import datetime
import os
import subprocess
import sys
import threading
import json



def write_request_file(wgid, stacode, msg_str, req_dir, debug=False):

    ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H%M%S')
    fn = f'req_{wgid}_{stacode}_{ts}.json'
    filepath = os.path.join(req_dir, fn)
    os.makedirs(req_dir, mode=0o664, exist_ok=True)
    if debug:
        print(f'Writing request file to {filepath}')
    with open(filepath, 'w') as f:
        f.write(msg_str+'\n')

    return filepath


def rsync_req_file(req_file_local, req_file_wg, wg_host, debug=False) -> bool:
# def run_rsync(src_root, dest, relpaths) -> None:
    """
    Use rsync to send the request file to the waveglider host
    Return True if successful, False if error
    """

    if not req_file_local or not os.path.isfile(req_file_local):
        print('Local request file {} does not exist.'.format(req_file_local))
        return False

    if not req_file_wg:
        print('Remote request file path must be specified.')
        return False

    if not wg_host:
        print('Waveglider hostname or IP must be specified.')
        return False

    if debug:
        print(f'rsyncing request file {req_file_local} to waveglider host {wg_host}:{req_file_wg}')


    cmd = [
        "rsync",
        "-vptog",
        "--partial",
        "--partial-dir=.rsync-tmp",
        "--delay-updates",
        "--timeout=30",
        "--itemize-changes",
        "--chown=tessa:tessagroup",
        "--chmod=D2775,F0664",
        req_file_local,
        f'{wg_host}:{req_file_wg}'
    ]

    if debug:
        print('rsync cmd: ', ' '.join(cmd))

    try:
        # Equivalent to subprocess.run(..., check=True) for this use case
        # out = subprocess.check_output(cmd) ###, stderr=subprocess.STDOUT)
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f'rsync failed with return code {res.returncode}')
            print(f'rsync output: {res.stdout}')
            return False
        
        if debug:
            print('rsync output:', res.stdout)

        return True
    
    except Exception as e:
        print(f'rsync failed: {e}')
        return False


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='construct and send data request to topic "tessa/request" and listenf or ACK on topic "tessa/reqack"')
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    parser.add_argument("wgid", action="store", help="Waveglider ID (e.g. 'WG1' and Env var TESSA_WG1_HOST must be defined", required=True)
    parser.add_argument("sta", action='store', help='station code to request data from', required=True)
    parser.add_argument("beg", action='store', help='Start time (iso8660) of requested data segment', required=True)
    parser.add_argument("end", action='store', help='End time (iso8660) of requested data segment', required=True)
    parser.add_argument("chnbm", action='store', help='Channel bitmap value (4 low order bits: 1-15)', required=True)

    args = parser.parse_args()

    debug = args.debug
    wgid = args.wgid.upper()
    sta = args.sta.upper()
    beg = args.beg.upper()
    if not beg.endswith('Z'):
        beg += 'Z'
    begep = datetime.datetime.fromisoformat(beg).timestamp()
    end = args.end.upper()
    if not end.endswith('Z'):
        end += 'Z'
    endep = datetime.datetime.fromisoformat(end).timestamp()
    chnbm = int(args.chnbm)

    rid = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

    msg = {
        'rid': rid,
        'sta': sta,
        'beg': begep,
        'end': endep,
        'chnbm': chnbm,
        'reqts': datetime.datetime.now().isoformat(timespec='seconds').replace(':', '')
    }

    msg_jstr = json.dumps(msg)
    print(f'msg_str: {msg_jstr}')

    TESSA_HUB_DATA_ROOT = os.getenv('TESSA_HUB_DATA_ROOT')
    if not TESSA_HUB_DATA_ROOT:
        print('ERROR: TESSA_HUB_DATA_ROOT env var does not exist. Quitting...', file=sys.stderr)
        sys.exit(1)

    TESSA_WG_DATA_ROOT = os.getenv('TESSA_WG_DATA_ROOT')
    if not TESSA_WG_DATA_ROOT:
        print('ERROR: TESSA_WG_DATA_ROOT env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    wg_host = os.getenv(f'TESSA_{wgid}_HOST')
    if not wg_host:
        print(f'ERROR: TESSA_{wgid}_HOST env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    req_dir_local = os.path.join(TESSA_HUB_DATA_ROOT, wgid, sta, 'requests')
    req_file_wg = os.path.join(TESSA_WG_DATA_ROOT, sta, 'requests')
    req_file_local = write_request_file(wgid, sta, msg_jstr, req_dir_local, False)

    ok = rsync_req_file(req_file_local, req_file_wg, wg_host, debug)
    if ok:
        print('Request transferred successfully')
    else:
        print('ERROR transferring requested file ()')




