#!/usr/bin/env python3
import argparse
import datetime
import os
import subprocess
import sys
import threading
import json



def write_request_file(wgid, stacode, msg_str, req_dir, req_fn, debug=False):

    if debug:
        print(f'Writing request file to {filepath}')

    os.makedirs(req_dir, mode=0o775, exist_ok=True)
    filepath = os.path.join(req_dir, req_fn)

    with open(filepath, 'wt') as reqfl:
        reqfl.write(msg_str)

    return filepath


def rsync_req_file(wg_host, req_file_local, req_dir_wg, debug=False, sshport=22) -> bool:
    """
    Use rsync to send the request file to the waveglider host
    Return True if successful, False if error
    """

    if not req_file_local or not os.path.isfile(req_file_local):
        print('Local request file {} does not exist.'.format(req_file_local))
        return False

    if not req_dir_wg:
        print('Remote request file path must be specified.')
        return False

    if not wg_host:
        print('Waveglider hostname or IP must be specified.')
        return False

    if debug:
        print(f'rsyncing request file {req_file_local} to waveglider host {wg_host}:{req_dir_wg}')

    cmd = [
        "scp",
        "-P {}".format(sshport),
        req_file_local,
        f'{wg_host}:{req_dir_wg}'
    ]


    if debug:
        print('transfer cmd: ', ' '.join(cmd))

    try:
        # Equivalent to subprocess.run(..., check=True) for this use case
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, text=True)
        if res.returncode != 0:
            print(f'transfer failed with return code {res.returncode}')
            print(f'transfer output: {res.stdout}')
            return False
        
        if debug:
            print('transfer output:', res.stdout)

        return True
    
    except Exception as e:
        print(f'rsync failed: {e}')
        return False


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='construct and send data request to topic "tessa/request" and listenf or ACK on topic "tessa/reqack"')
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    parser.add_argument("wgid", action="store", help="Waveglider ID (e.g. 'WG1' and Env var TESSA_WG1_HOST must be defined")
    parser.add_argument("sta", action='store', help='station code to request data from')
    parser.add_argument("beg", action='store', help='Start time (iso8660) of requested data segment')
    parser.add_argument("end", action='store', help='End time (iso8660) of requested data segment')
    parser.add_argument("chnbm", action='store', help='Channel bitmap value (4 low order bits: 1-15)')
    parser.add_argument("--port", "-p", action="store", type=int, default=22, help="Custom SSH port (default: 22)")
    args = parser.parse_args()

    debug = args.debug
    sshport = args.port
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

    req_fn = "{}_{}_{}_{}.reqXXXX".format(wgid, sta.upper(), chnbm, rid)
    req_dir = os.path.join(TESSA_HUB_DATA_ROOT, wgid, sta, 'requests')

    msg_str = "{}, {}, {}, {}, {}, {}\n".format(rid, wgid, sta, chnbm, beg, end)
    if debug:
        print(f'msg_str: {msg_str}')

    req_file_local = write_request_file(wgid, sta, msg_str, req_dir, req_fn, debug=debug)
    req_dir_wg = os.path.join(TESSA_WG_DATA_ROOT, sta, 'requests') + '/'

    ok = rsync_req_file(wg_host, req_file_local, req_dir_wg, debug=debug, sshport=sshport)
    if ok:
        print('Request transferred successfully')
    else:
        print('ERROR transferring requested file ()')




