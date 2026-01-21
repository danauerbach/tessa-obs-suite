#!/usr/bin/env python3
import argparse
import glob
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import json


def move_to_next_packet(iobuffer, sync_bytes, start_position=0):

    iobuffer.seek(start_position)  # Move to the start position
    while True:
        chunk = iobuffer.read(4096)  # Read the file in chunks
        if not chunk:
            break  # End of file
        index = chunk.find(sync_bytes)
        if index != -1:
            iobuffer.seek(start_position + index)
            return start_position + index
        start_position += len(chunk)  # Update position for the next chunk

    return -1  # Byte sequence not found


def move_file_to_sent(filepath: str):

    # move file to a 'sent' subdirectory of its current location
    fn = str(filepath)


    fdir = os.path.dirname(fn)

    sent_dir = os.path.join(fdir, 'SENT')
    os.makedirs(sent_dir, exist_ok=True)

    fname = os.path.basename(fn)
    save_fn = os.path.join(sent_dir, fname)

    print('XMITTER moving raw file {} to {}'.format(fn, save_fn))
    os.rename(fn, save_fn)


def run_rsync(src_root, dest, relpaths) -> None:
    """
    Use --files-from to avoid source tree walk.
    """
    if not relpaths:
        return

    print('src_root:', src_root)
    print('dest:', dest)
    print('number of files to rsync:', len(relpaths))

    try:
        # Build NUL-separated file list for rsync.
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
            list_path = tf.name
            for rp in relpaths:
                # rp should be a relative path in POSIX form (e.g. "a/b/c.txt")
                tf.write(rp.encode("utf-8") + "\n".encode("utf-8"))
                print('rsync file: {}'.format(rp))

        cmd = [
            "rsync",
            "-vrptog",
            "--files-from={}".format(list_path),
            "--partial",
            "--partial-dir=.rsync-tmp",
            "--delay-updates",
            "--timeout=30",
            "--itemize-changes",
            "--chown=tessa:tessadata",
            "--chmod=D2775,F0664"
        ]


        # Important: trailing slash on source root
        cmd.extend([src_root.rstrip("/") + "/", dest])

        print('cmd: ', ' '.join(cmd))

        # Equivalent to subprocess.run(..., check=True) for this use case
        out = subprocess.check_output(cmd) ###, stderr=subprocess.STDOUT)
        print('rsync out:', out)

    finally:
        if list_path:
            try:
                os.unlink(list_path)
            except OSError:
                pass



def interrupt_handler(signum, frame):

    print("shutting down...")
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, interrupt_handler)

    ENDPOINT = 'tessa-hub.ucsd.edu' ### MOVE TO ENVIRONMENT VARIABLE

    TESSA_HUB_DATA_ROOT = os.getenv('TESSA_HUB_DATA_ROOT')
    if not TESSA_HUB_DATA_ROOT:
        print('ERROR: TESSA_HUB_DATA_ROOT env var does not exist. Quitting...', file=sys.stderr)
        sys.exit(1)

    WG_DATA_ROOT_DIR = os.getenv('TESSA_WG_DATA_ROOT')
    if not WG_DATA_ROOT_DIR:
        print('ERROR: TESSA_DATA_ROOT env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    WG_ID = os.getenv('TESSA_WG_ID')
    if not WG_DATA_ROOT_DIR:
        print('ERROR: TESSA_DATA_ROOT env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)


    parser = argparse.ArgumentParser(description="list Pegasus raw packets in a file(s)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    # parser.add_argument("fileglob", action="store", nargs='+', help="filename(s) to read")

    args = parser.parse_args()
    debug = args.debug

    xfer_dirs = os.path.join(WG_DATA_ROOT_DIR, "*/raw/????-??-??/*.peg")

    dest_dir = 'tessa@{ENDPOINT}:{TESSA_HUB_DATA_ROOT}/{WG_ID}/'.format(
        ENDPOINT=ENDPOINT,
        TESSA_HUB_DATA_ROOT=TESSA_HUB_DATA_ROOT,
        WG_ID=WG_ID)

    while True:

        # get all files in: $WG_DATA_ROOT_DIR/<STACODE>/raw/<yyyy-mm-dd>/*.peg
        filelist = glob.glob(xfer_dirs)
        
        if filelist:

            filelist.sort()
            rel_filelist = [Path(p).relative_to(WG_DATA_ROOT_DIR).as_posix() for p in filelist]
            run_rsync(WG_DATA_ROOT_DIR, dest_dir, rel_filelist)

            if args.debug:
                print('FILES: {}'.format(filelist))

            for fn in filelist:

                if not Path(fn).exists():
                    if debug:
                        print('FILE NOT FOUND: {fn}. Skipping...'.format(fn=fn))
                    continue
                fn = Path(fn).absolute()
                move_file_to_sent(fn)

        time.sleep(15)

