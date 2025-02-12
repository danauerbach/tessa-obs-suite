#!/usr/bin/env python3

import argparse
# import base64
# import concurrent
from datetime import datetime, timezone
# import glob
import os
# from pathlib import Path, PurePath
# import struct
import sys
# import tempfile
# import time
# import json
# import boto3

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('s3synclog', type=str, action='store')
    args = parser.parse_args()

    s3synclog = args.s3synclog
    if s3synclog:

        print(f'sync log file: {s3synclog}')

        ms_filelist = []

        with open(s3synclog, 'rt') as logfl:

            line : str = ''
            for line in logfl:
                if line.startswith('download:'):
                    parts = line.split()
                    fn = os.path.abspath(parts[3])
                    print(fn)
                    if fn.endswith('.ms') and ('processing-failed' not in fn):
                        ms_filelist.append(fn)
                    if fn.endswith('.pegraw'):
                        print(f'got a pegraw: {fn}')

        print(f'ms files found: {ms_filelist}')

        # Now save list of files for dataselect
        dataselect_list_fn = os.path.splitext(s3synclog)[0] + '_ds_list.txt'
        with open(dataselect_list_fn, 'wt') as dsfl:
            for fn in ms_filelist:
                dsfl.write(fn + '\n')

