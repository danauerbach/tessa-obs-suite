#!/usr/bin/env python3
import argparse
import base64
import json
from pathlib import Path
import struct
import sys

#from awscrt import mqtt, http
#from awsiot import mqtt_connection_builder

from utils.rap import RAPPacket

### AWS IOT CONSTANTS
#CERT = '../../awstests/tessa-wg-dev.cert.pem'
#KEY = '../../awstests/tessa-wg-dev.private.key'
#ENDPOINT = 'a1cizoe0dy9v99-ats.iot.us-east-2.amazonaws.com'
#PORT = 8883
#ROOT_CA = None
#CLIENT_ID = 'binary_sender'
#TOPIC = 'tessa/data/raw'

### RAP CONSTANTS
SYNC_BYTES = b'PT02'

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


def print_packet_info(rappkt, userdata, debug=False):

    global print_cnt
    print_cnt += 1
    pkt_info = rappkt.header_str()
    print(pkt_info)
    if debug:
        print(rappkt.app_pkt_info)

def process_file(filename : str, handlers : list, debug=False):

    if debug:
        print(f'Processing file: {filename}.')

    with open(fn, 'rb') as pegfl:

        seq_num : int = -1
        pkt_start : bytes = b''
        pkt: bytes = b''
        offset : int = 0
        found_first_packet : bool = False

        while True:

            offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

            if offset == -1:
                if not found_first_packet and debug:
                    print(f"No sync bytes ({SYNC_BYTES}) found in file {filename}.")
                break

            pkt_start = pegfl.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.
            
            found_first_packet = True
            
            if (len(pkt_start) == 14) and (pkt_start[:4] == b'PT02'):

                pkt_segment_len = struct.unpack_from('!H', pkt_start, 12)[0] + 4

                if debug:
                    print(f'SEGMENT SEQNUM:                   {struct.unpack_from("!H", pkt_start, 6)[0]}')
                    print(f'SEGMENT PAYLOAD LEN (+4 for both crc): {pkt_segment_len}')

                payload = pegfl.read(pkt_segment_len)
                if payload:
                    pkt = pkt_start + payload
                    # set offest to next expected SYNC_BYTES position
                    offset += len(pkt)

            else:
                if pkt_start:
                    print(f'UNEXPECTED READ: {pkt_start}')
                    print('Looking for SYNC Bytes ("PT02")...')

                    offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

                    if offset == -1:
                        if debug:
                            print(f"No sync bytes ({SYNC_BYTES}) found in rest of the file {filename}.")
                else:
                    if debug:
                        print('Error reading file {filename}.')
                break

            if len(pkt) > 0:

                rappkt = RAPPacket(pkt[4:], debug)
                if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                    print(f'{rappkt.packet_seqnum - seq_num:>9} PACKETs MISSING')

                for handler in handlers:
                    handler["method"](rappkt, handler['userdata'], debug)
                # pkt_info = rappkt.header_str()
                # print(pkt_info)

        if pegfl.tell() < Path(filename).stat().st_size:
            print(f'File {filename} not read to the end!!!')


def process_pegraw_file(filename : str, handlers : list, debug=False):

    # if debug:
    print(f'###Processing file: {filename}.')

    with open(fn, 'rb') as pegfl:

        SYNC_BYTES = '{"'

        seq_num : int = -1
        pkt_start : bytes = b''
        pkt : bytes = b''
        offset : int = 0
        found_first_packet : bool = False

        data_s = pegfl.read().decode(encoding="ASCII")

        while data_s:

            # offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)
            offset = data_s.find(SYNC_BYTES)

            if offset == -1:
                if not found_first_packet and debug:
                    print(f"No sync bytes ({SYNC_BYTES}) found in file {filename}.")
                break
            found_first_packet = True
            
            json_len = data_s.find('"}') + 2 - offset

            pkt_json = data_s[:json_len]
            jrec = json.loads(pkt_json)
            pkt64 = jrec['pegpkt']
            pegpkt = base64.b64decode(pkt64)
            
            data_s = data_s[json_len:]

            if len(pegpkt) > 0:

                rappkt = RAPPacket(pegpkt[4:], debug)
                if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                    print(f'{rappkt.packet_seqnum - seq_num:>9} PACKETs MISSING')

                for handler in handlers:
                    handler["method"](rappkt, handler['userdata'], debug)


def teardown_print(userdata):

    print(f'Printed {print_cnt} records.')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="list Pegasus raw packets in a file(s)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    parser.add_argument("--json", "-j", action="store_true", help="Read PEGRAW in mqtt-json file(s)")
    parser.add_argument("fileglob", action="store", nargs='+', help="filename(s) to read")

    args = parser.parse_args()
    filelist = args.fileglob
    debug = args.debug
    rec_cnt = 0
    print_cnt = 0
    if args.debug:
        print(f'FILES: {filelist}')

    if type(filelist) == str:
        filelist = [filelist]

    handlers = [{
                'userdata': {},
                'setup': None, 
                'method': print_packet_info,
                'teardown': teardown_print

            }
    ]

    for handler in handlers:
        if handler.get('setup'):
            if handler['setup']:
                handler['setup'](handler['userdata'])

    for fn in filelist:
            
            if not Path(fn).exists():
                if debug:
                    print(f'FILE NOT FOUND: {fn}. Skipping...')
                continue
            fn = Path(fn).absolute()
            if args.json:
                process_pegraw_file(fn, handlers, debug)
            else:
                process_file(fn, handlers, debug)

    for handler in handlers:
        if handler.get('teardown'):
            if handler['teardown']:
                handler['teardown'](handler['userdata'])


