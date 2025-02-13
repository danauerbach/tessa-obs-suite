#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import struct

from utils.const import STA_CHAN_CODE_MAP, TESSA_NETCODE, TESSA_LOCCODE
from utils.rap import RAPPacket
from utils.ms_manager import MSManager

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


def source_id(netcode, stacode, chancode, loccode : str) -> str:

    chanchars = "_".join(chancode)
    return f"FDSN:{netcode[:2]}_{stacode[:5]}_{loccode[:2]}_{chanchars}"

# def convert_rap2ms(rappkt : RAPPacket, net, sta : str, chanmap : dict, msmgr : MSManager):
def convert_rap2ms(rappkt : RAPPacket, net, sta, loc : str, stachanmap : dict, msmgr : MSManager):

    sample_rate = rappkt.steim2["sr"]
    ts_start_byte = rappkt.steim2["byte_start"]
    ts_end_byte = ts_start_byte + rappkt.steim2["byte_cnt"] - 1

    print(f'sta={sta.lower()}    sr={str(round(sample_rate))}    channdx={rappkt.chan_ndx}')

    msmgr.set_network(net.upper())
    msmgr.set_station(sta.upper())
    msmgr.set_channel(stachanmap[sta.lower()][str(round(sample_rate))][str(rappkt.chan_ndx)])
    msmgr.set_location(loc)
    msmgr.set_sample_rate(sample_rate)

    if rappkt.data_packet_count < 8:
        ms_recsize = 512
    elif rappkt.data_packet_count < 16:
        ms_recsize = 1024
    elif rappkt.data_packet_count < 32:
        ms_recsize = 2048
    elif rappkt.data_packet_count < 64:
        ms_recsize = 4096
    else:
        print(f'UNEXPECTED data_packet_count: {rappkt.data_packet_count}. Skipping record...')
        return
    
    # print(f'data start: {ts_start_byte}; data end: {ts_end_byte}; recsize: {ms_recsize}; sample cnt: {rappkt.steim2['sample_cnt']}')
    # print(f'MS MSG: {msmgr}')
    msmgr.add_data(rappkt.app_payload[ts_start_byte:ts_end_byte+1], 
                    rappkt.ts_timestamp_ns,
                    rappkt.steim2['sample_cnt'], 
                    ms_recsize,
                    MSManager.TS_ENCODING_STEIM2)
    

def ms_handler(data, handlerdata):
    '''Write buffer to the file handle in handler data.

    This callback function can be changed to do anything you want
    with the generated records.  For example, you could write them
    to a file, to a pipe, or send them over a network connection.
    '''
    handlerdata["ms_rec_list"].append(bytes(data))
    print(f'type of DATA: {type(data)}; first 20 bytes: {data[:20]}')


def process_file(pegfn : str, msfn : str, sta_code, debug=False):

    if debug:
        print(f'Converting timeseries in: {pegfn} to miniseed in {msfn}')

    msmgr = MSManager()

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
                    print(f"No sync bytes ({SYNC_BYTES}) found in file {pegfn}.")
                break
            
            found_first_packet = True
            
            pegfl.seek(offset)

            pkt_start = pegfl.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.

            if (len(pkt_start) == 14) and (pkt_start[:4] == b'PT02'):

                pkt_segment_len = struct.unpack_from('!H', pkt_start, 12)[0] + 4

                if debug:
                    print(f'SEGMENT SEQNUM:                   {struct.unpack_from('!H', pkt_start, 6)[0]}')
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
                            print(f"No sync bytes ({SYNC_BYTES}) found in rest of the file {pegfn}.")
                else:
                    if debug:
                        print('Error reading file {filename}.')
                break

            if len(pkt) > 0:

                rappkt = RAPPacket(pkt[4:], debug)
                print(f'Packet Details: {rappkt.packet_details()}')
                if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                    print(f'{rappkt.packet_seqnum - seq_num:>9} PACKETs MISSING')

                if rappkt.is_timeseries():
                    convert_rap2ms(rappkt, TESSA_NETCODE, sta_code, TESSA_LOCCODE, STA_CHAN_CODE_MAP, msmgr)


        if pegfl.tell() < Path(pegfn).stat().st_size:
            print(f'File {pegfn} not read to the end!!!')

    # with open(msfn, 'ab') as msfl:
        # samps, recs = msmgr.write(ms_handler, {'fh':msfl})
    handlerdata = {
        # "fh" : msfl,
        "ms_rec_list": []
    }
    samps, recs = msmgr.pack_and_flush_with_handler(ms_handler, handlerdata)

    with open(msfn, 'ab') as msfl:
        # print(f'{len(handlerdata["ms_rec_list"])} ms recs received')
        for rec in handlerdata["ms_rec_list"]:
            print(f'rec first 20 bytes: {rec[:20]}')
            msfl.write(rec)


    # print(f'samps: {samps}, recs: {recs}')

              
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="list Pegasus raw packets in a file(s)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    parser.add_argument('sta_code', action='store', description='station code for data', 
                        help='station code for data', defualt='XTES1')
    parser.add_argument("fileglob", action="store", nargs='+', help="filename(s) to read")

    args = parser.parse_args()
    sta_code = args.sta_code
    filelist = args.fileglob
    debug = args.debug

    if debug:
        print(f'FILES: {filelist}')

    if type(filelist) == str:
        filelist = [filelist]

    for fn in filelist:
            
            if not Path(fn).exists():
                if debug:
                    print(f'FILE NOT FOUND: {fn}. Skipping...')
                continue
            pegfn = Path(fn).absolute()
            fnbase, ext = os.path.splitext(fn)
            msfn = fnbase + '.ms'
            process_file(pegfn, msfn, sta_code, debug)

