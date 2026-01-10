#!/usr/bin/env python3
import argparse
import datetime
import glob
import logging
import os
from pathlib import Path
import struct

from concurrent_log_handler import ConcurrentRotatingFileHandler

from utils.const import SYNC_BYTES, STA_CHAN_CODE_MAP, TESSA_NETCODE, TESSA_LOCCODE
from utils.rap import RAPPacket
from utils.ms_manager import MSManager


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

def convert_rap2ms(rappkt : RAPPacket, net, sta, loc : str, stachanmap : dict, msmgr : MSManager):

    sample_rate = rappkt.steim2["sr"]
    start_byte = rappkt.steim2["byte_start"]
    end_byte = start_byte + rappkt.steim2["byte_cnt"] - 1

    logger.info(f'starttime={rappkt.ts_timestamp_ns}   sta={sta.lower()}    sr={str(round(sample_rate))}    channdx={rappkt.chan_ndx}')

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
        logger.error(f'UNEXPECTED data_packet_count: {rappkt.data_packet_count}. Skipping record...')
        return
    
    # print(f"data start: {ts_start_byte}; data end: {ts_end_byte}; recsize: {ms_recsize}; sample cnt: {rappkt.steim2['sample_cnt']}")
    # print(f'MS MSG: {msmgr}')
    msmgr.add_data(rappkt.app_payload[start_byte:end_byte+1], 
                    rappkt.ts_timestamp_ns,
                    rappkt.steim2['sample_cnt'], 
                    ms_recsize,
                    MSManager.TS_ENCODING_STEIM2)
    
def process_file(filename : str, sta_code: str, msmgr: MSManager, debug=False):

    logger.info('Processing file: {}.'.format(filename))
    if debug:
        print('Processing file: {}.'.format(filename))

    with open(filename, 'rb') as pegfl:

        seq_num : int = -1
        pkt_start : bytes = b''
        pkt: bytes = b''
        offset : int = 0
        found_first_packet : bool = False

        while True:

            offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

            if offset == -1:
                if not found_first_packet and debug:
                    logger.warning("No sync bytes ({}) found in file {}.".format(SYNC_BYTES, filename))
                break

            pkt_start = pegfl.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.
            
            found_first_packet = True
            
            if (len(pkt_start) == 14) and (pkt_start[:4] == b'PT02'):

                pkt_segment_len = struct.unpack_from('!H', pkt_start, 12)[0] + 4

                if debug:
                    logger.debug('SEGMENT SEQNUM:                   {}'.format(struct.unpack_from("!H", pkt_start, 6)[0]))
                    logger.debug('SEGMENT PAYLOAD LEN (+4 for both crc): {}'.format(pkt_segment_len))
                payload = pegfl.read(pkt_segment_len)
                if payload:
                    pkt = pkt_start + payload
                    # set offest to next expected SYNC_BYTES position
                    offset += len(pkt)

            else:
                if pkt_start:
                    logger.warning('UNEXPECTED READ: {}'.format(pkt_start))
                    logger.warning('Looking for SYNC Bytes ("PT02")...')

                    offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

                    if offset == -1:
                        if debug:
                            logger.warning("No sync bytes ({}) found in rest of file {}.".format(SYNC_BYTES, filename))
                else:
                    if debug:
                        logger.warning('Error reading file {filename}.')
                break

            if len(pkt) == (14 + pkt_segment_len):

                rappkt = RAPPacket(pkt[4:], debug)
                if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                    logger.warning('{} PACKETs MISSING'.format(rappkt.packet_seqnum - seq_num))

                if rappkt.is_timeseries():
                    convert_rap2ms(rappkt, TESSA_NETCODE, sta_code, TESSA_LOCCODE, STA_CHAN_CODE_MAP, msmgr)


                # for handler in handlers:
                #     handler["method"](rappkt, handler['userdata'], debug)
                # pkt_info = rappkt.header_str()
                # print(pkt_info)

            else:
                logger.warning('[file: {}] Skipping incomplete packet.'.format(filename))

        if pegfl.tell() < Path(filename).stat().st_size:
            logger.warning('File {} not read to the end!!!'.format(filename))


def ms_handler(data, handlerdata):
    '''This callback function is used by mstracelist 
    to collect miniseed records into a list.
    '''

    handlerdata["ms_recs"].append(bytes(data))


def move_file(srcfile: str, subdir: str):

    p = Path(srcfile)
    dest_dir = p.parent / subdir
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / p.name

    p.rename(dest_file)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Convert Pegasus raw packet files to Miniseed")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    parser.add_argument("starawdir", action="store", help="Root station directory containin raw .peg files")
    # peg_sta_raw_dir is the 'raw' directory under the station directory and 
    # cointains the dated (in 'yyyy-mm-dd' format) subdirectories with .peg files collected 
    # on those respective dates

    args = parser.parse_args()
    debug = args.debug
    peg_sta_raw_dir = args.starawdir

    logger = logging.getLogger(__name__)
    handler = ConcurrentRotatingFileHandler('peg2ms.log', maxBytes=10*1024*1024, backupCount=50)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(processName)s %(name)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)



    p = Path(peg_sta_raw_dir)
    stacode = p.parts[-2]

    peg_sta_dir = p.resolve().parent
    print(f'Station directory: {peg_sta_dir}')

    peg_file_glob: str = f'{peg_sta_raw_dir}/????-??-??/*.peg'

    logger.debug(f'Processing station .peg files: {peg_file_glob}')
    if debug:
        print(f'Processing station .peg files: {peg_file_glob}')

    peg_files_list: list = glob.glob(peg_file_glob)

    ms_dir = os.path.normpath(f'{peg_sta_dir}/ms')
    os.makedirs(ms_dir, mode=0o775, exist_ok=True)

    ms_file = f"{ms_dir}/{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S.%f')}.ms"

    logger.debug(f'Output Miniseed file: {ms_file}')

    msmgr = MSManager()

    for fn in peg_files_list:

        process_file(fn, stacode, msmgr, debug)
        move_file(fn, 'converted')


    handler_msrec_list = {
        'ms_recs': []
    }

    _, rec_cnt = msmgr.pack_and_flush_with_handler(ms_handler, handler_msrec_list)

    if rec_cnt > 0:
        with open(ms_file, 'wb') as msfl:
            for rec in handler_msrec_list['ms_recs']:
                msfl.write(rec)

        logger.info(f'Wrote {len(handler_msrec_list["ms_recs"])} Miniseed records to file: {ms_file}')
    else:
        logger.warning(f'NO MINISEED RECORDS to write')