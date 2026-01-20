#!/usr/bin/env python3
import argparse
import datetime
import glob
import logging
import os
from os.path import normpath
from pathlib import Path
import struct
import time

from concurrent_log_handler import ConcurrentRotatingFileHandler

from utils.const import SYNC_BYTES, STA_CHAN_CODE_MAP, TESSA_NETCODE, TESSA_LOCCODE
from utils.rap import RAPPacket
from utils.ms_manager import MSManager


def move_to_next_packet(iobuffer, SYNC_BYTES, start_position=0):
    """
    Move file pointer to the next occurrence of SYNC_BYTES in the iobuffer.
    
    :param iobuffer: IO buffer of raw pegasus data file
    :param SYNC_BYTES: Byte sequence to search for
                       starts each Pegasus packet
    :param start_position: Description
    """
    CHUNK_SIZE = 4096

    iobuffer.seek(start_position)  # Move to the start position
    while True:
        chunk = iobuffer.read(CHUNK_SIZE)  # Read the file in chunks
        if not chunk:
            break  # End of file
        index = chunk.find(SYNC_BYTES)
        if index != -1:
            iobuffer.seek(start_position + index)
            return start_position + index  # return position of the found byte sequence

        start_position += len(chunk)  # SYNC_BYTES not found, position for the next CHUNK_SIZE chunk

    return -1  # Byte sequence not found

def convert_rap2ms(rappkt : RAPPacket, net, sta, loc : str, stachanmap : dict, msmgr : MSManager):
    """
    Take a RAP Packet and convert to Miniseed using MSManager.
    
    :param rappkt: INStance of an RAPPacket representing a single Pegasus raw packet
    :type rappkt: RAPPacket
    :param net: NET code for packet data (if packet is a timeseries packet)
    :type net: str
    :param sta: STation code for packet data (if packet is a timeseries packet)
    :type sta: str
    :param loc: Description
    :type loc: str
    :param stachanmap: Station channel mapping dictionary 
                       with CHAN codes for each smaple rate for each station
    :type stachanmap: dict
    :param msmgr: MSManager instance to use for accumulating Miniseed timeseries data 
                  and generating miniseed packets
    :type msmgr: MSManager
    """

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
    
    logger.info(f'ms_recsize={ms_recsize}')

    msmgr.add_data(rappkt.app_payload[start_byte:end_byte+1], 
                    rappkt.ts_timestamp_ns,
                    rappkt.steim2['sample_cnt'], 
                    ms_recsize,
                    MSManager.TS_ENCODING_STEIM2)
    logger.debug(f'ms data added to MSManager for sta={sta} chan={msmgr.chan_code} starttime={rappkt.ts_timestamp_ns}')
    
def process_file(filename : str, net_code, sta_code, loc_code: str, msmgr: MSManager, debug=False):
    """
    Process a Pegasus raw data file and convert contained timeseries packets to Miniseed.
    """

    logger.info('Processing file: {}.'.format(filename))
    if debug:
        print('Processing file: {}'.format(filename))

    with open(filename, 'rb') as pegfl:

        seq_num : int = -1
        pkt_start : bytes = b''
        pkt: bytes = b''
        offset : int = 0
        found_first_packet : bool = False

        while True:

            offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

            if offset == -1:
                if not found_first_packet:
                    logger.warning("No sync bytes ({}) found in file {}.".format(SYNC_BYTES, filename))
                break

            pkt_start = pegfl.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.
            
            found_first_packet = True
            
            if (len(pkt_start) == 14) and (pkt_start[:4] == SYNC_BYTES):

                pkt_segment_len = struct.unpack_from('!H', pkt_start, 12)[0] + 4

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
                        logger.warning("No sync bytes ({}) found in rest of file {}.".format(SYNC_BYTES, filename))
                else:
                    logger.warning('Error reading file {filename}.')
                break

            if len(pkt) == (14 + pkt_segment_len):

                rappkt = RAPPacket(pkt[4:], debug)
                if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                    logger.warning('{} PACKETs MISSING'.format(rappkt.packet_seqnum - seq_num))

                if rappkt.is_timeseries():
                    convert_rap2ms(rappkt, net_code, sta_code, loc_code, STA_CHAN_CODE_MAP, msmgr)

            else:
                logger.warning('[file: {}] Skipping incomplete packet.'.format(filename))

        if pegfl.tell() < Path(filename).stat().st_size:
            logger.warning('File {} not read to the end!!!'.format(filename))


def ms_handler(data, handlerdata):
    """This callback function is used by mstracelist 
    to collect miniseed records into a list.
    """

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
    parser.add_argument("sta_dir", action="store", help="Station directory")
    # parser.add_argument("sta_ms_dir", action="store", help="Location of the tessa-hub ms directory for .")
    parser.add_argument("ms_output_file", action="store", help="Output miniseed filename.")
    # peg_sta_raw_dir is the 'raw' directory under the station directory and 
    # cointains the dated (in 'yyyy-mm-dd' format) subdirectories with .peg files collected 
    # on those respective dates
    args = parser.parse_args()
    debug = args.debug
    sta_dir = args.sta_dir
    ms_file = Path(args.ms_output_file)

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

    sta_raw_dir = os.path.join(sta_dir, 'raw')
    sta_ms_dir = ms_file.parent
    os.makedirs(sta_ms_dir, mode=0o775, exist_ok=True)
    logger.info(f'Output Miniseed file: {str(ms_file)}')

    p = Path(sta_dir)
    stacode = p.parts[-1] # get station code from station component of sta_raw_dir path

    logger.info(f'  Station directory: {sta_dir}')
    logger.info(f'Raw (peg) directory: {sta_raw_dir}')
    logger.info(f' Miniseed directory: {sta_ms_dir}')

    peg_file_glob: str = f'{sta_dir}/raw/2026-01-1?/*.peg'
    logger.info(f'Processing station .peg files: {peg_file_glob}')

    peg_files_list: list = glob.glob(peg_file_glob)
    peg_files_list.sort()

    msmgr = MSManager()

    for fn in peg_files_list:

        process_file(fn, TESSA_NETCODE, stacode, TESSA_LOCCODE, msmgr, debug)
        move_file(fn, 'converted')

    handler_msrec_list = {
        'ms_recs': []
    }

    _, _ = msmgr.pack_and_flush_with_handler(ms_handler, handler_msrec_list)

    rec_cnt = len(handler_msrec_list['ms_recs'])
    if rec_cnt > 0:
        with open(ms_file, 'wb') as msfl:
            for rec in handler_msrec_list['ms_recs']:
                msfl.write(rec)
                msfl.flush()

        logger.info(f'Wrote {len(handler_msrec_list["ms_recs"])} Miniseed records to file: {ms_file}')
    else:
        logger.warning(f'NO MINISEED RECORDS to write')