#!/usr/bin/env python3

from binascii import hexlify
import crcmod
from datetime import datetime, timezone, timedelta
import argparse
import os
from os import path as p  #.path import join, rename, basename
import serial
import shlex
import struct
from sys import exit, stdout
from threading import Thread
import queue
import sys
from time import sleep

from utils.const import *
from utils.rap import RAPPacket, APP_RESPONSE_TYPE_STATION_CONFIG

QUIT_FLAG = 'quit'
DATA_FRAMES_PACKET = 8

def process_commands(seq_num):

    print("sending info and config requests")
    send_station_info_request(seq_num)
    seq_num += 1
    send_station_config_request(seq_num)
    seq_num += 1
    send_soh_request(seq_num)
    seq_num += 1

    print('Awaiting commands...')
    print('To get help, enter `help`.')

    while True:
        # handle_messages()
        try:
            the_input = input('> ')
        except EOFError:
            continue

        if the_input:
            cmd, *args = shlex.split(the_input)
        else:
            cmd="none"

        if cmd=='exit':
            break

        elif cmd=='quit':
            # kludge
            quit_q.put('quit')
            quit_q.put('quit')
            break

        elif cmd=='help':
            print('Commands:')
            print('soh: Send SOH request')
            print('stop: Stop current streaming request')
            print('start: Start stream with default parameters')
            print('info: get station info')
            print('config: get station config')
            print('quit/exit: quit application')
       
        elif cmd=='soh':
            send_soh_request(seq_num)
            seq_num+=1

        elif cmd=='stop':
            send_stop_streaming_request(seq_num)
            seq_num+=1

        elif cmd=='start':
            send_start_streaming_request(seq_num)
            seq_num+=1
        
        elif cmd in ['history-setup', 'hsu']:
            now = datetime.now(tz=timezone.utc).timestamp()
            now -= 1800
            send_history_setup_request(seq_num, int(now))
            seq_num+=1
        
        elif cmd in ['history-getnext', 'n']:
            send_history_getnext_request(seq_num)
            seq_num+=1
        
        elif cmd in ['history-repeat', 'r']:
            send_history_repeat_request(seq_num)
            seq_num+=1
        
        elif cmd=='info':
            send_station_info_request(seq_num)
            seq_num+=1

        elif cmd=='config':
            send_station_config_request(seq_num)
            seq_num+=1

        elif cmd=='none':
            # handle_messages()
            pass
            
        # ...
        else:
            print('Unknown command: {}'.format(cmd) )  
            # handle_messages()  
    
        # time.sleep(1)
        # handle_messages()
    return


def send_soh_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',3) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))
    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    soh_req = bytearray()
    soh_req += FrameSynchronizationWord
    soh_req += SegmentHeader
    soh_req += SegmentHeaderCRC
    soh_req += message
    soh_req += SegmentPayloadCRC

    # print("Sending:")
    print(hexlify(soh_req))

    ser.write(soh_req)    
    return

def send_start_streaming_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',1) #PacketType
    message += struct.pack('!H',6) #PacketPayloadLength
    message += struct.pack('!H', 0x0F) #Channels
    message += struct.pack('!b', 1) #SamplingRate factor
    message += struct.pack('!b', 1) #SamplingRate multiplier
    message += struct.pack('!B', 24) #SampleResolution
    message += struct.pack('!B', DATA_FRAMES_PACKET)  #DataframesPerPacket

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength
    #print("Header CRC")
    #print(hex(crcPegasus(SegmentHeader)))

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))

    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    stream_req = bytearray()
    stream_req += FrameSynchronizationWord
    stream_req += SegmentHeader
    stream_req += SegmentHeaderCRC
    stream_req += message
    stream_req += SegmentPayloadCRC

    print("Sending start streaming request:")
    print(stream_req.hex())

    ser.write(stream_req)
    return 

def send_history_setup_request(seq, epoch_start_time):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',5) #PacketType
    message += struct.pack('!H',8) #PacketPayloadLength
    message += struct.pack('!H', 0x0F) #Channels
    message += struct.pack('!H', 0) # reserved, filling with null
    message += struct.pack('!L', epoch_start_time)

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength
    #print("Header CRC")
    #print(hex(crcPegasus(SegmentHeader)))

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))

    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    stream_req = bytearray()
    stream_req += FrameSynchronizationWord
    stream_req += SegmentHeader
    stream_req += SegmentHeaderCRC
    stream_req += message
    stream_req += SegmentPayloadCRC

    print("Sending:")
    print(stream_req.hex())

    ser.write(stream_req)
    return 

def send_history_getnext_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',6) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength
    # message += struct.pack('!H', 0x01) #Channels
    # message += struct.pack('!b', 10) #SamplingRate factor
    # message += struct.pack('!b', 1) #SamplingRate multiplier
    # message += struct.pack('!B', 24) #SampleResolution
    # message += struct.pack('!B', 2)  #DataframesPerPacket

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength
    #print("Header CRC")
    #print(hex(crcPegasus(SegmentHeader)))

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))

    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    stream_req = bytearray()
    stream_req += FrameSynchronizationWord
    stream_req += SegmentHeader
    stream_req += SegmentHeaderCRC
    stream_req += message
    stream_req += SegmentPayloadCRC

    print("Sending:")
    print(stream_req.hex())

    ser.write(stream_req)
    return 

def send_history_repeat_request(seq):

    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',0x0007) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength
    # message += struct.pack('!H', 0x01) #Channels
    # message += struct.pack('!b', 10) #SamplingRate factor
    # message += struct.pack('!b', 1) #SamplingRate multiplier
    # message += struct.pack('!B', 24) #SampleResolution
    # message += struct.pack('!B', 2)  #DataframesPerPacket

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength
    #print("Header CRC")
    #print(hex(crcPegasus(SegmentHeader)))

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    stream_req = bytearray()
    stream_req += FrameSynchronizationWord
    stream_req += SegmentHeader
    stream_req += SegmentHeaderCRC
    stream_req += message
    stream_req += SegmentPayloadCRC


    print(f"Sending: {stream_req.hex()}")

    ser.write(stream_req)
    return 

def send_stop_streaming_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',2) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength
    #print("Header CRC")
    #print(hex(crcPegasus(SegmentHeader)))

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))

    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    stream_req = bytearray()
    stream_req += FrameSynchronizationWord
    stream_req += SegmentHeader
    stream_req += SegmentHeaderCRC
    stream_req += message
    stream_req += SegmentPayloadCRC

    print("Sending:")
    print(stream_req.hex())

    ser.write(stream_req)    
    return

def send_station_info_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',4) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))
    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    req = bytearray()
    req += FrameSynchronizationWord
    req += SegmentHeader
    req += SegmentHeaderCRC
    req += message
    req += SegmentPayloadCRC

    print("Sending:")
    print(req.hex())

    ser.write(req)    
    return

def send_station_config_request(seq):
    message = bytearray()
    message += struct.pack('!H',1) #ApplicationLayerVersion
    message += struct.pack('!H',8) #PacketType
    message += struct.pack('!H',0) #PacketPayloadLength

    #Transport Layer
    SegmentHeader = bytearray()
    SegmentHeader += struct.pack('!H',1) #TransportLayerVersion
    SegmentHeader += struct.pack('!H',seq) #PacketSequenceNumber  every request needs to be different than the one before
    SegmentHeader += struct.pack('!H',0) #SegmentIndex
    SegmentHeader += struct.pack('!H',1)  #SegmentTotalCount
    SegmentHeader += struct.pack('!H',len(message))  #SegmentPayloadLength

    SegmentHeaderCRC = bytearray()
    SegmentHeaderCRC += struct.pack('!H',crcPegasus(SegmentHeader)) #(Bytes 0-9 inclusive)

    SegmentPayloadCRC = bytearray()
    SegmentPayloadCRC += struct.pack('!H',crcPegasus(message))
    #end Transportlayer
    #end Datalink Layer

    FrameSynchronizationWord = b'PT02'

    #create an SOH request Message
    req = bytearray()
    req += FrameSynchronizationWord
    req += SegmentHeader
    req += SegmentHeaderCRC
    req += message
    req += SegmentPayloadCRC

    print("Sending:")
    print(req.hex())

    ser.write(req)    
    return

def log_message(msg):
    #log the message
    # f = open(ascii_log, "a")
    # f.write(f'{msg}\n')
    # f.close()
    pass
    # print(msg)
    # f = open(ascii_log, "ab")
    # f.write(b'PT02' + msg)
    # f.close()
    # f = open(ascii_log, "a")
    # f.write('\n')
    # f.close()

class DataLinkHeader:

    def __init__(self, packet: bytes):

        self.packet = packet
        # self.FrameSyncWord = packet[:4].decode()

    def __str__(self):

        resstr: str = ''
        # resstr += f'DataLink.FrameSyncWord: {self.FrameSyncWord}\n'
        resstr += f'DataLink.PayloadLength: {len(self.packet)}\n'

        return resstr


def get_data_link_header(msg: bytes):

    return DataLinkHeader(msg)


def get_transport_header(msg: bytes):

    return RAPPacket(msg)


def process_message(msg: bytes, debug=False) -> RAPPacket:

    rap_packet = RAPPacket(msg[4:], debug)
    print('CheckRAP:', rap_packet.header_str())


def handle_messages(quit_q, data_q: queue.Queue, ser : serial.Serial, debug=False):
    
    quitting: bool = False
    msg_array: bytearray = bytearray()
    result : bytes

    while True:
        
        try:
            msg: str = quit_q.get(block=False)
            quitting = msg == QUIT_FLAG
        except queue.Empty:
            pass

        if quitting:
            print('read thread breaking...')
            break
    
        #retrieve any messages
        result = ser.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.

        if (len(result) == 14) and (result[:4] == b'PT02'):
            segment_len = struct.unpack_from('!H', result, 12)[0] + 4
            if debug:
                print(f'SEGMENT SEQNUM:                   {struct.unpack_from("!H", result, 6)[0]}')
                print(f'SEGMENT PAYLOAD LEN (+4 for both crc): {segment_len}')

            payload = ser.read(segment_len)
            if payload:
                result += payload
        else:
            if result:
                print(f'UNEXPECTED READ: ({len(result)} bytes): {result}')
                ser.reset_input_buffer()
            continue

        rtime = datetime.now(timezone.utc)
        
        if len(result) > 0:
            # print(f'Time: {rtime}: read buffer length: {len(result)}.')
            # print(f"Number of Frame Sync Sequences: {result.count(b'PT02')}")
            # print(f"First 4 bytes: {struct.unpack_from('!4s', result[:4] ,0)[0]}\n")
            #need to split the messages here
            # print(f'res.hex ({rtime}): [{res.hex()}]')
            process_message(result, debug)  ## includes the 4 SYNC bytes
            # print(30*'-')
            try:
                data_q.put(result, timeout=.1)
            except:
                pass

    # result = ser.read(65000)

    return

def peg_raw_writer(quit_q, data_q, sta_code, write_bin_time_size_min=15, write_bin_max_size=100000, output_root='.', debug=False):

    BIN_LEGNTH_MIN = write_bin_time_size_min
    BIN_SIZE_BYTES = write_bin_max_size
    PEG_FILENAME_FORMAT = "%Y-%m-%d-%H%M"

    def round_to_next_time_bin(dt, bin_size_min=BIN_LEGNTH_MIN):
        mins_from_bin_start = (dt.minute % bin_size_min)
        dt -= timedelta(minutes=mins_from_bin_start)
        dt = dt.replace(second=0, microsecond=0)
        return dt

    # print(f'tmp output_dir: {TMP_DIR_PATH}')
    # print(f'bin_start_date: {write_bin_start_dt}')
    # print(f'bin_start_date_formatted: {write_bin_start_dt.strftime(PEG_FILENAME_FORMAT)}')
    # print(f'PEG Filename: {cur_pegfn}')
    stdout.flush()

    write_bin_start_dt = round_to_next_time_bin(datetime.now(timezone.utc), BIN_LEGNTH_MIN)

    TMP_DIR_PATH = p.join(output_root, sta_code, 'tmp')
    os.makedirs(TMP_DIR_PATH, exist_ok=True)

    cur_pegfn = p.join(TMP_DIR_PATH,write_bin_start_dt.strftime(PEG_FILENAME_FORMAT)+'.peg')

    RAW_DAY_DIR = p.join(output_root, sta_code, 'raw', write_bin_start_dt.strftime("%Y-%m-%d"))
    if not os.path.exists(RAW_DAY_DIR):
        os.makedirs(RAW_DAY_DIR, exist_ok=True)

    while True:

        try:
            msg = quit_q.get(block=False)
            if msg == QUIT_FLAG:
                fnname = p.basename(cur_pegfn).split('.')[0] # get rid of extension cause have to first concat cur time
                save_fn = p.join(RAW_DAY_DIR, fnname + '-' + datetime.now(timezone.utc).strftime("%H-%M-%S")+'.peg')
                print('write thread breaking... saving open file...{} ==> {}'.format(cur_pegfn, save_fn))
                os.rename(cur_pegfn, save_fn)
                print('write thread exiting...{}'.format(cur_pegfn))

                return
        except queue.Empty:
            pass

        try:
            pkt = data_q.get(timeout=0.1)

        except queue.Empty:
            pass

        else:
            if pkt:

                with open(cur_pegfn, 'ab') as pegfl:

                    pegfl.write(pkt)
                    pegfl.flush()
                    cur_file_size = pegfl.tell()

                # RAW_DAY_DIR = p.join(RAW_ROOT_DIR, write_bin_start_dt.strftime("%Y-%m-%d"))
                # if not os.path.exists(RAW_DAY_DIR):
                #     os.makedirs(RAW_DAY_DIR, exist_ok=True)

                if ((datetime.now(timezone.utc) - write_bin_start_dt).total_seconds() > \
                        BIN_LEGNTH_MIN * 60)  or \
                        cur_file_size > BIN_SIZE_BYTES:
                    
                    RAW_DAY_DIR = p.join(output_root, sta_code, 'raw', write_bin_start_dt.strftime("%Y-%m-%d"))
                    if not os.path.exists(RAW_DAY_DIR):
                        os.makedirs(RAW_DAY_DIR, exist_ok=True)

                    fn = p.basename(cur_pegfn)
                    save_fn = p.join(RAW_DAY_DIR, fn)
                    os.rename(cur_pegfn, save_fn)

                    write_bin_start_dt = round_to_next_time_bin(datetime.now(timezone.utc))
                    cur_pegfn = p.join(TMP_DIR_PATH,
                                             write_bin_start_dt.strftime(PEG_FILENAME_FORMAT)+'.peg')
                    


if __name__ == "__main__":

    WRITE_TIME_BIN_LEGNTH_MIN = 5
    WRITE_BIN_SIZE_BYTES = 100000

    DATA_ROOT_DIR = os.getenv('TESSA_DATA_ROOT')
    if not DATA_ROOT_DIR:
        print('ERROR: TESSA_DATA_ROOT DIR DOES NOT EXIST. Nothing to do.', file=sys.stderr)
        sys.exit(1)


    parser = argparse.ArgumentParser('Pegasus RAP Reader')
    parser.add_argument('sta_code', action='store', help='station code for data', default='XTES1')
    parser.add_argument("--port", "-p",
                        action='store', 
                        default='/dev/ttyUSB0'
                        )
    parser.add_argument("--debug", "-d", action='store_true')
    args = parser.parse_args()

    crcPegasus = crcmod.predefined.mkCrcFun('crc-aug-ccitt')
    #pegasus uses CRC-CCITT(0x1DOF)


    #open the serial port
    print(f'Opening Serial Port: {args.port}')
    ser = serial.Serial(args.port, baudrate=115200, bytesize=8, parity=serial.PARITY_NONE)
    if not ser.is_open:
        print('Serial port NOT OPEN!')
    ser.flush()
    ser.send_break(0.1)
    ser.reset_input_buffer()  
    ser.reset_output_buffer()  
    # time.sleep(1)

    # print(ser)

    quit_q = queue.Queue()
    data_q = queue.Queue()

    # create and start thread to receive packets from Pegasus
    read_thr = Thread(target=handle_messages, args=(quit_q, data_q, ser, args.debug))
    read_thr.start()

    # create and start thread for writing packets to disk
    max_filesize = 1000000
    write_thr = Thread(target=peg_raw_writer, args=(quit_q, data_q, args.sta_code,
                                                    WRITE_TIME_BIN_LEGNTH_MIN, WRITE_BIN_SIZE_BYTES,
                                                    DATA_ROOT_DIR, 
                                                    args.debug))
    write_thr.start()

    #start the interactive command processor
    process_commands(100)  #start sequence number. Quit after 100 commands (kinda silly)

    read_thr.join()
    write_thr.join()

    ser.flush()
    ser.close()

    print('done')

