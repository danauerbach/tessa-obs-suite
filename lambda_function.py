#!/usr/bin/env python3
from pathlib import Path
import base64
from utils.const import STA_CHAN_CODE_MAP, TESSA_NETCODE, TESSA_LOCCODE
from utils.rap import RAPPacket
from utils.ms_manager import MSManager
import json

SYNC_BYTES = b'PT02'
MS_NET = "XX"
MS_LOC = "00"
MS_STA = "TES1"  # using serial number of Pegasus BUT this must come from elsewhere todistinguish difference OBS


# def move_to_next_packet(iobuffer, sync_bytes, start_position=0):

#     iobuffer.seek(start_position)  # Move to the start position
#     while True:
#         chunk = iobuffer.read(4096)  # Read the file in chunks
#         if not chunk:
#             break  # End of file
#         index = chunk.find(sync_bytes)
#         if index != -1:
#             iobuffer.seek(start_position + index)
#             return start_position + index
#         start_position += len(chunk)  # Update position for the next chunk

#     return -1  # Byte sequence not found


def source_id(netcode, stacode, chancode, loccode : str) -> str:

    chanchars = "_".join(chancode)
    return f"FDSN:{netcode[:2]}_{stacode[:5]}_{loccode[:2]}_{chanchars}"

def convert_rap2ms(rappkt : RAPPacket, net, sta, loc : str, stachanmap : dict, msmgr : MSManager):

    sample_rate = rappkt.steim2["sr"]
    start_byte = rappkt.steim2["byte_start"]
    end_byte = start_byte + rappkt.steim2["byte_cnt"] - 1

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
    
    # print(f"data start: {ts_start_byte}; data end: {ts_end_byte}; recsize: {ms_recsize}; sample cnt: {rappkt.steim2['sample_cnt']}")
    # print(f'MS MSG: {msmgr}')
    msmgr.add_data(rappkt.app_payload[start_byte:end_byte+1], 
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
    # print(f'type of DATA: {type(data)}; first 20 bytes: {data[:20]}')


def lambda_handler(event, context):

    seq_num : int = -1
    msmgr = MSManager()

    for record in event['records']:

        asc_data = base64.b64decode(record['data']).decode(encoding='ascii')
        jrec = json.loads(asc_data)
        print(f'jrec:{jrec}')
        
        pkt64 = jrec['pegpkt']
        pkt = base64.b64decode(pkt64)
        rappkt = RAPPacket(pkt[4:])

        sta_code = jrec['sta']

        if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
            print(f'{rappkt.packet_seqnum - seq_num - 1:>9} PACKETs MISSING')

        if rappkt.is_timeseries():
            convert_rap2ms(rappkt, TESSA_NETCODE, sta_code, TESSA_LOCCODE, STA_CHAN_CODE_MAP, msmgr)


    handler_data = {
        'ms_rec_list': []
    }
    _, _ = msmgr.pack_and_flush_with_handler(ms_handler, handler_data)

    raw_rec_cnt : int = len(event['records'])
    ms_recs = handler_data['ms_rec_list']
    ms_rec_cnt : int = len(ms_recs)

    # print(f'RAW REC CNT: {raw_rec_cnt}')
    # print(f'MS REC CNT: {ms_rec_cnt}')

    output = []
    for ndx, rec in enumerate(ms_recs):
        output_record = {
            'recordId': event['records'][ndx]['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(rec)
        }
        print("output_ms_rec:")
        print(output_record)
        output.append(output_record)

    for rec in event['records'][ms_rec_cnt:]:
        output_record = {
            'recordId': rec['recordId'],
            'result': 'Dropped',
            'data': rec['data']
        }
        print("output_orig_rec:")
        print(output_record)
        output.append(output_record)


    print('Successfully processed {} records.'.format(len(event['records'])))

    return {'records': output}
