#!/usr/bin/env python3
import argparse
import base64
import datetime
import glob
import os
from pathlib import Path
import signal
import ssl
import struct
import sys
import time
import json

import paho.mqtt.client as mqtt

from utils.rap import RAPPacket


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


def print_packet_info(rappkt: RAPPacket, debug=False):

    pkt_info = rappkt.header_str()
    print('xmitter:', pkt_info)


def send_packet(rappkt, sta, mqtt_client, topic, qos, debug=False):

    pkt = rappkt.full_packet()
    # metadata = rappkt.packet_metadata()

    pkt64 = base64.b64encode(pkt).decode('ascii')

    jpkt = {
        "xmit_ts": datetime.datetime.now(tz=datetime.timezone.utc).timestamp(),
        "sta": sta,
        "pegpkt": pkt64
    }
    # jpkt.update(metadata)
    jmsg64 = json.dumps(jpkt)

    mqtt_res = mqtt_client.publish(topic=topic, payload=jmsg64, qos=qos)
    print('waiting to publish msg seqnum/mid: {}/{}; {} bytes'.format(rappkt.packet_seqnum, mqtt_res.mid, len(jmsg64)))
    mqtt_res.wait_for_publish()


def process_file(filename, mqtt_client, topic, debug=False):

    if debug:
        print('Processing file: ' + str(filename))

    # mqtt_client: mqtt.Connection = setup_pub()
    if not mqtt_client:
        print('You must supply an mqtt client connection to process_file()')
        return

    fn = str(filename)
    with open(fn, 'rb') as pegfl:

        # seq_num : int = -1
        pkt_start = b''
        pkt = b''
        offset = 0
        found_first_packet = False

        # extract sta_code from path
        pathparts = fn.split(os.sep)
        sta_code = pathparts[4].lower() ### RELLY NEED TO USE ENV VAR TO FIND correct PATH SEGMENT FOR STA-CODE

        while True:

            offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)

            if offset == -1:
                if not found_first_packet and debug:
                    print("No sync bytes ({synbyt}) found in file {fn}.".format(synbyt=SYNC_BYTES, fn=fn))
                break

            pegfl.seek(offset)

            found_first_packet = True
            pkt_start = pegfl.read(14)  ## read until we get to the SEGMENT_LENGTH in the transport section of the packet.

            if (len(pkt_start) == 14) and (pkt_start[:4] == b'PT02'):

                pkt_segment_len = struct.unpack_from('!H', pkt_start, 12)[0] + 4
                payload = pegfl.read(pkt_segment_len)
                if payload:
                    pkt = pkt_start + payload
                    # set offest to next expected SYNC_BYTES position
                    offset += len(pkt)

            else:
                if pkt_start:
                    print('UNEXPECTED READ: {}'.format(pkt_start))
                    print('Looking for SYNC Bytes...')

                    offset = move_to_next_packet(pegfl, SYNC_BYTES, offset)
                    if offset == -1:
                        if debug:
                            print("No sync bytes ({synbyt}) found in rest of the file {fn}.".format(synbyt=SYNC_BYTES, fn=fn))
                else:
                    if debug:
                        print('Error reading file {fn}.'.format(fn=filename))
                break

            if len(pkt) > 0:

                rappkt = RAPPacket(pkt[4:], debug)
                # if (seq_num > -1) and (rappkt.seq_num != seq_num + 1):
                #     print(f'{rappkt.packet_seqnum - seq_num:>9} PACKETs MISSING')

                # for handler in handlers:
                #     handler["method"](rappkt, handler['userdata'], debug)

                print_packet_info(rappkt, debug)
                send_packet(rappkt, sta_code, mqtt_client, topic, 1, debug)

            time.sleep(0.1)

        if pegfl.tell() < Path(filename).stat().st_size:
            print('File {fn} not read to the end!!!'.format(fn=filename))


def move_file_to_sent(filepath: str):

    # move file to a 'sent' subdirectory of its current location
    fn = str(filepath)


    fdir = os.path.dirname(fn)

    sent_dir = os.path.join(fdir, 'SENT')
    if not os.path.exists(sent_dir):
        os.makedirs(sent_dir)

    fname = os.path.basename(fn)
    save_fn = os.path.join(sent_dir, fname)
    print('XMITTER moving raw file {} to {}'.format(fn, save_fn))
    os.rename(fn, save_fn)

def paho_setup(endpoint, port, client_id, root_ca, cert, key):

    print('paho client setup: {} {} {} {} {} {}'.format(endpoint, port, client_id, root_ca, cert, key))

    def on_connect(client, userdata, flags, reason_code):
        print("Connected client {} with result code {}".format(client, reason_code))
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.

    def on_publish(client, userdata, mid):
        print('msg {} published succesfully.'.format(mid))

    def on_disconnect(client, userdata, rc):
        print('client DISCONNECTED: {} with rc: {}'.format(client, rc))

    def on_message(client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))

    mqttc = mqtt.Client(client_id=client_id)
    mqttc.tls_set(root_ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_REQUIRED)
    mqttc.on_connect = on_connect
    mqttc.on_disconnect = on_disconnect
    mqttc.on_message = on_message
    mqttc.on_publish = on_publish

    mqttc.connect(endpoint, port, keepalive=600)
    mqttc.loop_start()

    return mqttc

def interrupt_handler(signum, frame):

    mqtt_client.loop_stop()

    time.sleep(0.5)
    print("shutting down...")
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, interrupt_handler)

    ### AWS IOT CONSTANTS (NEED TO PULL FROM ENV)
    # ENDPOINT = 'a1cizoe0dy9v99-ats.iot.us-east-2.amazonaws.com'
    # ENDPOINT = 'iot-nlb-a0a43ed2e3f13805.elb.us-east-2.amazonaws.com'
    # ENDPOINT = '3.136.73.214'
    ENDPOINT = 'iot.tessa-obs.net'
    PORT = 8883

    ### RAP CONSTANTS
    SYNC_BYTES = b'PT02'

    aws_dir = os.getenv('TESSA_AWS_DIR')
    if not aws_dir:
        print('ERROR: TESSA_AWS_DIR env var does not exist. Quitting...', file=sys.stderr)
        sys.exit(1)

    thing_name = os.getenv('TESSA_WG_THING_NAME')
    if not thing_name:
        print('ERROR: TESSA_WG_THING_NAME env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    DATA_ROOT_DIR = os.getenv('TESSA_DATA_ROOT')
    if not DATA_ROOT_DIR:
        print('ERROR: TESSA_DATA_ROOT env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    CERT = os.path.join(aws_dir, thing_name+'.pem.crt')
    KEY = os.path.join(aws_dir, thing_name+'.private.pem.key')
    ROOT_CA = os.path.join(aws_dir, 'AmazonRootCA1.pem')

    CLIENT_ID = thing_name
    TOPIC = 'tessa/data/raw'

    parser = argparse.ArgumentParser(description="list Pegasus raw packets in a file(s)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
    # parser.add_argument("fileglob", action="store", nargs='+', help="filename(s) to read")

    args = parser.parse_args()
    # filelist = args.fileglob
    debug = args.debug


    while True:

        # get all files in: $TESSA_DATA_ROOT/<STACODE>/raw/<yyyy-mm-dd>/*.peg
        filelist = glob.glob(os.path.join(DATA_ROOT_DIR,
                                        "*",
                                        'raw',
                                        '*',
                                        '*.peg'))
        if filelist:

            filelist.sort()
            if args.debug:
                print('FILES: {}'.format(filelist))

            mqtt_client = paho_setup(ENDPOINT, PORT, CLIENT_ID, ROOT_CA, CERT, KEY)

            for fn in filelist:

                print('XMITTER reading file:', fn)
                if not Path(fn).exists():
                    if debug:
                        print('FILE NOT FOUND: {fn}. Skipping...'.format(fn=fn))
                    continue
                fn = Path(fn).absolute()
                process_file(fn, mqtt_client, TOPIC, debug)
                move_file_to_sent(fn)

            mqtt_client.loop_stop()

        time.sleep(15)
