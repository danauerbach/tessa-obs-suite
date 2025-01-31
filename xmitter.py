#!/usr/bin/env python3
import argparse
import base64
import datetime
import glob
import os
from pathlib import Path
import struct
import sys
import time
import json

# from paho.mqtt import client as paho_client
from awscrt import mqtt
from awsiot import mqtt_connection_builder

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


def send_packet(rappkt: RAPPacket, sta, aws_client, topic: str, qos=mqtt.QoS.AT_LEAST_ONCE, debug: bool =False):

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
    
    pub_future = aws_client.publish(topic=topic, payload=jmsg64, qos=mqtt.QoS.AT_LEAST_ONCE)

    ### TODO: try/except
    res = pub_future[0].result()


def process_file(filename, mqtt_client, debug=False):

    if debug:
        print('Processing file: ' + filename)

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
        sta_code = pathparts[3].lower()

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
                send_packet(rappkt, sta_code, mqtt_client, TOPIC, mqtt.QoS.AT_LEAST_ONCE, debug)

            time.sleep(0.1)

        if pegfl.tell() < Path(filename).stat().st_size:
            print('File {fn} not read to the end!!!'.format(fn=filename))

    stats = mqtt_client.get_stats()
        ###TODO: check for any unpublished packets
    while stats.incomplete_operation_count > 0:
        print('Incomplete_operation_count: {ioc}'.format(ioc=stats.incomplete_operation_count))
        print('Unacked_operation_count: {uoc}'.format(uoc=stats.unacked_operation_count))
        time.sleep(0.25)
        ### TODO: should we wait? Loop?


def setup_pub(endpoint, port, client_id, root_ca, cert, key):

    # Callback when connection is accidentally lost.
    def aws_on_connection_interrupted(connection, error, **kwargs):
        print("Connection interrupted. error: {}".format(error))


    # Callback when an interrupted connection is re-established.
    def aws_on_connection_resumed(connection, return_code, session_present, **kwargs):
        print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

        if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
            print("Session did not persist. Resubscribing to existing topics...")
            resubscribe_future, _ = connection.resubscribe_existing_topics()

            # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
            # evaluate result with a callback instead.
            resubscribe_future.add_done_callback(on_resubscribe_complete)

    def on_resubscribe_complete(resubscribe_future):
        resubscribe_results = resubscribe_future.result()
        print("Resubscribe results: {}".format(resubscribe_results))

        for topic, qos in resubscribe_results['topics']:
            if qos is None:
                sys.exit("Server rejected resubscribe to topic: {}".format(topic))


    # Callback when the connection successfully connects
    def aws_on_connection_success(connection, callback_data):
        assert isinstance(callback_data, mqtt.OnConnectionSuccessData)
        print("Connection Successful with return code: {} session present: {}".format(callback_data.return_code, callback_data.session_present))

    # Callback when a connection attempt fails
    def aws_on_connection_failure(connection, callback_data):
        assert isinstance(callback_data, mqtt.OnConnectionFailureData)
        print("Connection failed with error code: {}".format(callback_data.error))

    # Callback when a connection has been disconnected or shutdown successfully
    def aws_on_connection_closed(connection, callback_data):
        print("Connection closed")

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=endpoint,
        port=port,
        cert_filepath=cert,
        pri_key_filepath=key,
        ca_filepath=root_ca,
        on_connection_interrupted=aws_on_connection_interrupted,
        on_connection_resumed=aws_on_connection_resumed,
        client_id=client_id,
        clean_session=False,
        keep_alive_secs=30,
        http_proxy_options=None,
        on_connection_success=aws_on_connection_success,
        on_connection_failure=aws_on_connection_failure,
        on_connection_closed=aws_on_connection_closed,
    )
    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    try: 
        connect_future.result()
        print("mqtt client connected!")

    except Exception as e:

        print('Unable to establish mqtt connection with AWS IoT')
        return None

    return mqtt_connection

def teardown_pub(mqtt_connection: mqtt_connection_builder):

    if mqtt_connection:
        disconnect_future = mqtt_connection.disconnect()

        try:
            disconnect_future.result()
            print('mqtt client disconnected')
        except Exception as e:

            print('Error closing mqtt_client connection')

def move_file_to_sent(filepath: str):

    # move file to a 'sent' subdirectory of its current location
    fdir = os.path.dirname(filepath)

    sent_dir = os.path.join(fdir, 'SENT')
    if not os.path.exists(sent_dir):
        os.makedirs(sent_dir)

    fname = os.path.basename(filepath)
    save_fn = os.path.join(sent_dir, fname)
    os.rename(filepath, save_fn)


if __name__ == '__main__':

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

    CERT = os.path.join(aws_dir, f'{thing_name}.pem')
    KEY = os.path.join(aws_dir, f'{thing_name}.private.key')
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


            mqtt_client = setup_pub(ENDPOINT, PORT, CLIENT_ID, ROOT_CA, CERT, KEY)

            for fn in filelist:
                    
                    if not Path(fn).exists():
                        if debug:
                            print('FILE NOT FOUND: {fn}. Skipping...'.format(fn=fn))
                        continue
                    fn = Path(fn).absolute()
                    process_file(fn, mqtt_client, debug)
                    move_file_to_sent(fn)

            teardown_pub(mqtt_client)

        time.sleep(30)