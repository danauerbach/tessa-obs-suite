#!/usr/bin/env python3
import argparse
from pathlib import Path
import struct
import sys

from awscrt import mqtt, http
from awsiot import mqtt_connection_builder

from utils.rap import RAPPacket

### AWS IOT CONSTANTS
CERT = '../../awstests/tessa-wg-dev.cert.pem'
KEY = '../../awstests/tessa-wg-dev.private.key'
ENDPOINT = 'a1cizoe0dy9v99-ats.iot.us-east-2.amazonaws.com'
PORT = 8883
ROOT_CA = None
CLIENT_ID = 'binary_sender'
TOPIC = 'tessa/data/raw'

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
            
            found_first_packet = True
            
            # pegfl.seek(offset)

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



def send_packet(rappkt, userdata, debug):

    global rec_cnt
    payload = rappkt.full_packet()
    pub_future = userdata['client'].publish(topic=userdata['topic'], payload=payload, qos=mqtt.QoS.AT_LEAST_ONCE)
    _ = pub_future[0].result()

def setup_pub(userdata):

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


    # userdata['client'] = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, userdata['client_id'], userdata=userdata)
    # userdata['client'].on_connect = pub_on_connect
    # userdata['client'].on_disconnect = pub_on_disconnect
    # userdata['client'].on_publish = pub_on_pub
    # userdata['client'].connect(
    #     userdata['host'],
    #     userdata['port']
    # )
    # userdata['client'].loop_start()

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=ENDPOINT,
        port=PORT,
        cert_filepath=CERT,
        pri_key_filepath=KEY,
        ca_filepath='',
        on_connection_interrupted=aws_on_connection_interrupted,
        on_connection_resumed=aws_on_connection_resumed,
        client_id=CLIENT_ID,
        clean_session=False,
        keep_alive_secs=30,
        http_proxy_options=None,
        on_connection_success=aws_on_connection_success,
        on_connection_failure=aws_on_connection_failure,
        on_connection_closed=aws_on_connection_closed,
    )
    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected!")

    userdata['client'] = mqtt_connection

def teardown_pub(userdata):

    print('teardown:', userdata['client_id'].upper())
    if userdata['client']:
        disconnect_future = userdata['client'].disconnect()
        disconnect_future.result()
        print(f"Disconnected after sending {rec_cnt} bytes")

def teardown_print(userdata):

    print(f'Printed {print_cnt} records.')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="list Pegasus raw packets in a file(s)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug/verbose mode")
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

            },
            {
                'userdata': {
                    'client': None, 
                    'client_id': 'rap_pkt_pusher',
                    'host': 'localhost',
                    'port': 1883,
                    'topic': 'tessa/data/raw'
                    },
                'setup': setup_pub, 
                'method': send_packet,
                'teardown': teardown_pub
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
            process_file(fn, handlers, debug)

    for handler in handlers:
        if handler.get('teardown'):
            if handler['teardown']:
                handler['teardown'](handler['userdata'])


