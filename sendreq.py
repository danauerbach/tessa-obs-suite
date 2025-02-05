#!/usr/bin/env python3

import argparse
import base64
import datetime
import glob
import os
from pathlib import Path
import queue
import signal
import ssl
import struct
import sys
import threading
import time
import json

import paho.mqtt.client as mqtt


def paho_client_setup(endpoint, port, client_id, root_ca, cert, key, ack_topic, req_q):

    def is_valid_request(msg):

        return msg.get('rid') and \
            msg.get('sta') and \
            msg.get('begep') and \
            msg.get('endep') and \
            (msg.get('chnbm') <= 15) and (msg.get('chnbm') > 0) # chan bitmap int, 4 bits

    def on_message(client, userdata, message):

        msg_str = message.payload.decode('utf-8')
        print(f'{client_id}:on_message: {msg_str}')
        msg_dict = json.loads(msg_str)
        req_q.put(msg_dict)

    def on_connect(client, userdata, flags, rc):
        if rc==0:
            print("{client_id}:on_connect: connected OK: {client}")
        else:
            print("{client_id}:on_connect: Bad connection for {client} Returned code: ", rc)
            client.loop_stop()

    def on_disconnect(client, userdata, rc):
        print("client disconnected ok")

    def on_subscribe(client, userdata, mid, granted_qos):
        print("Subscribed: "+str(mid)+" "+str(granted_qos))

    def on_publish(client, userdata, mid):
        print("{client_id}:on_connect: {client} mid= "  ,mid)


    req_client = mqtt.Client(client_id=client_id)
    req_client.tls_set(root_ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_REQUIRED)
    req_client.on_connect = on_connect
    req_client.on_disconnect = on_disconnect
    req_client.on_subscribe = on_subscribe
    req_client.on_publish = on_publish
    req_client.on_message = on_message
    req_client.connect(endpoint, port)

    res, _ = req_client.subscribe(ack_topic, qos=1)
    if res != mqtt.MQTT_ERR_SUCCESS:
        print(f'{client_id}: ERROR subscribing to {ack_topic}')
        print(f'{client_id}: shutting down')
        # quit_evt.set()
        time.sleep(.25)
        return None
    else:
        req_client.loop_start()

    return req_client


def interrupt_handler(signum, frame):

    quit_evt.set()
    time.sleep(1)
    # sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, interrupt_handler)

    parser = argparse.ArgumentParser(description='construct and send data request to topic "tessa/request" and listenf or ACK on topic "tessa/reqack"')
    parser.add_argument("sta", action='store', help='station code to request data from')
    parser.add_argument("beg", action='store', help='Start time (iso8660) of requested data segment')
    parser.add_argument("end", action='store', help='End time (iso8660) of requested data segment')

    args = parser.parse_args()

    sta = args.sta.upper()
    beg = args.beg.upper()
    if not beg.endswith('Z'):
        beg += 'Z'
    begep = datetime.datetime.fromisoformat(beg).timestamp()
    end = args.end.upper()
    if not end.endswith('Z'):
        end += 'Z'
    endep = datetime.datetime.fromisoformat(end).timestamp()

    rid = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

    msg = {
        'rid': rid,
        'sta': sta,
        'beg': begep,
        'end': endep
    }

    msg_str = json.dumps(msg)
    print(f'msg_str: {msg_str}')


    aws_dir = os.getenv('TESSA_AWS_DIR')
    if not aws_dir:
        print('ERROR: TESSA_AWS_DIR env var does not exist. Quitting...', file=sys.stderr)
        sys.exit(1)
    
    thing_name = os.getenv('TESSA_WG_THING_NAME')
    if not thing_name:
        print('ERROR: TESSA_WG_THING_NAME env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    ENDPOINT = 'iot.tessa-obs.net'
    PORT = 8883
    CERT = os.path.join(aws_dir, f'{thing_name}.pem.crt')
    KEY = os.path.join(aws_dir, f'{thing_name}.private.pem.key')
    ROOT_CA = os.path.join(aws_dir, 'AmazonRootCA1.pem')

    CLIENT_ID = thing_name
    REQ_TOPIC = 'tessa/request'
    ACK_TOPIC = 'tessa/reqack'

    # threadsafe quit flag for qhen something goes wrong in a thread
    quit_evt = threading.Event()

    # threadsafe way to pass incoming requests from paho internal loop thread 
    # to main thread that writes to disk and sends ack
    req_q = queue.Queue()

    req_client = paho_client_setup(ENDPOINT, PORT, CLIENT_ID, ROOT_CA, CERT, KEY, ACK_TOPIC, req_q)

    req_client.publish(REQ_TOPIC, payload=msg_str.encode('utf-8'), qos=1)

    while not quit_evt.is_set():

        try:
            req_dict = req_q.get(block=True, timeout=1)
            req_q.task_done()

        except queue.Empty as e:
            print(f'No ACK received yet....')
            continue

        except Exception as e:
            print(f'reqmon:main: ERROR receiving data msg: {e}')
            continue

        #### CHECK FOR status='OK' ACK msg ########
        # TODO TODO
        

        
        time.sleep(1)

    # gives threads a chance to exit cleanly    
    req_client.loop_stop()



