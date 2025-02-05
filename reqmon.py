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

# REQMON_CFG = {
#     "mqtt": {
#         "HOST": 'iot.tessa-obs.net',
#         "PORT": 8883,
#         "root-CA": 'AmazonRootCA1.pem',
#         "key": 'tessa-reqmon.private.pem.key',
#         "cert": 'tessa-reqmon.pem.crt',
#         "req_topic": 'tessa/req',
#         "reqack_topic": 'teesa/reqack',
#         "reqmon_client_id": "tessa-reqmon",
#         "reqack_client_id": "tessa-reqack",
#     }
# }


def paho_client_setup(endpoint, port, client_id, root_ca, cert, key, req_topic, req_q):

    def is_valid_request(msg):

        return msg.get('rid') and \
            msg.get('sta') and \
            msg.get('beg') and \
            msg.get('end') and \
            (msg.get('chnbm') <= 15) and (msg.get('chnbm') > 0) # chan bitmap int, 4 bits

    def on_message(client, userdata, message):

        msg_str = message.payload.decode('utf-8')
        print(f'reqmon:on_message: {msg_str}')
        msg_dict = json.loads(msg_str)
        if is_valid_request(msg_dict):
            req_q.put(msg_dict)

    def on_connect(client, userdata, flags, rc):
        if rc==0:
            print("reqmon:on_connect: connected OK: {client}")
        else:
            print("reqmon:on_connect: Bad connection for {client} Returned code: ", rc)
            client.loop_stop()

    def on_disconnect(client, userdata, rc):
        print("client disconnected ok")

    def on_subscribe(client, userdata, mid, granted_qos):
        print("Subscribed: "+str(mid)+" "+str(granted_qos))

    def on_publish(client, userdata, mid):
        print("reqmon:on_connect: {client} mid= "  ,mid)


    reqmon_client = mqtt.Client(client_id=client_id)
    reqmon_client.tls_set(root_ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_REQUIRED)
    reqmon_client.on_connect = on_connect
    reqmon_client.on_disconnect = on_disconnect
    reqmon_client.on_subscribe = on_subscribe
    reqmon_client.on_publish = on_publish
    reqmon_client.on_message = on_message
    reqmon_client.connect(endpoint, port)

    res, _ = reqmon_client.subscribe(req_topic, qos=1)
    if res != mqtt.MQTT_ERR_SUCCESS:
        print(f'{client_id}: ERROR subscribing to {req_topic}')
        print(f'{client_id}: shutting down')
        # quit_evt.set()
        time.sleep(.25)
        return None
    else:
        reqmon_client.loop_start()

    return reqmon_client


def interrupt_handler(signum, frame):

    quit_evt.set()

    time.sleep(1)
    # sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, interrupt_handler)

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

    ENDPOINT = 'iot.tessa-obs.net'
    PORT = 8883
    CERT = os.path.join(aws_dir, f'{thing_name}.pem.crt')
    KEY = os.path.join(aws_dir, f'{thing_name}.private.pem.key')
    ROOT_CA = os.path.join(aws_dir, 'AmazonRootCA1.pem')

    CLIENT_ID = 'tessa-wg-reqmon'
    REQ_TOPIC = 'tessa/request'
    ACK_TOPIC = 'tessa/reqack'

    # threadsafe quit flag for qhen something goes wrong in a thread
    quit_evt = threading.Event()

    # threadsafe way to pass incoming requests from paho internal loop thread 
    # to main thread that writes to disk and sends ack
    req_q = queue.Queue()

    reqmon_client = paho_client_setup(ENDPOINT, PORT, CLIENT_ID, ROOT_CA, CERT, KEY, REQ_TOPIC, req_q)


    while not quit_evt.is_set():

        try:
            req_dict = req_q.get(block=True, timeout=1)
            req_q.task_done()

        except queue.Empty as e:
            # print(f'reqmon:main: Ignoring empty request.')
            continue

        except Exception as e:
            print(f'reqmon:main: ERROR receiving data msg: {e}')
            continue

        # construct ACK response
        cmd = {
            'rid': req_dict['rid'],
            'rcvd_ts': datetime.datetime.now(tz=datetime.timezone.utc).timestamp(),
            'status': 'OK'
        }
        reqmon_client.publish(ACK_TOPIC, json.dumps(cmd).encode("utf-8"), qos=1)

        time.sleep(1)

    quit_evt.wait()

    # gives threads a chance to exit cleanly    
    reqmon_client.loop_stop()

    # start threads for each client with reference to req_q.
    # reqmon_client thread will:
    #   listen for requets from AWS IoT and
    #   vaidate request
    # if valid, send to req ack client thread using req_q Queue

    # reqack_client thread will
    #   Listen got requests over internal queue
    #   Serialize request to disk  
    #   Send ACk message to 'tessa/reqack' topic at AWS IoT with RequestID of incoming request.
