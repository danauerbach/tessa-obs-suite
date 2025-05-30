#!/usr/bin/env python3

import argparse
import base64
import datetime
import glob
import os
from pathlib import Path
import queue
import shutil
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

    def validate_request(msg):

        errmsg = ''
        if not msg.get('rid'):
            return 'ERR', 'MISSING FIELD: "rid" required in request'

        if not msg.get('sta'):    
            return 'ERR', 'MISSING FIELD: "sta" required in request'
            
        if not msg.get('beg'):    
            return 'ERR', 'MISSING FIELD: "beg" required in request'

        if not msg.get('end'):    
            return 'ERR', 'MISSING FIELD: "end" required in request'

        if not msg.get('chnbm'):    
            return 'ERR', 'MISSING FIELD: "chnbm" required in request'

        begts = msg.get('beg')
        endts = msg.get('end')
        if begts > endts:
            return 'ERR', 'BEG date later than END date'

        if msg.get('chnbm') not in range(1,16):
            return 'ERR', 'CHNBM invalid. must be 1-15'

        return 'OK', ''

    def on_message(client, userdata, message):

        msg_str = message.payload.decode('utf-8')
        print('reqmon:on_msg:', msg_str)
        msg_dict = json.loads(msg_str)
        
        msgres, errmsg = validate_request(msg_dict)
        msg_dict['status'] = msgres
        msg_dict['errmsg'] = errmsg
        msg_dict['rcvd_ts'] = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

        req_q.put(msg_dict)

    def on_connect(client, userdata, flags, rc):
        if rc != 0:
            print("reqmon:on_connect: Bad connection for {} Returned code: {}".format(client, rc))
            client.loop_stop()
        else:
            print('reqmon:connected')
            res, _ = client.subscribe(req_topic, qos=1)
            if res != mqtt.MQTT_ERR_SUCCESS:
                print('client {}: ERROR subscribing to {}'.format(client_id, req_topic))
                print('shutting down')
                # quit_evt.set()
                time.sleep(.25)
                return None
            else:
                print("client {}: connected and subscribed to topic {}".format(client_id, req_topic))

    def on_disconnect(client, userdata, rc):
        print("client disconnected ok")

    def on_subscribe(client, userdata, mid, granted_qos):
        print("Subscribed: "+str(mid)+" "+str(granted_qos))

    def on_publish(client, userdata, mid):
        print("reqmon:on_publish: {} mid= ".format(client,mid))


    reqmon_client = mqtt.Client(client_id=client_id)
    reqmon_client.tls_set(root_ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_REQUIRED)
    reqmon_client.on_connect = on_connect
    reqmon_client.on_disconnect = on_disconnect
    reqmon_client.on_subscribe = on_subscribe
    reqmon_client.on_publish = on_publish
    reqmon_client.on_message = on_message
    reqmon_client.connect(endpoint, port, keepalive=600)

    # res, _ = reqmon_client.subscribe(req_topic, qos=1)
    # if res != mqtt.MQTT_ERR_SUCCESS:
    #     print('Client {}: ERROR subscribing to {}'.format(client_id, req_topic))
    #     print('shutting down')
    #     # quit_evt.set()
    #     time.sleep(.25)
    #     return None
    # else:
    print('reqmon:paho_client_setup: starting mqtt loop....')
    reqmon_client.loop_start()

    return reqmon_client


def write_request(target_dir, reqdict):

    reqts = reqdict['reqts']
    rid = reqdict['rid']
    sta = reqdict['sta']

    req_fn = "{}_{}_{}.req".format(sta.upper(), reqdict['chnbm'], rid)
    req_path = os.path.join(target_dir, sta.upper(), 'requests')
    if not os.path.exists(req_path):
        os.makedirs(req_path, exist_ok=True)

    req_fn = os.path.join(req_path, req_fn)

    with open(req_fn, 'wt') as reqfl:
        # reqrec = f"{rid}, {sta.upper()}, {reqdict['chnbm']}, {reqdict['beg']}, {reqdict['end']}\n"
        reqrec = "{}, {}, {}, {}, {}\n".format(rid, sta.upper(), reqdict['chnbm'], reqdict['beg'], reqdict['end'])
        reqfl.write(reqrec)

    shutil.chown(req_fn, user='tessa', group='tessa')


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
    CERT = os.path.join(aws_dir, thing_name+'.pem.crt')
    KEY = os.path.join(aws_dir, thing_name+'.private.pem.key')
    ROOT_CA = os.path.join(aws_dir, 'AmazonRootCA1.pem')


    CLIENT_ID = thing_name
    REQ_TOPIC = 'tessa/request'
    ACK_TOPIC = 'tessa/reqack'

    print('reqmon: ENDPOINT: {}', ENDPOINT)
    print('reqmon: PORT: {}', PORT)
    print('reqmon: CERT: {}', CERT)
    print('reqmon:  KEY: {}', KEY)
    print('reqmon: ROOT: {}', ROOT_CA)

    # threadsafe quit flag for qhen something goes wrong in a thread
    quit_evt = threading.Event()

    # threadsafe way to pass incoming requests from paho internal loop thread 
    # to main thread that writes to disk and sends ack
    req_q = queue.Queue()

    reqmon_client = paho_client_setup(ENDPOINT, PORT, CLIENT_ID, ROOT_CA, CERT, KEY, REQ_TOPIC, req_q)


    while not quit_evt.is_set():

        try:
            req_dict = req_q.get(block=True, timeout=5)
            req_q.task_done()
            reqmon_client.publish(ACK_TOPIC, json.dumps(req_dict).encode("utf-8"), qos=1)
            if req_dict['status'].upper() == 'OK':
                write_request(DATA_ROOT_DIR, req_dict)

        except queue.Empty as e:
            print('reqmon:main: no msg rcvd')
            continue

        except Exception as e:
            print('reqmon:main: ERROR receiving data msg:', e)
            continue

        # time.sleep(1)

    quit_evt.wait()

    # gives threads a chance to exit cleanly    
    reqmon_client.loop_stop()
    reqmon_client.disconnect()
    
