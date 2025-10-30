#!/usr/bin/env python3

import argparse
import base64
import datetime
import glob
import logging
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



def paho_client_setup(endpoint, port, client_id, root_ca, cert, key, req_topic, req_q):

    logger = logging.getLogger("reqmon")


    def on_message(client, userdata, message):

        try:
            msg_str = message.payload.decode('utf-8')
            msg_dict = json.loads(msg_str)
            req_q.put(msg_dict)

        except Exception as e:
            # Never let an exception escape a callback
            print("reqmon:ON_MESSAGE ERROR:", e)
            # optionally publish an error ack, but keep it short & non-blocking

    def on_connect(client, userdata, flags, rc):
        try:
            if rc != 0:
                print("reqmon:ON_CONNECT error rc={} (will auto-retry)".format(rc))
                return

            res, mid = client.subscribe(req_topic, qos=1)
            if res != mqtt.MQTT_ERR_SUCCESS:
                print("ERROR subscribing to {}: {}".format(req_topic, res))

            logger.error("reqmon:ON_CONNECT rc={}".format(rc))
            if rc in (4, 5):
                threading.Timer(5.0, client.reconnect).start()

        except Exception as e:
            logger.error("reqmon:on_connect ERROR:", e)


    def on_disconnect(client, userdata, rc):
        logger.warning("reqmon:ON_DISCONNECT rc={}".format(rc))

    def on_subscribe(client, userdata, mid, granted_qos):
        logger.info("Subscribed: "+str(mid)+" "+str(granted_qos))

    def on_publish(client, userdata, mid):
        logger.info("reqmon:on_publish: " + str(mid) + " published successfully.")


    reqmon_client = mqtt.Client(client_id=client_id, clean_session=False, protocol=mqtt.MQTTv311)
    # reqmon_client.tls_set_context(ctx)
    reqmon_client.enable_logger()
    reqmon_client.tls_set(root_ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_REQUIRED)
    reqmon_client.tls_insecure_set(False)            # don’t bypass verification
    reqmon_client.on_connect = on_connect
    reqmon_client.on_disconnect = on_disconnect
    reqmon_client.on_subscribe = on_subscribe
    reqmon_client.on_publish = on_publish
    reqmon_client.on_message = on_message
    reqmon_client.reconnect_delay_set(min_delay=1, max_delay=20)
    reqmon_client.loop_start()
    time.sleep(0.25)
    reqmon_client.connect_async(endpoint, port, keepalive=20, clean_start=False)
    print('reqmon:paho_client_setup: starting mqtt loop....')

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
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, interrupt_handler)

    logging.basicConfig(
        level=logging.DEBUG,  # show DEBUG and up
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("reqmon")

    aws_dir = os.getenv('TESSA_AWS_DIR')
    if not aws_dir:
        logger.error('ERROR: TESSA_AWS_DIR env var does not exist. Quitting...', file=sys.stderr)
        sys.exit(1)
    
    thing_name = os.getenv('TESSA_WG_THING_NAME')
    if not thing_name:
        logger.error('ERROR: TESSA_WG_THING_NAME env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    DATA_ROOT_DIR = os.getenv('TESSA_DATA_ROOT')
    if not DATA_ROOT_DIR:
        logger.error('ERROR: TESSA_DATA_ROOT env var does not exist. Quitting....', file=sys.stderr)
        sys.exit(1)

    ENDPOINT = 'iot.tessa-obs.net'
    PORT = 8883
    CERT = os.path.join(aws_dir, thing_name+'.pem.crt')
    KEY = os.path.join(aws_dir, thing_name+'.private.pem.key')
    ROOT_CA = os.path.join(aws_dir, 'AmazonRootCA1.pem')
    CLIENT_ID = thing_name
    REQ_TOPIC = 'tessa/request'
    ACK_TOPIC = 'tessa/reqack'

    print('reqmon: CLIENTID:', CLIENT_ID)
    print('reqmon: ENDPOINT:', ENDPOINT)
    print('reqmon: PORT:    ', PORT)
    print('reqmon: CERT:    ', CERT)
    print('reqmon:  KEY:    ', KEY)
    print('reqmon: ROOT:    ', ROOT_CA)

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

            msgres, errmsg = validate_request(req_dict)
            req_dict['status'] = msgres
            req_dict['errmsg'] = errmsg
            req_dict['rcvd_ts'] = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

            rc, mid = reqmon_client.publish(ACK_TOPIC, json.dumps(req_dict).encode("utf-8"), qos=0)
            if rc != mqtt.MQTT_ERR_SUCCESS:
                logger.error("publish to {} failed rc={}".format(ACK_TOPIC, rc))

            if req_dict['status'].upper() == 'OK':
                write_request(DATA_ROOT_DIR, req_dict)

        except queue.Empty as e:
            logger.info('reqmon:main: no msg rcvd')
            continue

        except Exception as e:
            logger.error('reqmon:main: ERROR receiving data msg:', e)
            continue

        # time.sleep(1)

    quit_evt.wait()

    # gives threads a chance to exit cleanly    
    reqmon_client.loop_stop()
    reqmon_client.disconnect()
    
