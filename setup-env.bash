#!/bin/bash

sudo apt install python3-pip

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.tst

# for Pegasus aewrial connection only
sudo usermod -a -G dialout `whoami`