#!/usr/bin/env python3

SYNC_BYTES = b'PT02'

TESSA_NETCODE                       = 'XX'
TESSA_LOCCODE                       = '00'

########################################################
# FOR each station and sample rate provide chan-codes for each pegasus chan ndx (1-4)
# {
#     "sta-code": {
#         '<samplerate-int>': {
#             '1': "LHZ", # pegasus chan ndx 1
#             '2': "LH1", # pegasus chan ndx 2
#             '3': "LH2", # pegasus chan ndx 3
#             '4': "LDI"  # pegasus chan ndx 4
#         },
# }

STA_CHAN_CODE_MAP = {
    "tes1": {
        '1': {
            '1': "LH1",
            '2': "LH2",
            '3': "LHZ",
            '4': "LDI"
        },
        '10': {
            '1': "MH1",
            '2': "MH2", 
            '3': "MHZ",
            '4': "MDI"
        },
        '50': {
            '1': "BH1",
            '2': "BH2",
            '3': "BHZ",
            "4": "BDI"
        },
    },
    "tes2": {
        '1': {
            '1': "LH1",
            '2': "LH2",
            '3': "LHZ",
            '4': "LDI"
        },
        '10': {
            '1': "MH1",
            '2': "MH2", 
            '3': "MHZ",
            '4': "MDI"
        },
        '50': {
            '1': "BH1",
            '2': "BH2",
            '3': "BHZ",
            "4": "BDI"
        },
    },
    "xtes2": {
        '1': {
            '1': "LH1",
            '2': "LH2",
            '3': "LHZ",
            '4': "LDI"
        },
        '10': {
            '1': "MH1",
            '2': "MH2", 
            '3': "MHZ",
            '4': "MDI"
        },
        '50': {
            '1': "BH1",
            '2': "BH2",
            '3': "BHZ",
            "4": "BDI"
        },
    },
    "xtes1": {
        '1': {
            '1': "LH1",
            '2': "LH2",
            '3': "LHZ",
            '4': "LDI"
        },
        '10': {
            '1': "MH1",
            '2': "MH2", 
            '3': "MHZ",
            '4': "MDI"
        },
        '50': {
            '1': "BH1",
            '2': "BH2",
            '3': "BHZ",
            "4": "BDI"
        },
    },
}