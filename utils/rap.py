# from copy import deepcopy
import crcmod
from datetime import datetime
import struct

# from mseedlib import MSTraceList, timestr2nstime
# from simplemseed import decodeSteim2
# from const import *


DATA_SYNC_SEQUENCE                  = 'PT02'

TRANSPORT_LAYER_VERSION             = 0x0001
APP_LAYER_VERSION                   = 0x0001

APP_REQUEST_TYPE_START_STREAM       = 0x0001
APP_REQUEST_TYPE_STOP_STREAM        = 0x0002
APP_REQUEST_TYPE_LATEST_SOH         = 0x0003
APP_REQUEST_TYPE_STATION_INFO       = 0x0004
APP_REQUEST_TYPE_SETUP_HISTORY      = 0x0005
APP_REQUEST_TYPE_GET_NEXT_HISTORY   = 0x0006
APP_REQUEST_TYPE_REPEAT_HISTORY     = 0x0007
APP_REQUEST_TYPE_STATION_CONFIG     = 0x0008

APP_RESPONSE_TYPE_ACK               = 0x8000
APP_RESPONSE_TYPE_STREAMED_SERIES   = 0x8001
APP_RESPONSE_TYPE_RESERVED          = 0x8002
APP_RESPONSE_TYPE_LATEST_SOH        = 0x8003
APP_RESPONSE_TYPE_STATION_INFO      = 0x8004
APP_RESPONSE_TYPE_SETUP_HISTORY     = 0x8005
APP_RESPONSE_TYPE_HISTORY_GET_NEXT  = 0x8006
APP_RESPONSE_TYPE_HISTORY_REPEAT    = 0x8007
APP_RESPONSE_TYPE_STATION_CONFIG    = 0x8008

# MEDIA_TYPE_STEIM2                   = 0x0002

# PEG_CHANCFG_DEFAULT = [
#     {
#         "net": "XX",
#         "sta": "TES1",
#         "chan": {
#             "1": "LHZ",
#             "50": "BHZ"
#         },
#         "loc": "00"
#     },
#     {
#         "net": "XX",
#         "sta": "TES1",
#         "chan": {
#             "1": "LH1",
#             "50": "BH1"
#         },
#         "loc": "00"
#     },
#     {
#         "net": "XX",
#         "sta": "TES1",
#         "chan": {
#             "1": "LH2",
#             "50": "BH2"
#         },
#         "loc": "00"
#     },
#     {
#         "net": "XX",
#         "sta": "TES1",
#         "chan": "LDI",
#         "loc": "00"
#     },
# ]


class RAPPacket:

    ### CONFIGURATION CONSTANTS
    # GNSS Constellation info in station config reponse pkt
    GNSS_USE_EXT_ANT = 0b00000001
    # GNSS_RESERVED    = 0b00000010
    GNSS_GPS         = 0b00000100
    GNSS_GLONASS     = 0b00001000
    GNSS_GALILEO     = 0b00010000
    GNSS_BEIDOU      = 0b00100000
    GNSS_QZSS        = 0b01000000
    # GNSS_RESERVED    = 0b10000000

    # COnnector & Channel Info
    CC_A_POW_OUT_EN   = 0b00000001
    CC_A_SMART_SENSOR = 0b00000010
    CC_B_POW_OUT      = 0b00000100
    CC_CHAN_1_DIG_EN  = 0b00001000
    CC_CHAN_2_DIG_EN  = 0b00010000
    CC_CHAN_3_DIG_EN  = 0b00100000
    CC_CHAN_4_DIG_EN  = 0b01000000

    # COntrol Line Level
    ASS_ZERO_DEASS_POS   = 0b00000001
    ASS_ZERO_DEASS_HIGHZ = 0b00000010
    ASS_POS_DEASS_ZERO   = 0b00000100
    ASS_POS_DEASS_HIGHZ  = 0b00001000
    ASS_HIGHZ_DEASS_ZERO = 0b00010000
    ASS_HIGHZ_DEASS_POS  = 0b00100000
    ###

    SYNC_BYTES = b'PT02'

    def __init__(self, packet: bytes, debug=False):

        self.packet = packet
        self.debug = debug
        self.payload_length = len(self.packet)
        self.layer_version  = struct.unpack_from('!H', self.packet, 0)[0]
        self.packet_seqnum  = struct.unpack_from('!H', self.packet, 2)[0]
        self.segment_index  = struct.unpack_from('!H', self.packet, 4)[0]
        self.segment_count  = struct.unpack_from('!H', self.packet, 6)[0]
        self.segment_length = struct.unpack_from('!H', self.packet, 8)[0]
        self.segment_hdrcrc = struct.unpack_from('!H', self.packet, 10)[0]
        self.crcPegasus = crcmod.predefined.mkCrcFun('crc-aug-ccitt')
        self.steim2 = {
            'byte_cnt': 0,
            'byte_start': 0,
            'sr': 0,
            'ts': 0,
            'sample_cnt': 0
        }
        self.chan_ndx = -1
        # self.chanmap = deepcopy(PEG_CHANCFG_DEFAULT)
        self.chan_code = ''
        self.net_code = ''
        self.sta_code = ''
        self.loc_code = ''
        self.sample_rate = 0
        self.ts_timestamp_ns = 0

        # check hdr CRC
        this_hdr_CRC = self.crcPegasus(self.packet[:10])
        # check header CRC:
        if self.segment_hdrcrc == this_hdr_CRC:
            pass
            # print("TL Header CRC matches")
        else:
            print(f"TL Header CRC DOES NOT MATCH (read vs computed): {self.segment_hdrcrc} vs {this_hdr_CRC}")

        # get payload
        self.segment_payload_raw = self.packet[12:12+self.segment_length]

        # Check payload CRC
        self.segment_payload_crc = struct.unpack_from('!H', self.packet, 12+self.segment_length)[0]
        this_payload_crc = self.crcPegasus(self.segment_payload_raw)
        if self.segment_payload_crc == this_payload_crc:
            pass
            # print("Segment payload CRC matches")
        else:
            print(f"Segment payload CRC DOES NOT MATCH (read vs computed): {self.segment_payload_crc} vs {this_payload_crc}")

        # Get App packet info
        self.app_layer_version = struct.unpack_from('!H', self.segment_payload_raw, 0)[0]
        # self.app_packet_type   = binascii.hexlify(self.segment_payload_raw[2:4])
        self.app_packet_type   = struct.unpack_from('!H', self.segment_payload_raw, 2)[0]
        self.app_payload_len = struct.unpack_from('!H', self.segment_payload_raw, 4)[0]
        self.app_payload = self.segment_payload_raw[6:6+self.app_payload_len]

        app_pkt_info : str = self.message_info()


    def __str__(self):

        resstr: str = ''
        resstr += f'Transport.LayerVersion: {self.layer_version}\n'
        resstr += f'Transport.PacketSeqnum: {self.packet_seqnum}\n'
        resstr += f'Transport.SegmentIndex: {self.segment_index}\n'
        resstr += f'Transport.SegmentCount: {self.segment_count}\n'
        resstr += f'Transport.SegmentLength: {self.segment_length}\n'
        resstr += f'Transport.SegmentHDRCRC: {self.segment_hdrcrc}\n'
        resstr += f'Transport.Payload_CRC: {self.segment_payload_crc}\n'

        resstr += f'Application.LayerVersion: {self.app_layer_version}\n'
        resstr += f'Application.PacketType: {hex(self.app_packet_type)}\n'
        resstr += f'Application.Payload_Length: {self.app_payload_len}\n'

        return resstr
    
    def full_packet(self):

        return self.SYNC_BYTES + self.packet

    def store_timeseries_info(self, data_frame_cnt : int):
    
        self.steim2['byte_cnt'] = data_frame_cnt * 64
        self.steim2['byte_start'] = 20 # data starts at byte 20
        self.steim2['ts'] = struct.unpack_from('!Q', self.app_payload, 0)[0]
        self.steim2['sr'] = struct.unpack_from('!b', self.app_payload, 14)[0]
        self.steim2['sample_cnt'] = struct.unpack_from('!H', self.app_payload, 12)[0]
        self.data_packet_count = data_frame_cnt
        self.channdx = {struct.unpack_from('!B', self.app_payload, 8)[0]}

    # def packet_metadata(self) -> dict:

    #     metadata : dict = {}
    #     metadata["net"]      = 'N/A'
    #     metadata["sta"]      = 'N/A'
    #     metadata["chn"]      = 'N/A'
    #     metadata["loc"]      = 'N/A'
    #     metadata['srfact']   = 0
    #     metadata['srmult']   = 0
    #     metadata['ms_ts_ns'] = 0

    #     if self.is_timeseries():
    #         channdx = struct.unpack_from('!B', self.app_payload, 8)[0]
    #         metadata["net"]      = self.chanmap[channdx-1]["net"]
    #         metadata["sta"]      = self.chanmap[channdx-1]["sta"]
    #         metadata["chn"]      = self.chanmap[channdx-1]["chan"]
    #         metadata["loc"]      = self.chanmap[channdx-1]["loc"]
    #         metadata['srfact']   = struct.unpack_from('!b', self.app_payload, 14)[0]
    #         metadata['srmult']   = struct.unpack_from('!b', self.app_payload, 15)[0]
    #         metadata['ms_ts_ns'] = struct.unpack_from('!Q', self.app_payload, 0)[0]
    #         metadata['sample_rate'] = self.steim2['sr']
    
    #     return metadata


    def packet_details(self) -> str:

        details : str = ''

        if self.app_packet_type == APP_RESPONSE_TYPE_ACK:
            details += f"               ack packet: {self._packet_type_name()}\n"
            details += f"             request type: {struct.unpack('!H', self.app_payload[0:2])[0]}\n"
            details += f"              status_code: {struct.unpack('!H', self.app_payload[2:4])[0]}\n"

        elif self.app_packet_type == APP_RESPONSE_TYPE_STREAMED_SERIES:
            details += f"Stream Time Series packet: {self._packet_type_name()}\n\n"
            self.ts_timestamp_ns = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(self.ts_timestamp_ns/1000000000)
            details += f"                timestamp: {self.ts_timestamp_ns}\n"
            details += f"                           {dt.isoformat()}\n"
            # details += f"                timestamp: {struct.unpack_from('!Q', self.app_payload, 0)[0]}\n"
            self.chan_ndx = struct.unpack_from('!B', self.app_payload, 8)[0]
            details += f"               chan index: {struct.unpack_from('!B', self.app_payload, 8)[0]}\n"
            details += f"               media type: {struct.unpack_from('!H', self.app_payload, 10)[0]}\n"
            details += f"                # samples: {struct.unpack_from('!H', self.app_payload, 12)[0]}\n"
            details += f"                sr factor: {struct.unpack_from('!b', self.app_payload, 14)[0]}\n"
            details += f"            sr multiplier: {struct.unpack_from('!b', self.app_payload, 15)[0]}\n"
            details += f"           sample bit res: {struct.unpack_from('!B', self.app_payload, 16)[0]}\n"
            details += f"      data frames per pkt: {struct.unpack_from('!B', self.app_payload, 17)[0]}\n"

            data_frame_cnt = struct.unpack_from('!B', self.app_payload, 17)[0]
            self.store_timeseries_info(data_frame_cnt)

        elif self.app_packet_type == APP_RESPONSE_TYPE_LATEST_SOH:
            # ts = struct.unpack_from('!I', self.app_payload, 0)[0]
            # print(ts, type(ts))

            details += f" Latest SOH series packet: {self._packet_type_name()}\n"
            details += f"                timestamp: {struct.unpack_from('!I', self.app_payload, 0)[0]}\n"
            details += f"            status-uptime: {struct.unpack_from('!I', self.app_payload, 4)[0]}\n"
            details += f"          status-battvolt: {struct.unpack_from('!f', self.app_payload, 8)[0]}\n"
            details += f"          status-maincurr: {struct.unpack_from('!f', self.app_payload, 12)[0]}\n"
            details += f"          status-senscurr: {struct.unpack_from('!f', self.app_payload, 16)[0]}\n"
            details += f"           status-systemp: {struct.unpack_from('!f', self.app_payload, 20)[0]}\n"
            details += f"          status-syspress: {struct.unpack_from('!f', self.app_payload, 24)[0]}\n"
            details += f"              status-soh1: {struct.unpack_from('!f', self.app_payload, 28)[0]}\n"
            details += f"              status-soh2: {struct.unpack_from('!f', self.app_payload, 32)[0]}\n"
            details += f"              status-soh3: {struct.unpack_from('!f', self.app_payload, 36)[0]}\n"
            details += f"              status-soh4: {struct.unpack_from('!f', self.app_payload, 40)[0]}\n"

            details += f"             gnss-tm2lock: {struct.unpack_from('!I', self.app_payload, 60)[0]}\n"
            details += f"                 gnss-lat: {struct.unpack_from('!d', self.app_payload, 64)[0]}\n"
            details += f"                 gnss-lon: {struct.unpack_from('!d', self.app_payload, 72)[0]}\n"
            details += f"                 gnss-alt: {struct.unpack_from('!f', self.app_payload, 80)[0]}\n"
            details += f"            gnss-tmuncert: {struct.unpack_from('!I', self.app_payload, 84)[0]}\n"
            details += f"           gnss-tmlastpps: {struct.unpack_from('!I', self.app_payload, 88)[0]}\n"
            details += f"             gnss-antstat: {struct.unpack_from('!B', self.app_payload, 92)[0]}\n"
            details += f"              gnss-extant: {struct.unpack_from('!?', self.app_payload, 93)[0]}\n"
            details += f"              gnss-satcnt: {struct.unpack_from('!B', self.app_payload, 94)[0]}\n"

            details += f"               obs-tmstat: {struct.unpack_from('!B', self.app_payload, 95)[0]}\n"
            details += f"              obs-ssphval: {struct.unpack_from('!I', self.app_payload, 96)[0]}\n"
            details += f"              obs-ssphrng: {struct.unpack_from('!I', self.app_payload, 100)[0]}\n"
            details += f"           obs-tmlastsync: {struct.unpack_from('!I', self.app_payload, 104)[0]}\n"
            details += f"          obs-gnsslockdur: {struct.unpack_from('!I', self.app_payload, 108)[0]}\n"
            details += f"         obs-systmgnsspps: {struct.unpack_from('!Q', self.app_payload, 112)[0]}\n"


        elif self.app_packet_type == APP_RESPONSE_TYPE_STATION_INFO:
            details += f"      Station Info packet: {self._packet_type_name()}\n"
            details += f"               serial num: {struct.unpack_from('6s', self.app_payload, 0)[0].decode()}\n"
            details += f"               fw version: {struct.unpack_from('16s', self.app_payload, 38)[0].decode()}\n"

        elif self.app_packet_type == APP_RESPONSE_TYPE_SETUP_HISTORY:
            start_time_ns : int = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(start_time_ns/10**9)
            details += f"Start Time Available: {dt.isoformat()}\n"

        elif self.app_packet_type in [APP_RESPONSE_TYPE_HISTORY_GET_NEXT, 
                                      APP_RESPONSE_TYPE_HISTORY_REPEAT]:
            details += f'       Get History packet: {self._packet_type_name()}\n'
            self.ts_timestamp_ns = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(self.ts_timestamp_ns/1000000000)
            details += f"                timestamp: {self.ts_timestamp_ns}\n"
            details += f"                           {dt.isoformat()}\n"
            details += f"               chan index: {struct.unpack_from('!B', self.app_payload, 8)[0]}\n"
            self.chan_ndx = struct.unpack_from('!B', self.app_payload, 8)[0]
            details += f"               media type: {struct.unpack_from('!H', self.app_payload, 10)[0]}\n"
            details += f"                # samples: {struct.unpack_from('!H', self.app_payload, 12)[0]}\n"
            details += f"                sr factor: {struct.unpack_from('!b', self.app_payload, 14)[0]}\n"
            details += f"            sr multiplier: {struct.unpack_from('!b', self.app_payload, 15)[0]}\n"
            details += f"           sample bit res: {struct.unpack_from('!B', self.app_payload, 16)[0]}\n"

            data_frame_cnt = 63
            self.store_timeseries_info(data_frame_cnt)

        elif self.app_packet_type == APP_RESPONSE_TYPE_STATION_CONFIG:
            details += f"Station Configuration packet: {self._packet_type_name()}\n"
            self.net_code = struct.unpack_from('2s', self.app_payload, 2)[0].decode()
            details += f"                     Network: {self.net_code}\n"
            self.sta_code = struct.unpack_from('5s', self.app_payload, 4)[0].decode()
            details += f"                     Station: {self.sta_code}\n"
            details += f" Low Volt Shutdown Threshold: {struct.unpack_from('!I', self.app_payload, 9)[0]}\n"
            details += f"Low Volt Reconnect Threshold: {struct.unpack_from('!I', self.app_payload, 13)[0]}\n"
            details += f"          Low Volt Threshold: {struct.unpack_from('!I', self.app_payload, 17)[0]}\n"
            details += f"         High Volt Threshold: {struct.unpack_from('!I', self.app_payload, 21)[0]}\n"
            details += f"          Low Curr Threshold: {struct.unpack_from('!I', self.app_payload, 25)[0]}\n"
            details += f"         High Curr Threshold: {struct.unpack_from('!I', self.app_payload, 29)[0]}\n"
            

            details += '\n'
            gnss_bits = struct.unpack_from('!B', self.app_payload, 33)[0]
            gnss_str = self._format_gnss_bits(gnss_bits)
            details += f"         GNSS Constellations: {gnss_str}\n"

            details += f"Low GNSS Sat Count Threshold: {struct.unpack_from('!B', self.app_payload, 42)[0]}\n"

            details += '\n'
            con_chan_enable_bits = int(struct.unpack_from('!B', self.app_payload, 57)[0])
            enable_str = self._format_con_chan_enable_bits(con_chan_enable_bits)
            details += f" Connector & Channel Enables: {enable_str}\n"

            details += '\n'
            ctl_line_level_bits = int(struct.unpack_from('!B', self.app_payload, 58)[0])
            details += f" Connector A - Cntl Line Lvl: {self._format_control_line_lvl_bits(ctl_line_level_bits)}\n"
            details += f"Connector A - Pulse Duration: {struct.unpack_from('!B', self.app_payload, 59)[0]}\n"
            details += f"   Connector A - Sample Rate: {struct.unpack_from('!H', self.app_payload, 60)[0]}\n"
            details += f"  Connector A - Harware Gain: {struct.unpack_from('!B', self.app_payload, 62)[0]}\n"

            ctl_line_level_bits = int(struct.unpack_from('!B', self.app_payload, 63)[0])
            details += f" Connector B - Cntl Line Lvl: {self._format_control_line_lvl_bits(ctl_line_level_bits)}\n"
            details += f"Connector B - Pulse Duration: {struct.unpack_from('!B', self.app_payload, 64)[0]}\n"
            details += f"   Connector B - Sample Rate: {struct.unpack_from('!H', self.app_payload, 65)[0]}\n"
            details += f"  Connector B - Harware Gain: {struct.unpack_from('!B', self.app_payload, 67)[0]}\n"

            details += '\n'

            # net and sta codes are the same for all 4 channel indexes
            # for chndx in range(0,4):
            #     self.chanmap[chndx]["net"] = self.net_code
            #     self.chanmap[chndx]["sta"] = self.sta_code

            # self.chanmap = [
            #     {
            #         "net": self.net_code,
            #         "sta": self.sta_code,
            #         "chan": struct.unpack_from('3s', self.app_payload, 70)[0].decode(),
            #         "loc": struct.unpack_from('2s', self.app_payload, 68)[0].decode()
            #     },
            #     {
            #         "net": self.net_code,
            #         "sta": self.sta_code,
            #         "chan": struct.unpack_from('3s', self.app_payload, 75)[0].decode(),
            #         "loc": struct.unpack_from('2s', self.app_payload, 73)[0].decode()
            #     },
            #     {
            #         "net": self.net_code,
            #         "sta": self.sta_code,
            #         "chan": struct.unpack_from('3s', self.app_payload, 80)[0].decode(),
            #         "loc": struct.unpack_from('2s', self.app_payload, 78)[0].decode()
            #     },
            #     {
            #         "net": self.net_code,
            #         "sta": self.sta_code,
            #         "chan": struct.unpack_from('3s', self.app_payload, 85)[0].decode(),
            #         "loc": struct.unpack_from('2s', self.app_payload, 83)[0].decode()
            #     }
            # ]

            # details += f"             Chan 1 CHN Code: {self.chanmap[0]['chan']}\n"
            # details += f"             Chan 1 LOC Code: {self.chanmap[0]['loc']}\n"
            # details += f"             Chan 2 CHN Code: {self.chanmap[1]['chan']}\n"
            # details += f"             Chan 2 LOC Code: {self.chanmap[1]['loc']}\n"
            # details += f"             Chan 3 CHN Code: {self.chanmap[2]['chan']}\n"
            # details += f"             Chan 3 LOC Code: {self.chanmap[2]['loc']}\n"
            # details += f"             Chan 4 CHN Code: {self.chanmap[3]['chan']}\n"
            # details += f"             Chan 4 LOC Code: {self.chanmap[3]['loc']}\n"

            details += '\n'
            details += f"          Control Line Setting: {(struct.unpack_from('!B', self.app_payload, 88)[0]):b}\n"
            details += f"       Control Line 1 Descript: {struct.unpack_from('10s', self.app_payload, 89)[0].decode()}\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 99)[0])
            details += f"       Control Line 1 Function: {ctl_func_str}\n"
            details += f"       Control Line 2 Descript: {struct.unpack_from('10s', self.app_payload, 100)[0].decode()}\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 110)[0])
            details += f"       Control Line 2 Function: {ctl_func_str}\n"
            details += f"       Control Line 3 Descript: {struct.unpack_from('10s', self.app_payload, 111)[0].decode()}\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 121)[0])
            details += f"       Control Line 3 Function: {ctl_func_str}\n"
            details += f"       Control Line 4 Descript: {struct.unpack_from('10s', self.app_payload, 122)[0].decode()}\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 132)[0])
            details += f"       Control Line 4 Function: {ctl_func_str}\n"

            details += '\n'
            details += f"             SOH Lines Enabled: {struct.unpack_from('!B', self.app_payload, 133)[0]:b}\n"

            details += f"          SOH Line 1  Descript: {struct.unpack_from('10s', self.app_payload, 134)[0].decode()}\n"
            details += f"          SOH Line 1 Threshold: {struct.unpack_from('!f', self.app_payload, 144)[0]}\n"
            details += f"          SOH Line 2  Descript: {struct.unpack_from('10s', self.app_payload, 148)[0].decode()}\n"
            details += f"          SOH Line 2 Threshold: {struct.unpack_from('!f', self.app_payload, 158)[0]}\n"
            details += f"          SOH Line 3  Descript: {struct.unpack_from('10s', self.app_payload, 162)[0].decode()}\n"
            details += f"          SOH Line 3 Threshold: {struct.unpack_from('!f', self.app_payload, 172)[0]}\n"
            details += f"          SOH Line 4  Descript: {struct.unpack_from('10s', self.app_payload, 176)[0].decode()}\n"
            details += f"          SOH Line 4 Threshold: {struct.unpack_from('!f', self.app_payload, 186)[0]}\n"

            details += '\n'
            auto_mctr_flags = struct.unpack_from('!B', self.app_payload, 190)[0]
            details += f"           Auto Mass Centering: {'Enable Low Thresh' if auto_mctr_flags == 0 else 'Enable High Thresh'}\n"
            details += f"     Auto Mass Ctr Low  Thresh: {struct.unpack_from('!f', self.app_payload, 191)[0]} V\n"
            details += f"     Auto Mass Ctr High Thresh: {struct.unpack_from('!f', self.app_payload, 195)[0]} V\n"
            details += f"Auto Mass Ctr Low Holdoff Time: {struct.unpack_from('!B', self.app_payload, 199)[0]} secs\n"
            details += f"     Auto Mass Ctr Max Retries: {struct.unpack_from('!B', self.app_payload, 200)[0]}\n"
            details += f"  Auto Mass Ctr Retry Interval: {struct.unpack_from('!B', self.app_payload, 201)[0]} min\n"
        else:
            details += f'UNRECOGNIZED RESPONSE packet: {hex(self.app_packet_type)}\n'

        return details
    
    def _format_control_line_function(self, val) -> str:

        if val == 0: return 'UNUSED'
        if val == 1: return 'SP/LP; assert=SP'
        if val == 2: return 'SP/LP; assert=LP'
        if val == 3: return 'XYZ/UVW; assert=XYZ'
        if val == 4: return 'XYZ/UVW; assert=UVW'
        if val == 5: return 'Mass Centre'
        if val == 6: return 'Mass lock'
        if val == 7: return 'Mass unlock'
        return 'ERROR: UNKNOWN CONTROL LINE FUNCTION'
    
    def _format_control_line_lvl_bits(self, bits) -> str:

        res_str : str = ''
        res_str += 'ASS_ZERO_DEASS_POS '   if (bits & self.ASS_ZERO_DEASS_POS) else ''
        res_str += 'ASS_ZERO_DEASS_HIGHZ ' if (bits & self.ASS_ZERO_DEASS_HIGHZ) else ''
        res_str += 'ASS_POS_DEASS_ZERO '   if (bits & self.ASS_POS_DEASS_ZERO) else ''
        res_str += 'ASS_POS_DEASS_HIGHZ '  if (bits & self.ASS_POS_DEASS_HIGHZ) else ''
        res_str += 'ASS_HIGHZ_DEASS_ZERO ' if (bits & self.ASS_HIGHZ_DEASS_ZERO) else ''
        res_str += 'ASS_HIGHZ_DEASS_POS '  if (bits & self.ASS_HIGHZ_DEASS_POS) else ''

        return res_str

    def _format_con_chan_enable_bits(self, bits) -> str:

        res_str : str = ''
        res_str += 'CC_A_POW_OUT_EN '   if (bits & self.CC_A_POW_OUT_EN) else ''
        res_str += 'CC_A_SMART_SENSOR ' if (bits & self.CC_A_SMART_SENSOR) else ''
        res_str += 'CC_B_POW_OUT '      if (bits & self.CC_B_POW_OUT) else ''
        res_str += 'CC_CHAN_1_DIG_EN '  if (bits & self.CC_CHAN_1_DIG_EN) else ''
        res_str += 'CC_CHAN_2_DIG_EN '  if (bits & self.CC_CHAN_2_DIG_EN) else ''
        res_str += 'CC_CHAN_3_DIG_EN '  if (bits & self.CC_CHAN_3_DIG_EN) else ''
        res_str += 'CC_CHAN_4_DIG_EN '  if (bits & self.CC_CHAN_4_DIG_EN) else ''

        return res_str

    def _format_gnss_bits(self, gnss_bits) -> str:

        res_str : str = ''
        res_str += 'EXT_ANT' if (gnss_bits | self.GNSS_USE_EXT_ANT) else ''
        res_str += 'GPS' if (gnss_bits | self.GNSS_GPS) else ''
        res_str += 'GLONASS' if (gnss_bits | self.GNSS_GLONASS) else ''
        res_str += 'GALILEO' if (gnss_bits | self.GNSS_GALILEO) else ''
        res_str += 'BEIDOU' if (gnss_bits | self.GNSS_BEIDOU) else ''
        res_str += 'QZSS' if (gnss_bits | self.GNSS_QZSS) else ''

        return res_str

    def message_info(self) -> str:

        xporthdr_info : str = ''
        apphdr_info : str = ''
        if self.debug:
            # get Tansport Layer header/packet info
            xporthdr_info += f'Transport: Layer Version: {self.layer_version}; '
            xporthdr_info += f'Packet Seqnum: {self.packet_seqnum}; '
            xporthdr_info += f'Segment Index: {self.segment_index}; '
            xporthdr_info += f'Segment Count: {self.segment_count}; '
            xporthdr_info += f'Segment Length: {self.segment_length}; '
            xporthdr_info += f'SegmentHDR CRC: {self.segment_hdrcrc}; '
            xporthdr_info += f'Payload CRC: {self.segment_payload_crc}\n'

            # get Application Layer header/packet info
            apphdr_info += f'Application: Layer Version: {self.app_layer_version}; '
            apphdr_info += f'Packet Type: {hex(self.app_packet_type)}; '
            apphdr_info += f'Payload Length: {self.app_payload_len}\n'

        # packet details (except seismic binary payload)
        pkt_info : str = self.packet_details()

        return xporthdr_info + apphdr_info + pkt_info
    
    def header_str(self) -> str:

        hdr = f'{self.packet_seqnum:<10} {self.packet_id():<35} {len(self.packet)}'
        return hdr
    
    def is_timeseries(self) -> bool:

        return self.app_packet_type in [APP_RESPONSE_TYPE_HISTORY_REPEAT,
                                        APP_RESPONSE_TYPE_HISTORY_GET_NEXT,
                                        APP_RESPONSE_TYPE_STREAMED_SERIES]

    
    def _packet_type_name(self) -> str:

        if self.app_packet_type == 0x0001:
            return 'APP_REQUEST_TYPE_START_STREAM'
        if self.app_packet_type == 0x0002:
            return 'APP_REQUEST_TYPE_STOP_STREAM'
        if self.app_packet_type == 0x0003:
            return 'APP_REQUEST_TYPE_LATEST_SOH'
        if self.app_packet_type == 0x0004:
            return 'APP_REQUEST_TYPE_STATION_INFO'
        if self.app_packet_type == 0x0005:
            return 'APP_REQUEST_TYPE_SETUP_HISTORY'
        if self.app_packet_type == 0x0006:
            return 'APP_REQUEST_TYPE_GET_NECXT_HISTORY'
        if self.app_packet_type == 0x0007:
            return 'APP_REQUEST_TYPE_REPEAT_HISTORY'
        if self.app_packet_type == 0x0008:
            return 'APP_REQUEST_TYPE_STATION_CONFIG'
        if self.app_packet_type == 0x8000:
            return 'APP_RESPONSE_TYPE_ACK'
        if self.app_packet_type == 0x8001:
            return 'APP_RESPONSE_TYPE_STREAMED_SERIES'
        if self.app_packet_type == 0x8002:
            return 'APP_RESPONSE_TYPE_RESERVED'
        if self.app_packet_type == 0x8003:
            return 'APP_RESPONSE_TYPE_LATEST_SOH'
        if self.app_packet_type == 0x8004:
            return 'APP_RESPONSE_TYPE_STATION_INFO'
        if self.app_packet_type == 0x8005:
            return 'APP_RESPONSE_TYPE_SETUP_HISTORY'
        if self.app_packet_type == 0x8006:
            return 'APP_RESPONSE_TYPE_HISTORY_GET_NEXT'
        if self.app_packet_type == 0x8007:
            return 'APP_RESPONSE_TYPE_HISTORY_REPEAT'
        if self.app_packet_type == 0x8008:
            return 'APP_RESPONSE_TYPE_STATION_CONFIG'

        return f'UNKNOWN PACKET TYPE {self.app_packet_type}'

    def packet_id(self) -> str:

        return self._packet_type_name()
