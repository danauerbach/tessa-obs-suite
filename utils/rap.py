import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
import crcmod
from datetime import datetime
import struct
from .const import SYNC_BYTES



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

APP_RESPONSE_TYPE_UNKNOWN           = 0xFFFF
APP_RESPONSE_TYPE_ACK               = 0x8000
APP_RESPONSE_TYPE_STREAMED_SERIES   = 0x8001
APP_RESPONSE_TYPE_RESERVED          = 0x8002
APP_RESPONSE_TYPE_LATEST_SOH        = 0x8003
APP_RESPONSE_TYPE_STATION_INFO      = 0x8004
APP_RESPONSE_TYPE_SETUP_HISTORY     = 0x8005
APP_RESPONSE_TYPE_HISTORY_GET_NEXT  = 0x8006
APP_RESPONSE_TYPE_HISTORY_REPEAT    = 0x8007
APP_RESPONSE_TYPE_STATION_CONFIG    = 0x8008


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

    SYNC_BYTES = SYNC_BYTES

    def __init__(self, packet: bytes, debug=False):

        # set up logging
        logger = logging.getLogger(__name__)
        handler = ConcurrentRotatingFileHandler('peg2ms.log', maxBytes=10*1024*1024, backupCount=50)
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d %(processName)s %(name)s %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",    
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        self.packet = packet
        self.packet_seqnum = -1
        self.debug = debug
        self.app_payload = 0
        self.app_payload_len = 0
        self.payload_length = len(self.packet)
        self.app_packet_type = APP_RESPONSE_TYPE_UNKNOWN
        self.app_pkt_info = ''
        self.app_layer_version = 0
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
        self.crc_bad = False
        self.incomplete_packet = False

        # check that we at least have enough bytes for a complete header...
        if len(packet) < 14:

            print("ERROR: Incomplete Packet ({} bytes). Skipping packet".format(len(packet)))
            self.incomplete_packet = True

        else:

            self.layer_version  = struct.unpack_from('!H', self.packet, 0)[0]
            self.packet_seqnum  = struct.unpack_from('!H', self.packet, 2)[0]
            self.segment_index  = struct.unpack_from('!H', self.packet, 4)[0]
            self.segment_count  = struct.unpack_from('!H', self.packet, 6)[0]
            self.segment_length = struct.unpack_from('!H', self.packet, 8)[0]
            self.segment_hdrcrc = struct.unpack_from('!H', self.packet, 10)[0]
            self.crcPegasus = crcmod.predefined.mkCrcFun('crc-aug-ccitt')

            # check hdr CRC
            this_hdr_CRC = self.crcPegasus(self.packet[:10])
            # check header CRC:
            if self.segment_hdrcrc == this_hdr_CRC:
                pass
                # print("TL Header CRC matches")
            else:
                print("TL Header CRC DOES NOT MATCH (read vs computed):", self.segment_hdrcrc, 'vs', this_hdr_CRC)
                print("Will not process as a timeseries packet")
                self.crc_bad = True

            # get payload and check length is what we expect
            self.segment_payload_raw = self.packet[12:12+self.segment_length]
            if (len(self.segment_payload_raw) < self.segment_length) or \
                (len(self.packet) < self.segment_length + 12 + 2):   ## If segment length from header less than the actual length
                                                                     ##  or
                                                                     ## not enough bytes in packet for segment CRC
                                                                     ## then incomplete packet
                print("ERROR: Incomplete Segment {} vs {}. Skipping packet".format(len(self.segment_payload_raw) , self.segment_length))
                self.incomplete_packet = True

            # if packet complete and good header CRC, read and check full segment payload CRC
            if not (self.crc_bad or self.incomplete_packet):

                # Check payload CRC
                self.segment_payload_crc = struct.unpack_from('!H', self.packet, 12+self.segment_length)[0]
                this_payload_crc = self.crcPegasus(self.segment_payload_raw)
                if self.segment_payload_crc == this_payload_crc:
                    pass
                    # print("Segment payload CRC matches")
                else:
                    print("Segment payload CRC DOES NOT MATCH (read vs computed):", self.segment_payload_crc, "vs", this_payload_crc)
                    print("Will not process as a timeseries packet")
                    self.crc_bad = True

                # Get App packet info
                self.app_layer_version = struct.unpack_from('!H', self.segment_payload_raw, 0)[0]
                # self.app_packet_type   = binascii.hexlify(self.segment_payload_raw[2:4])
                self.app_packet_type   = struct.unpack_from('!H', self.segment_payload_raw, 2)[0]
                self.app_payload_len = struct.unpack_from('!H', self.segment_payload_raw, 4)[0]
                self.app_payload = self.segment_payload_raw[6:6+self.app_payload_len]

        self.app_pkt_info = self.message_info()


    def __str__(self):

        resstr = ''
        resstr += 'Transport.LayerVersion: '  + self.layer_version + '\n'
        resstr += 'Transport.PacketSeqnum: '  + self.packet_seqnum + '\n'
        resstr += 'Transport.SegmentIndex: '  + self.segment_index + '\n'
        resstr += 'Transport.SegmentCount: '  + self.segment_count + '\n'
        resstr += 'Transport.SegmentLength: ' + self.segment_length + '\n'
        resstr += 'Transport.SegmentHDRCRC: ' + self.segment_hdrcrc + '\n'
        resstr += 'Transport.Payload_CRC: '   + self.segment_payload_crc + '\n'

        resstr += 'Application.LayerVersion: ' + self.app_layer_version + '\n'
        resstr += 'Application.PacketType: '   + hex(self.app_packet_type) + '\n'
        resstr += 'Application.Payload_Length: ' + self.app_payload_len + '\n'

        return resstr
    
    def full_packet(self):

        return self.SYNC_BYTES + self.packet

    def store_timeseries_info(self, data_frame_cnt):
    
        self.steim2['byte_cnt'] = data_frame_cnt * 64
        self.steim2['byte_start'] = 20 # data starts at byte 20
        self.steim2['ts'] = struct.unpack_from('!Q', self.app_payload, 0)[0]
        self.steim2['sr'] = struct.unpack_from('!b', self.app_payload, 14)[0]
        self.steim2['sample_cnt'] = struct.unpack_from('!H', self.app_payload, 12)[0]
        self.data_packet_count = data_frame_cnt
        self.channdx = {struct.unpack_from('!B', self.app_payload, 8)[0]}

    def packet_details(self) -> str:

        details = ''

        if self.app_packet_type == APP_RESPONSE_TYPE_ACK:
            details += "               ack packet: "+ self._packet_type_name() + "\n"
            details += "             request type: "+ str(struct.unpack('!H', self.app_payload[0:2])[0]) + "\n"
            details += "              status_code: "+ str(struct.unpack('!H', self.app_payload[2:4])[0]) + "\n"

        elif self.app_packet_type == APP_RESPONSE_TYPE_STREAMED_SERIES:
            details += "Stream Time Series packet: " + self._packet_type_name() + "\n\n"
            self.ts_timestamp_ns = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(self.ts_timestamp_ns/1000000000)
            details += "                timestamp: " + str(self.ts_timestamp_ns) + "\n"
            details += "                           " + dt.isoformat() + "\n"
            self.chan_ndx = struct.unpack_from('!B', self.app_payload, 8)[0]
            details += "               chan index: " + str(struct.unpack_from('!B', self.app_payload, 8)[0])  + "\n"
            details += "               media type: " + str(struct.unpack_from('!H', self.app_payload, 10)[0]) + "\n"
            details += "                # samples: " + str(struct.unpack_from('!H', self.app_payload, 12)[0]) + "\n"
            details += "                sr factor: " + str(struct.unpack_from('!b', self.app_payload, 14)[0]) + "\n"
            details += "            sr multiplier: " + str(struct.unpack_from('!b', self.app_payload, 15)[0]) + "\n"
            details += "           sample bit res: " + str(struct.unpack_from('!B', self.app_payload, 16)[0]) + "\n"
            details += "      data frames per pkt: " + str(struct.unpack_from('!B', self.app_payload, 17)[0]) + "\n"

            data_frame_cnt = struct.unpack_from('!B', self.app_payload, 17)[0]
            self.store_timeseries_info(data_frame_cnt)

        elif self.app_packet_type == APP_RESPONSE_TYPE_LATEST_SOH:
            # ts = struct.unpack_from('!I', self.app_payload, 0)[0]
            # print(ts, type(ts))

            details += " Latest SOH series packet: " + self._packet_type_name() + "\n"
            details += "                timestamp: " + str(struct.unpack_from('!I', self.app_payload, 0)[0]) + "\n"
            details += "            status-uptime: " + str(struct.unpack_from('!I', self.app_payload, 4)[0]) + "\n"
            details += "          status-battvolt: " + str(struct.unpack_from('!f', self.app_payload, 8)[0]) + "\n"
            details += "          status-maincurr: " + str(struct.unpack_from('!f', self.app_payload, 12)[0]) + "\n"
            details += "          status-senscurr: " + str(struct.unpack_from('!f', self.app_payload, 16)[0]) + "\n"
            details += "           status-systemp: " + str(struct.unpack_from('!f', self.app_payload, 20)[0]) + "\n"
            details += "          status-syspress: " + str(struct.unpack_from('!f', self.app_payload, 24)[0]) + "\n"
            details += "              status-soh1: " + str(struct.unpack_from('!f', self.app_payload, 28)[0]) + "\n"
            details += "              status-soh2: " + str(struct.unpack_from('!f', self.app_payload, 32)[0]) + "\n"
            details += "              status-soh3: " + str(struct.unpack_from('!f', self.app_payload, 36)[0]) + "\n"
            details += "              status-soh4: " + str(struct.unpack_from('!f', self.app_payload, 40)[0]) + "\n"

            details += "             gnss-tm2lock: " + str(struct.unpack_from('!I', self.app_payload, 60)[0]) + "\n"
            details += "                 gnss-lat: " + str(struct.unpack_from('!d', self.app_payload, 64)[0]) + "\n"
            details += "                 gnss-lon: " + str(struct.unpack_from('!d', self.app_payload, 72)[0]) + "\n"
            details += "                 gnss-alt: " + str(struct.unpack_from('!f', self.app_payload, 80)[0]) + "\n"
            details += "            gnss-tmuncert: " + str(struct.unpack_from('!I', self.app_payload, 84)[0]) + "\n"
            details += "           gnss-tmlastpps: " + str(struct.unpack_from('!I', self.app_payload, 88)[0]) + "\n"
            details += "             gnss-antstat: " + str(struct.unpack_from('!B', self.app_payload, 92)[0]) + "\n"
            details += "              gnss-extant: " + str(struct.unpack_from('!?', self.app_payload, 93)[0]) + "\n"
            details += "              gnss-satcnt: " + str(struct.unpack_from('!B', self.app_payload, 94)[0]) + "\n"

            details += "               obs-tmstat: " + str(struct.unpack_from('!B', self.app_payload, 95)[0]) + "\n"
            details += "              obs-ssphval: " + str(struct.unpack_from('!I', self.app_payload, 96)[0]) + "\n"
            details += "              obs-ssphrng: " + str(struct.unpack_from('!I', self.app_payload, 100)[0]) + "\n"
            details += "           obs-tmlastsync: " + str(struct.unpack_from('!I', self.app_payload, 104)[0]) + "\n"
            details += "          obs-gnsslockdur: " + str(struct.unpack_from('!I', self.app_payload, 108)[0]) + "\n"
            details += "         obs-systmgnsspps: " + str(struct.unpack_from('!Q', self.app_payload, 112)[0]) + "\n"


        elif self.app_packet_type == APP_RESPONSE_TYPE_STATION_INFO:
            details += "      Station Info packet: " + self._packet_type_name() + "\n"
            details += "               serial num: " + struct.unpack_from('6s', self.app_payload, 0)[0].decode() + "\n"
            details += "               fw version: " + struct.unpack_from('16s', self.app_payload, 38)[0].decode() + "\n"

        elif self.app_packet_type == APP_RESPONSE_TYPE_SETUP_HISTORY:
            start_time_ns = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(start_time_ns/10**9)
            details += "Start Time Available: " + dt.isoformat() + "\n"

        elif self.app_packet_type in [APP_RESPONSE_TYPE_HISTORY_GET_NEXT, 
                                      APP_RESPONSE_TYPE_HISTORY_REPEAT]:
            details += '       Get History packet: ' + self._packet_type_name() + '\n'
            self.ts_timestamp_ns = struct.unpack_from('!Q', self.app_payload, 0)[0]
            dt = datetime.fromtimestamp(self.ts_timestamp_ns/1000000000)
            details += "                timestamp: " + str(self.ts_timestamp_ns) + "\n"
            details += "                           " + dt.isoformat() + "\n"
            details += "               chan index: " + str(struct.unpack_from('!B', self.app_payload, 8)[0])  + "\n"
            details += "               media type: " + str(struct.unpack_from('!H', self.app_payload, 10)[0]) + "\n"
            details += "                # samples: " + str(struct.unpack_from('!H', self.app_payload, 12)[0]) + "\n"
            details += "                sr factor: " + str(struct.unpack_from('!b', self.app_payload, 14)[0]) + "\n"
            details += "            sr multiplier: " + str(struct.unpack_from('!b', self.app_payload, 15)[0]) + "\n"
            details += "           sample bit res: " + str(struct.unpack_from('!B', self.app_payload, 16)[0]) + "\n"
            self.chan_ndx = struct.unpack_from('!B', self.app_payload, 8)[0]

            data_frame_cnt = 63
            self.store_timeseries_info(data_frame_cnt)

        elif self.app_packet_type == APP_RESPONSE_TYPE_STATION_CONFIG:
            details += "Station Configuration packet: " + self._packet_type_name() + "\n"
            details += "                     Network: " + self.net_code + "\n"
            self.net_code = struct.unpack_from('2s', self.app_payload, 2)[0].decode()
            details += "                     Station: " + self.sta_code + "\n"
            self.sta_code = struct.unpack_from('5s', self.app_payload, 4)[0].decode()
            details += " Low Volt Shutdown Threshold: " + str(struct.unpack_from('!I', self.app_payload, 9)[0]) + "\n"
            details += "Low Volt Reconnect Threshold: " + str(struct.unpack_from('!I', self.app_payload, 13)[0]) + "\n"
            details += "          Low Volt Threshold: " + str(struct.unpack_from('!I', self.app_payload, 17)[0]) + "\n"
            details += "         High Volt Threshold: " + str(struct.unpack_from('!I', self.app_payload, 21)[0]) + "\n"
            details += "          Low Curr Threshold: " + str(struct.unpack_from('!I', self.app_payload, 25)[0]) + "\n"
            details += "         High Curr Threshold: " + str(struct.unpack_from('!I', self.app_payload, 29)[0]) + "\n"
            

            details += '\n'
            gnss_bits = struct.unpack_from('!B', self.app_payload, 33)[0]
            gnss_str = self._format_gnss_bits(gnss_bits)
            details += "         GNSS Constellations: " + gnss_str + "\n"

            details += "Low GNSS Sat Count Threshold: " + str(struct.unpack_from('!B', self.app_payload, 42)[0]) + "\n"

            details += '\n'
            con_chan_enable_bits = int(struct.unpack_from('!B', self.app_payload, 57)[0])
            enable_str = self._format_con_chan_enable_bits(con_chan_enable_bits)
            details += " Connector & Channel Enables: " + enable_str + "\n"

            details += '\n'
            ctl_line_level_bits = int(struct.unpack_from('!B', self.app_payload, 58)[0])
            details += " Connector A - Cntl Line Lvl: " + self._format_control_line_lvl_bits(ctl_line_level_bits) + "\n"
            details += "Connector A - Pulse Duration: " + str(struct.unpack_from('!B', self.app_payload, 59)[0]) + "\n"
            details += "   Connector A - Sample Rate: " + str(struct.unpack_from('!H', self.app_payload, 60)[0]) + "\n"
            details += "  Connector A - Harware Gain: " + str(struct.unpack_from('!B', self.app_payload, 62)[0]) + "\n"

            ctl_line_level_bits = int(struct.unpack_from('!B', self.app_payload, 63)[0])
            details += " Connector B - Cntl Line Lvl: " + self._format_control_line_lvl_bits(ctl_line_level_bits) + "\n"
            details += "Connector B - Pulse Duration: " + str(struct.unpack_from('!B', self.app_payload, 64)[0]) + "\n"
            details += "   Connector B - Sample Rate: " + str(struct.unpack_from('!H', self.app_payload, 65)[0]) + "\n"
            details += "  Connector B - Harware Gain: " + str(struct.unpack_from('!B', self.app_payload, 67)[0]) + "\n"

            details += '\n'
            details += '\n'
            details += "          Control Line Setting: " + str(struct.unpack_from('!B', self.app_payload, 88)[0]) + "\n"
            details += "       Control Line 1 Descript: " + struct.unpack_from('10s', self.app_payload, 89)[0].decode() + "\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 99)[0])
            details += "       Control Line 1 Function: " + ctl_func_str + "\n"
            details += "       Control Line 2 Descript: " + struct.unpack_from('10s', self.app_payload, 100)[0].decode() + "\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 110)[0])
            details += "       Control Line 2 Function: " + ctl_func_str + "\n"
            details += "       Control Line 3 Descript: " + struct.unpack_from('10s', self.app_payload, 111)[0].decode() + "\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 121)[0])
            details += "       Control Line 3 Function: " + ctl_func_str + "\n"
            details += "       Control Line 4 Descript: " + struct.unpack_from('10s', self.app_payload, 122)[0].decode() + "\n"
            ctl_func_str = self._format_control_line_function(struct.unpack_from('!B', self.app_payload, 132)[0])
            details += "       Control Line 4 Function: " + ctl_func_str + "\n"

            details += "             SOH Lines Enabled: " + str(struct.unpack_from('!B', self.app_payload, 133)[0]) + "\n"

            details += "          SOH Line 1  Descript: " + struct.unpack_from('10s', self.app_payload, 134)[0].decode() + "\n"
            details += "          SOH Line 1 Threshold: " + str(struct.unpack_from('!f', self.app_payload, 144)[0]) + "\n"
            details += "          SOH Line 2  Descript: " + struct.unpack_from('10s', self.app_payload, 148)[0].decode() + "\n"
            details += "          SOH Line 2 Threshold: " + str(struct.unpack_from('!f', self.app_payload, 158)[0]) + "\n"
            details += "          SOH Line 3  Descript: " + struct.unpack_from('10s', self.app_payload, 162)[0].decode() + "\n"
            details += "          SOH Line 3 Threshold: " + str(struct.unpack_from('!f', self.app_payload, 172)[0]) + "\n"
            details += "          SOH Line 4  Descript: " + struct.unpack_from('10s', self.app_payload, 176)[0].decode() + "\n"
            details += "          SOH Line 4 Threshold: " + str(struct.unpack_from('!f', self.app_payload, 186)[0]) + "\n"

            details += '\n'
            auto_mctr_flags = struct.unpack_from('!B', self.app_payload, 190)[0]
            details += "           Auto Mass Centering: " + 'Enable Low Thresh' if auto_mctr_flags == 0 else 'Enable High Thresh' "\n"
            details += "     Auto Mass Ctr Low  Thresh: " + str(struct.unpack_from('!f', self.app_payload, 191)[0]) + "V\n"
            details += "     Auto Mass Ctr High Thresh: " + str(struct.unpack_from('!f', self.app_payload, 195)[0]) + "V\n"
            details += "Auto Mass Ctr Low Holdoff Time: " + str(struct.unpack_from('!B', self.app_payload, 199)[0]) + "secs\n"
            details += "     Auto Mass Ctr Max Retries: " + str(struct.unpack_from('!B', self.app_payload, 200)[0]) + "\n"
            details += "  Auto Mass Ctr Retry Interval: " + str(struct.unpack_from('!B', self.app_payload, 201)[0]) + "min\n"
        elif self.app_packet_type == APP_RESPONSE_TYPE_UNKNOWN:
            details += 'PACKET ERROR: BAD_CRC:{}   INCOMPLETE:{}'.format(self.crc_bad, self.incomplete_packet)
        else:
            details += 'UNRECOGNIZED RESPONSE packet: ' + hex(self.app_packet_type) + '\n'

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

        res_str = ''
        res_str += 'ASS_ZERO_DEASS_POS '   if (bits & self.ASS_ZERO_DEASS_POS) else ''
        res_str += 'ASS_ZERO_DEASS_HIGHZ ' if (bits & self.ASS_ZERO_DEASS_HIGHZ) else ''
        res_str += 'ASS_POS_DEASS_ZERO '   if (bits & self.ASS_POS_DEASS_ZERO) else ''
        res_str += 'ASS_POS_DEASS_HIGHZ '  if (bits & self.ASS_POS_DEASS_HIGHZ) else ''
        res_str += 'ASS_HIGHZ_DEASS_ZERO ' if (bits & self.ASS_HIGHZ_DEASS_ZERO) else ''
        res_str += 'ASS_HIGHZ_DEASS_POS '  if (bits & self.ASS_HIGHZ_DEASS_POS) else ''

        return res_str

    def _format_con_chan_enable_bits(self, bits) -> str:

        res_str = ''
        res_str += 'CC_A_POW_OUT_EN '   if (bits & self.CC_A_POW_OUT_EN) else ''
        res_str += 'CC_A_SMART_SENSOR ' if (bits & self.CC_A_SMART_SENSOR) else ''
        res_str += 'CC_B_POW_OUT '      if (bits & self.CC_B_POW_OUT) else ''
        res_str += 'CC_CHAN_1_DIG_EN '  if (bits & self.CC_CHAN_1_DIG_EN) else ''
        res_str += 'CC_CHAN_2_DIG_EN '  if (bits & self.CC_CHAN_2_DIG_EN) else ''
        res_str += 'CC_CHAN_3_DIG_EN '  if (bits & self.CC_CHAN_3_DIG_EN) else ''
        res_str += 'CC_CHAN_4_DIG_EN '  if (bits & self.CC_CHAN_4_DIG_EN) else ''

        return res_str

    def _format_gnss_bits(self, gnss_bits) -> str:

        res_str = ''
        res_str += 'EXT_ANT' if (gnss_bits | self.GNSS_USE_EXT_ANT) else ''
        res_str += 'GPS' if (gnss_bits | self.GNSS_GPS) else ''
        res_str += 'GLONASS' if (gnss_bits | self.GNSS_GLONASS) else ''
        res_str += 'GALILEO' if (gnss_bits | self.GNSS_GALILEO) else ''
        res_str += 'BEIDOU' if (gnss_bits | self.GNSS_BEIDOU) else ''
        res_str += 'QZSS' if (gnss_bits | self.GNSS_QZSS) else ''

        return res_str

    def message_info(self) -> str:

        xporthdr_info = ''
        apphdr_info = ''
        pkt_info = ''
        if not (self.crc_bad or self.incomplete_packet):
            if self.debug:
                # get Tansport Layer header/packet info
                xporthdr_info += 'Transport: Layer Version: ' + str(self.layer_version) + '; '
                xporthdr_info += 'Packet Seqnum: '  + str(self.packet_seqnum) + '; '
                xporthdr_info += 'Segment Index: '  + str(self.segment_index) + '; '
                xporthdr_info += 'Segment Count: '  + str(self.segment_count) + '; '
                xporthdr_info += 'Segment Length: ' + str(self.segment_length) + '; '
                xporthdr_info += 'SegmentHDR CRC: ' + str(self.segment_hdrcrc) + '; '
                xporthdr_info += 'Payload CRC: ' + str(self.segment_payload_crc) + '\n'

                # get Application Layer header/packet info
                apphdr_info += 'Application: Layer Version: ' + str(self.app_layer_version) + '\n'
                apphdr_info += 'Packet Type: ' + hex(self.app_packet_type) + '\n'
                apphdr_info += 'Payload Length: ' + str(self.app_payload_len) + '\n'

            # packet details (except seismic binary payload)
            pkt_info = self.packet_details()

        return xporthdr_info + apphdr_info + pkt_info
    
    def header_str(self) -> str:

        hdr = 'INCOMPLETE PACKET HEADER'
        if not self.incomplete_packet:
            hdr = str(self.packet_seqnum) + '   ' + str(self.packet_id()) + '   ' + str(len(self.packet))
        return hdr
    
    def is_timeseries(self) -> bool:

        return (self.app_packet_type in [APP_RESPONSE_TYPE_HISTORY_REPEAT,
                                        APP_RESPONSE_TYPE_HISTORY_GET_NEXT,
                                        APP_RESPONSE_TYPE_STREAMED_SERIES]) and not self.crc_bad

    
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

        if self.app_packet_type == 0xFFFF:
            return 'APP_RESPONSE_TYPE_UNKNOWN'

        return 'UNKNOWN PACKET TYPE: ' + str(self.app_packet_type)

    def packet_id(self) -> str:

        return self._packet_type_name()
