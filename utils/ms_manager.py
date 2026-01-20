import io
from typing import Tuple
from pymseed import MS3TraceList, DataEncoding
from simplemseed import steim2

class MSManager():

    TS_ENCODING_RAW = 1
    TS_ENCODING_STEIM2 = 2
    
    def __init__(self):

        self.ms_filename = ''
        self.ms_file : io.BufferedWriter = None
        self.net_code = ''
        self.sta_code = ''
        self.chan_code = ''
        self.loc_code = ''
        self.sample_rate = 0
        self.source_id = ''

        self.ms_tracelist = MS3TraceList()
        self.ms_recsize = 0

    def __str__(self):

        res = ''
        res += f'Net: {self.net_code}; '
        res += f'Sta; {self.sta_code}; '
        res += f'Chn: {self.chan_code}; '
        res += f'Loc: {self.loc_code}; '
        res += f'S/R: {self.sample_rate}'

        return res

    def set_msfile(self, msfn : str):

        # lose current file, if it exists
        if self.ms_file:
            self.ms_file.close()

        self.ms_filename = msfn

    def set_network(self, net_code : str):

        self.net_code = net_code
        self.update_source_id()


    def set_station(self, sta_code : str):

        self.sta_code = sta_code
        self.update_source_id()


    def set_channel(self, chan_code : str):

        self.chan_code = chan_code
        self.update_source_id()


    def set_location(self, loc_code : str):

        self.loc_code = loc_code
        self.update_source_id()


    def set_sample_rate(self, sample_rate : float):

        self.sample_rate = sample_rate


    def attributes_set(self) -> bool:

        if not self.loc_code: return False
        if not self.chan_code: return False
        if not self.sta_code: return False
        if not self.net_code: return False
        if not self.sample_rate: return False
        return True
    

    def update_source_id(self):

        chanchars = "_".join(self.chan_code)
        self.source_id = f"FDSN:{self.net_code}_{self.sta_code}_{self.loc_code}_{chanchars}"

    def convert_single_packet(self, ts_data : bytes, timestamp : int, sample_cnt : int, ms_recsize : int, format : str):

            self.ms_recsize = max(self.ms_recsize, ms_recsize)

            packed_samples = []
            packed_records = []

            if self.attributes_set():

                if format == self.TS_ENCODING_STEIM2:
                    data_samples = steim2.decodeSteim2(ts_data, sample_cnt)
                elif format == self.TS_ENCODING_RAW:
                    data_samples = ts_data
                else:
                    return

                # print(f"adding data... sample cnt: {len(data_samples)}")
                self.ms_tracelist.add_data(
                    sourceid=self.source_id,
                    data_samples=data_samples,
                    sample_type='i',
                    sample_rate=self.sample_rate,
                    start_time=timestamp,
                )

                (packed_samples, packed_records) = self.ms_tracelist.pack(None,
                                    handlerdata=None,
                                    format_version=2,
                                    record_length=self.ms_recsize,
                                    flush_data=True,
                                    encoding=DataEncoding.STEIM2
                )

            return packed_samples, packed_records


    def add_data(self, ts_data : bytes, timestamp : int, sample_cnt : int, ms_recsize : int, format : str):

        # need to make sure outbound MS recs are at least as large as the largest incoming data
        # so check and save new max if needed
        self.ms_recsize = max(self.ms_recsize, ms_recsize)

        if self.attributes_set():

            if format == self.TS_ENCODING_STEIM2:
                data_samples = steim2.decodeSteim2(ts_data, sample_cnt)
            elif format == self.TS_ENCODING_RAW:
                data_samples = ts_data

            else:
                return

            self.ms_tracelist.add_data(
                sourceid=self.source_id,
                data_samples=data_samples,
                sample_type='i',
                sample_rate=self.sample_rate,
                start_time=timestamp,
                publication_version=1,
            )

    def write(self, handler, handlerdata) -> Tuple[int, int]:

        (packed_samples, packed_records) = self.ms_tracelist.pack(handler,
                               handlerdata=handlerdata,
                               format_version=2,
                               record_length=self.ms_recsize,
                               flush_data=True,
                               encoding=DataEncoding.STEIM2
        )

        return packed_samples, packed_records

    def pack_and_flush_with_handler(self, handler, handler_dict={}) -> Tuple[int,int]:

        (packed_samples, packed_records) = self.ms_tracelist.pack(handler,
                               handlerdata=handler_dict,
                               format_version=2,
                               record_length=self.ms_recsize,
                               flush_data=True,
                               encoding=DataEncoding.STEIM2
        )

        return packed_samples, packed_records
