# -*- coding: UTF-8 -*-
"""
classes provide for stats update
"""
from __future__ import division


class PktSar:
    """pkt sar stats class

    calculate the pps and bps from the text
    """

    def __init__(self, start_time, pkt_size = 0) -> None:
        """init sar stats"""
        self.start = start_time
        self._pkts = 0
        self._pkt_size = pkt_size
        self._bytes = 0
        self.last_update = start_time
        self.pps = 0.0
        self.bps = 0.0

    def update(self, pkts_so_far, timestamp, bytes_so_far):
        """update stats"""
        diff_pkts = pkts_so_far - self._pkts
        self._pkts = pkts_so_far
        if self._pkt_size > 0:
            diff_bytes = bytes_so_far - self._bytes
            self._bytes = bytes_so_far
        diff_time = (timestamp - self.last_update) / 1000000
        if diff_time != 0:
            self.last_update = timestamp
            if timestamp == self.start:
                self.pps = 0.0
                self.bps = 0.0
            else:
                self.pps = diff_pkts / diff_time
                if self._pkt_size == 0:
                    self.bps = self.pps * (self._pkt_size + 4)
                else:
                    self.bps = diff_bytes / diff_time

    def get_stats(self):
        """get stats"""
        return self.pps, self.bps
