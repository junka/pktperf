#!/usr/bin/env python
from __future__ import print_function
from __future__ import division
import sys
import subprocess
import re
import time
import datetime
import signal
from decimal import Decimal
from os.path import exists
from os import listdir
import argparse
import netifaces


stop = False


def check_output(args, stderr=None):
    """Run a command and capture its output"""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, shell=False, stderr=stderr)
    out, err = p.communicate()
    return p.returncode, out, err


def print_format_header(tm):
    print(
        "% s% 20s% 16s% 16s% 16s% 16s% 16s % 16s"
        % (
            tm,
            "IFACE",
            "rxpck/s",
            "txpck/s",
            "rxkB/s",
            "txkB/s",
            "txdrop/s",
            "rxdrop/s",
        )
    )


def print_format_string(
    tm,
    port_name,
    diff_rxpkts,
    diff_txpkts,
    diff_rxbytes,
    diff_txbytes,
    diff_txdrops,
    diff_rxdrops,
):
    rxpps = Decimal(diff_rxpkts).quantize(Decimal("0.00"))
    txpps = Decimal(diff_txpkts).quantize(Decimal("0.00"))
    rxbps = Decimal(diff_rxbytes / (1024)).quantize(Decimal("0.00"))
    txbps = Decimal(diff_txbytes / (1024)).quantize(Decimal("0.00"))
    txdrop = Decimal(diff_txdrops / (1024)).quantize(Decimal("0.00"))
    rxdrop = Decimal(diff_rxdrops / (1024)).quantize(Decimal("0.00"))
    print(
        "%s% 20s% 16s% 16s% 16s% 16s% 16s % 16s"
        % (tm, port_name, rxpps, txpps, rxbps, txbps, txdrop, rxdrop)
    )


class PhyStats:
    """
    Implements ethtool -s DEV commands

    @ \todo dynamic port add
    """

    def __init__(self, name):
        self._name = name
        self._rx_pkts = 0
        self._tx_pkts = 0
        self._rx_pkts_phy = 0
        self._tx_pkts_phy = 0
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_bytes_phy = 0
        self._tx_bytes_phy = 0
        self._rx_discard_phy = 0
        self._tx_discard_phy = 0
        self._tx_errors_phy = 0
        self._rx_oob = 0
        self._rx_oversize = 0
        self._times = 0
        self._interval = 1.0

        self._init_rx_pkts = 0
        self._init_tx_pkts = 0
        self._init_rx_pkts_phy = 0
        self._init_tx_pkts_phy = 0
        self._init_rx_bytes = 0
        self._init_tx_bytes = 0
        self._init_rx_bytes_phy = 0
        self._init_tx_bytes_phy = 0
        self._init_rx_discard_phy = 0
        self._init_tx_discard_phy = 0
        self._init_tx_errors_phy = 0
        self._init_rx_oob = 0
        self._init_rx_oversize = 0

        self._delta_rx_pkts = 0
        self._delta_tx_pkts = 0
        self._delta_rx_pkts_phy = 0
        self._delta_tx_pkts_phy = 0
        self._delta_rx_bytes = 0
        self._delta_tx_bytes = 0
        self._delta_rx_bytes_phy = 0
        self._delta_tx_bytes_phy = 0
        self._delta_rx_discard_phy = 0
        self._delta_tx_discard_phy = 0
        self._delta_tx_errors_phy = 0
        self._delta_rx_oob = 0
        self._delta_rx_oversize = 0

        self._type = 0
        self._init_stats()

    def set_interval(self, interval):
        self._interval = interval

    def _init_stats(self):
        ret, stats_info, err = check_output(["ethtool", "-S", self._name])
        if ret != 0:
            return
        if err is not None:
            drv = re.search(r"no stats available", err.decode())
            if drv is not None:
                return
        self._type = 1
        self.update_stats()
        self._init_rx_pkts = self._rx_pkts
        self._init_tx_pkts = self._tx_pkts
        self._init_rx_pkts_phy = self._rx_pkts_phy
        self._init_tx_pkts_phy = self._tx_pkts_phy
        self._init_rx_bytes = self._rx_bytes
        self._init_tx_bytes = self._tx_bytes
        self._init_rx_bytes_phy = self._rx_bytes_phy
        self._init_tx_bytes_phy = self._tx_bytes_phy
        self._init_rx_discard_phy = self._rx_discard_phy
        self._init_tx_discard_phy = self._tx_discard_phy
        self._init_tx_errors_phy = self._tx_errors_phy

        self._delta_rx_pkts = 0
        self._delta_tx_pkts = 0
        self._delta_rx_pkts_phy = 0
        self._delta_tx_pkts_phy = 0
        self._delta_rx_bytes = 0
        self._delta_tx_bytes = 0
        self._delta_rx_bytes_phy = 0
        self._delta_tx_bytes_phy = 0
        self._delta_rx_discard_phy = 0
        self._delta_tx_discard_phy = 0
        self._delta_tx_errors_phy = 0
        self._delta_rx_oob = 0
        self._delta_rx_oversize = 0

    def update_stats(self):
        """
        https://enterprise-support.nvidia.com/s/article/understanding-mlx5-ethtool-counters

        """
        self._times += 1
        _, statsresult, err = check_output(["ethtool", "-S", self._name])
        stats_info = statsresult.decode()
        rxdrop = re.search(r"rx_discards_phy: (\d+)", stats_info)
        txdrop = re.search(r"tx_discards_phy: (\d+)", stats_info)
        rxpkts = re.search(r"rx_packets: (\d+)", stats_info)
        rxpkts_phy = re.search(r"rx_packets_phy: (\d+)", stats_info)
        txpkts = re.search(r"tx_packets: (\d+)", stats_info)
        txpkts_phy = re.search(r"tx_packets_phy: (\d+)", stats_info)
        rxbytes = re.search(r"rx_bytes: (\d+)", stats_info)
        rxbytes_phy = re.search(r"rx_bytes_phy: (\d+)", stats_info)
        txbytes = re.search(r"tx_bytes: (\d+)", stats_info)
        txbytes_phy = re.search(r"tx_bytes_phy: (\d+)", stats_info)
        rxoob = re.search(r"rx_out_of_buffer: (\d+)", stats_info)
        rxoversize = re.search(r"rx_oversize_pkts_phy: (\d+)", stats_info)
        if rxdrop is not None:
            self._delta_rx_discard_phy = int(rxdrop.group(1)) - self._rx_discard_phy
            self._rx_discard_phy = int(rxdrop.group(1))
        if txdrop is not None:
            self._delta_tx_discard_phy = int(txdrop.group(1)) - self._tx_discard_phy
            self._tx_discard_phy = int(txdrop.group(1))
        if rxpkts is not None:
            self._delta_rx_pkts = int(rxpkts.group(1)) - self._rx_pkts
            self._rx_pkts = int(rxpkts.group(1))
        if txpkts is not None:
            self._delta_tx_pkts = int(txpkts.group(1)) - self._tx_pkts
            self._tx_pkts = int(txpkts.group(1))
        if rxbytes is not None:
            self._delta_rx_bytes = int(rxbytes.group(1)) - self._rx_bytes
            self._rx_bytes = int(rxbytes.group(1))
        if txbytes is not None:
            self._delta_tx_bytes = int(txbytes.group(1)) - self._tx_bytes
            self._tx_bytes = int(txbytes.group(1))
        if rxpkts_phy is not None:
            self._delta_rx_pkts_phy = int(rxpkts_phy.group(1)) - self._rx_pkts_phy
            self._rx_pkts_phy = int(rxpkts_phy.group(1))
        if txpkts_phy is not None:
            self._delta_tx_pkts_phy = int(txpkts_phy.group(1)) - self._tx_pkts_phy
            self._tx_pkts_phy = int(txpkts_phy.group(1))
        if rxbytes_phy is not None:
            self._delta_rx_bytes_phy = int(rxbytes_phy.group(1)) - self._rx_bytes_phy
            self._rx_bytes_phy = int(rxbytes_phy.group(1))
        if txbytes_phy is not None:
            self._delta_tx_bytes_phy = int(txbytes_phy.group(1)) - self._tx_bytes_phy
            self._tx_bytes_phy = int(txbytes_phy.group(1))
        if rxoob is not None:
            self._delta_rx_oob = int(rxoob.group(1)) - self._rx_oob
            self._rx_oob = int(rxoob.group(1))
        if rxoversize is not None:
            self._delta_rx_oversize = int(rxoversize.group(1)) - self._rx_oversize
            self._rx_oversize = int(rxoversize.group(1))

    def print_calc_stats(self, ts):
        port_name = self._name
        diff_rxpkts = (self._delta_rx_pkts_phy) / (self._interval)
        diff_txpkts = (self._delta_tx_pkts_phy) / (self._interval)
        diff_rxbytes = (self._delta_rx_bytes_phy) / (self._interval)
        diff_txbytes = (self._delta_tx_bytes_phy) / (self._interval)
        diff_txdrops = self._delta_tx_discard_phy + self._delta_tx_errors_phy
        diff_rxdrops = (self._delta_rx_discard_phy + self._delta_rx_oob) / (
            self._interval
        )
        print_format_string(
            ts,
            port_name,
            diff_rxpkts,
            diff_txpkts,
            diff_rxbytes,
            diff_txbytes,
            diff_txdrops,
            diff_rxdrops,
        )

    def print_average_stats(self):
        port_name = self._name
        diff_rxpkts = (self._rx_pkts_phy - self._init_rx_pkts_phy) / (
            self._interval * (self._times - 1)
        )
        diff_txpkts = (self._tx_pkts_phy - self._init_tx_pkts_phy) / (
            self._interval * (self._times - 1)
        )
        diff_rxbytes = (self._rx_bytes_phy - self._init_rx_bytes_phy) / (
            self._interval * (self._times - 1)
        )
        diff_txbytes = (self._tx_bytes_phy - self._init_tx_bytes_phy) / (
            self._interval * (self._times - 1)
        )
        diff_txdrops = (
            self._tx_discard_phy
            + self._tx_errors_phy
            - self._init_tx_discard_phy
            - self._init_tx_errors_phy
        ) / (self._interval * (self._times - 1))
        diff_rxdrops = (
            self._rx_discard_phy
            + self._rx_oob
            + self._rx_oversize
            - self._init_rx_discard_phy
            - self._init_rx_oob
            - self._init_rx_oversize
        ) / (self._interval * (self._times - 1))
        print_format_string(
            "Average:",
            port_name,
            diff_rxpkts,
            diff_txpkts,
            diff_rxbytes,
            diff_txbytes,
            diff_txdrops,
            diff_rxdrops,
        )


class Bond:
    """
    read slaves for a bond from /proc/sys/class/net/xxx/bonding/slaves
    @ \todo dynamic port add
    """

    def __init__(self, name):
        self._times = 1
        self._name = name
        self._phys = []
        self._initphys = []
        slavespath = "/sys/class/net/%s/bonding/slaves" % name
        if exists(slavespath):
            try:
                with open(slavespath, "r", encoding="utf-8") as f:
                    self.slaves = f.read().split()
            except IOError:
                sys.exit("Error: unable to read slaves for %s", name)
        else:
            sys.exit("Error: unable to find slaves file for %s", name)
        print("%s has slaves %s" % (name, self.slaves))
        for i in self.slaves:
            phy = PhyStats(i)
            if phy._type == 0:
                sys.exit("Error: slaves are not phy ports")
            self._phys.append(phy)

    def set_interval(self, interval):
        for i in self._phys:
            i.set_interval(interval)

    def update_stats(self):
        self._times += 1
        for i in self._phys:
            i.update_stats()

    def print_calc_stats(self, ts):
        for m in self._phys:
            m.print_calc_stats(ts)

    def print_average_stats(self):
        for m in self._phys:
            m.print_average_stats()


def signal_handler():
    global stop
    stop = True


def bonding_list(names) -> (list, list):
    boding_path = "/proc/net/bonding"
    bonds = []
    unbondphys = []
    if exists(boding_path):
        bondnames = listdir(boding_path)
        for i in bondnames:
            if names is None or i in names:
                bonds.append(Bond(i))
                names.remove(i)
    if names is not None:
        for i in names:
            for j in bonds:
                if i in j.slaves:
                    names.remove(i)
    if names is not None and len(names) > 0:
        for i in names:
            p = PhyStats(i)
            if p._type == 1:
                unbondphys.append(p)
    return bonds, unbondphys


def main():
    global stop
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--name", "-n", type=str, action="append")
    parser.add_argument("--interval", "-i", type=float, default=1)
    args = parser.parse_args()
    if args.name is not None and len(args.name) > 1:
        for n in args.name:
            if n not in netifaces.interfaces():
                print("%s is not a valid interface name" % n)
                exit()
    if args.name is not None:
        bonds, phys = bonding_list(args.name)
    else:
        bonds, phys = bonding_list(netifaces.interfaces())
    if len(bonds) == 0 and len(phys) == 0:
        print("no valid devices")
        exit()
    alldev = bonds + phys
    interval = args.interval + 0.0
    for i in alldev:
        i.set_interval(interval)
    signal.signal(signal.SIGINT, lambda signal, frame: signal_handler())
    while stop is False:
        time.sleep(interval)
        ts = datetime.datetime.now().strftime("%I:%M:%S %p")
        print_format_header(ts)
        for i in alldev:
            i.update_stats()
            i.print_calc_stats(ts)
        print("")
    for i in alldev:
        i.print_average_stats()


if __name__ == "__main__":
    main()
