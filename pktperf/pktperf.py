#!/usr/bin/env python
# -*- coding: UTF-8 -*-
""" pktperf with cli options"""
import os
import signal
from threading import Thread, Event
import time
import argparse
from .pktgen import Pktgen, modinfo_check


parser = argparse.ArgumentParser(
    description="pktgen python scripts %s" % modinfo_check(), epilog="\n"
)
parser.add_argument("-i", "--interface", help="output interface/device", required=False)
parser.add_argument("-s", "--size", help="packet size", default=60, required=False)
parser.add_argument(
    "-d",
    "--dst",
    help="destination IP address. CIDR is" " also allowed",
    required=False,
)
parser.add_argument(
    "--src", help="source IP address. CIDR is also allowed", required=False
)
parser.add_argument(
    "-m",
    "--mac",
    help="destination MAC-addr",
    default="90:e2:ba:ff:ff:ff",
    required=False,
)
parser.add_argument(
    "-p",
    "--portrange",
    help="destination PORT range is" " also allowed",
    required=False,
)
parser.add_argument(
    "-k", "--txcsum", help="enable UDP tx checksum", required=False, action="store_true"
)
parser.add_argument(
    "-t", "--threads", help="threads to start", default=1, required=False
)
parser.add_argument(
    "-f", "--firstthread", help="index of first thread", default=0, required=False
)
parser.add_argument(
    "-c", "--clone", help="SKB clones before alloc new SKB", default=0, required=False
)
parser.add_argument(
    "-n",
    "--num",
    help="num messages to send per thread," " 0 means indefinitely",
    default=100000,
    required=False,
)
parser.add_argument(
    "-b", "--burst", help="HW level bursting of SKBs", default=0, required=False
)
parser.add_argument("-v", "--verbose", help="verbose", action="store_true")
parser.add_argument("--debug", help="debug", action="store_true")
parser.add_argument("--flows", help="Limit number of flows", default=0, required=False)
parser.add_argument(
    "--flowpkts", help="packets number a flow will send", required=False
)
parser.add_argument(
    "-w", "--delay", help="Tx Delay value (ns)", default=0, required=False
)
parser.add_argument(
    "--append",
    help="Script will not reset generator's" "state, but will append its config",
    required=False,
    action="store_true",
)
parser.add_argument(
    "-q",
    "--queuemap",
    help="queue mapping with irq affinity",
    required=False,
    action="store_true",
)
parser.add_argument(
    "--tos",
    help="tos for IPv4 or traffic class for IPv6 traffic",
    default=0,
    required=False,
)
parser.add_argument("-r", "--bps", help="bps rate limit per thread", required=False)
parser.add_argument("-y", "--pps", help="pps rate limit per thread", required=False)
parser.add_argument("--frags", help="frags number in skb_shared_info", required=False)
parser.add_argument("--vlan", help="vlan id 0-4095", required=False)
parser.add_argument("--svlan", help="svlan id 0-4095", required=False)
parser.add_argument(
    "--file",
    help="config file for all pktgen parameters, will"
    " override all parameters specified from cmdline",
    required=False,
)

if modinfo_check() == "3.0":
    parser.add_argument("--vni", help="vxlan vni", required=False)
    parser.add_argument(
        "--tundport", help="vxlan udp port", required=False, default=4789
    )
    parser.add_argument("--tundst", help="tunnel outer ip dst", required=False)
    parser.add_argument("--tunsrc", help="tunnerl outer ip src", required=False)
    parser.add_argument("--innerdmac", help="inner dst mac", required=False)
    parser.add_argument("--innersmac", help="inner src mac", required=False)
    parser.add_argument("--microburst", help="enable micro burst model", required=False)
    parser.add_argument(
        "--timeout", help="set timeout for pktgen runs", default=0, type=int
    )
    parser.add_argument(
        "--imix", help="set imix test weight parameter list", required=False
    )


def ui_func(pktgen, event):
    """ui_func prints out statistics"""
    while not event.is_set():
        print("")
        ret = pktgen.result(False, print)
        if ret == 1:
            os.kill(os.getpid(), signal.SIGINT)
        time.sleep(1)
    return 0


def main():
    """main function entry"""
    args = parser.parse_args()
    pktgen = Pktgen(args)

    event = Event()
    tui = Thread(
        target=ui_func,
        name="ui",
        args=(
            pktgen,
            event,
        ),
        daemon=False,
    )

    def sig_exit(_sig, _frame):
        event.set()
        tui.join()
        pktgen.stop()
        pktgen.result(True, print)

    signal.signal(signal.SIGINT, sig_exit)
    signal.signal(signal.SIGALRM, sig_exit)

    if int(args.timeout) > 0:
        signal.alarm(int(args.timeout))
    pktgen.config_queue()
    tui.start()
    pktgen.start()


if __name__ == "__main__":
    main()
