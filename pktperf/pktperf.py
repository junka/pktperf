#!/usr/bin/env python
""" pktperf with cli options"""
import os
import sys
import signal
from threading import Event, Thread
import time
import argparse
from .pktgen import Pktgen


event = Event()


def parse_options(args):
    """ opt_cli parse args and init the pktgen """
    pktgen = Pktgen(args.interface, args.size, args.dest, args.mac,
                    args.portrange, args.txcsum, args.threads,
                    args.firstthread, args.clone, args.num, args.burst,
                    args.verbose, args.debug, args.ipv6, args.flows,
                    args.flowpkt, args.delay, args.append, args.queuemap,
                    args.tos, args.bps, args.pps, args.frags)

    def sig_exit(_sig, _frame):
        pktgen.result(True, print)
        sys.exit(0)

    tui = Thread(target=ui_func, name="ui", args=(pktgen,), daemon=True)
    signal.signal(signal.SIGINT, sig_exit)
    pktgen.config_queue()
    tui.start()
    pktgen.start()
    event.set()
    tui.join()
    os.kill(os.getpid(), signal.SIGINT)


def ui_func(pktgen):
    """ ui_func prints out statistics """
    while not event.is_set():
        print("")
        pktgen.result(False, print)
        time.sleep(1)


parser = argparse.ArgumentParser(description="pktgen python scripts")
parser.add_argument('-i', '--interface', help="output interface/device",
                    required=True)
parser.add_argument('-s', '--size', help="packet size", default=60,
                    required=False)
parser.add_argument('-d', '--dest', help="destination IP address. CIDR is"
                    " also allowed", required=False)
parser.add_argument('-m', '--mac', help="destination MAC-addr",
                    default="90:e2:ba:ff:ff:ff", required=False)
parser.add_argument('-p', '--portrange',  help="destination PORT range is"
                    " also allowed", required=False)
parser.add_argument('-k', '--txcsum', help="enable UDP tx checksum",
                    required=False, action="store_true")
parser.add_argument('-t', '--threads', help="threads to start", default=1,
                    required=False)
parser.add_argument('-f', '--firstthread', help="index of first thread",
                    default=0, required=False)
parser.add_argument('-c', '--clone', help="SKB clones before alloc new SKB",
                    default=0, required=False)
parser.add_argument('-n', '--num', help="num messages to send per thread,"
                    " 0 means indefinitely", default=100000, required=False)
parser.add_argument('-b', '--burst', help="HW level bursting of SKBs",
                    default=0, required=False)
parser.add_argument('-v', '--verbose', help="verbose", action="store_true")
parser.add_argument('-x', '--debug', help="debug", action="store_true")
parser.add_argument('--ipv6', help="IPv6", required=False, action="store_true")
parser.add_argument('-z', '--flows', help="Limit number of flows", default=0,
                    required=False)
parser.add_argument('-l', '--flowpkt', help="packets number a flow will send",
                    required=False)
parser.add_argument('-w', '--delay', help="Tx Delay value (ns)", default=0,
                    required=False)
parser.add_argument('-a', '--append', help="Script will not reset generator's"
                    "state, but will append its config", required=False,
                    action="store_true")
parser.add_argument('-q', '--queuemap', help="queue mapping with irq affinity",
                    required=False,
                    action="store_true")
parser.add_argument('-o', '--tos', help="tos for IPv4 or traffic class for"
                    " IPv6 traffic", default=0, required=False)
parser.add_argument('-r', '--bps', help="bps rate limit per thread",
                    required=False)
parser.add_argument('-y', '--pps', help="pps rate limit per thread",
                    required=False)
parser.add_argument('-e', '--frags', help="frags number in skb_shared_info",
                    required=False)


def main():
    """ main function entry """
    pargs = parser.parse_args()
    parse_options(pargs)


if __name__ == "__main__":
    main()
