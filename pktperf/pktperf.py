#!/usr/bin/env python
import os
import sys
import signal
import threading
import time
import argparse
from .pktgen import Pktgen


__run_flag__ = True


def opt_cli(args):
    pktgen = Pktgen(args.interface, args.size, args.dest, args.mac,
                    args.portrange, args.txcsum, args.threads, args.firstthread,
                    args.clone, args.num, args.burst, args.verbose, args.debug,
                    args.ipv6, args.flows, args.flowpkt, args.delay,
                    args.append, args.queuemap, args.tos, args.bps,
                    args.pps, args.frags)
    # pktgen = Pktgen(i, s, d, m, p, k, t, f, c, n, b, v, x, ip6, z, l, w, a, q, o, r, y, e)
    global __run_flag__

    def sig_exit(_sig, _frame):
        pktgen.result(True, print)
        sys.exit(0)

    tui = threading.Thread(target=ui_func, name="ui", args=(pktgen,), daemon=True)
    signal.signal(signal.SIGINT, sig_exit)
    pktgen.config_queue()
    tui.start()
    pktgen.start()
    __run_flag__ = False
    tui.join()
    os.kill(os.getpid(), signal.SIGINT)


def ui_func(pktgen):
    global __run_flag__

    while __run_flag__:
        print("")
        pktgen.result(False, print)
        time.sleep(1)


parser = argparse.ArgumentParser(description="pktgen python scripts")
parser.add_argument('-i', '--interface', help="output interface/device", required=True)
parser.add_argument('-s', '--size', help="packet size", default=60, required=False)
parser.add_argument('-d', '--dest', help="destination IP. CIDR is also allowed", required=False)
parser.add_argument('-m', '--mac', help="destination MAC-addr", default="90:e2:ba:ff:ff:ff", required=False)
parser.add_argument('-p', '--portrange',  help="destination PORT range is also allowed", required=False)
parser.add_argument('-k', '--txcsum', help="enable UDP tx checksum", required=False, action="store_true")
parser.add_argument('-t', '--threads', help="threads to start", default=1, required=False)
parser.add_argument('-f', '--firstthread', help="index of first thread", default=0, required=False)
parser.add_argument('-c', '--clone', help="SKB clones send before alloc new SKB", default=0, required=False)
parser.add_argument('-n', '--num', help="num messages to send per thread, 0 means indefinitely",
              default=100000, required=False)
parser.add_argument('-b', '--burst', help="HW level bursting of SKBs", default=0, required=False)
parser.add_argument('-v', '--verbose', help="verbose", action="store_true")
parser.add_argument('-x', '--debug', help="debug", action="store_true")
parser.add_argument('--ipv6', help="IPv6", required=False, action="store_true")
parser.add_argument('-z', '--flows', help="Limit number of flows", default=0, required=False)
parser.add_argument('-l', '--flowpkt', help="packets number a flow will send", required=False)
parser.add_argument('-w', '--delay', help="Tx Delay value (ns)", default=0, required=False)
parser.add_argument('-a', '--append', help="Script will not reset generator's state, but will append its config",
              required=False, action="store_true")
parser.add_argument('-q', '--queuemap', help="queue mapping with irq affinity", required=False, action="store_true")
parser.add_argument('-o', '--tos', help="tos for IPv4 or traffic class for IPv6 traffic",
              default=0, required=False)
parser.add_argument('-r', '--bps', help="bps rate limit per thread", required=False)
parser.add_argument('-y', '--pps', help="pps rate limit per thread", required=False)
parser.add_argument('-e', '--frags', help="frags number in skb_shared_info", required=False)

if __name__ == "__main__":
    args = parser.parse_args()
    opt_cli(args)
