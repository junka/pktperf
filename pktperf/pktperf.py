#!/usr/bin/env python
import os
import sys
import signal
import threading
import time
import click
from .pktgen import Pktgen


__run_flag__ = True

@click.command()
@click.option('-i', help="output interface/device", required=True)
@click.option('-s', help="packet size", default=60, required=False)
@click.option('-d', help="destination IP. CIDR is also allowed", required=False)
@click.option('-m', help="destination MAC-addr", default="90:e2:ba:ff:ff:ff",
              required=False)
@click.option('-p', help="destination PORT range is also allowed", required=False)
@click.option('-k', help="enable UDP tx checksum", required=False, is_flag=True)
@click.option('-t', help="threads to start", default=1, required=False)
@click.option('-f', help="index of first thread", default=0, required=False)
@click.option('-c', help="SKB clones send before alloc new SKB", default=0, required=False)
@click.option('-n', help="num messages to send per thread, 0 means indefinitely",
              default=100000, required=False)
@click.option('-b', help="HW level bursting of SKBs", default=0, required=False)
@click.option('-v', help="verbose", is_flag=True)
@click.option('-x', help="debug", is_flag=True)
@click.option('-ip6', help="IPv6", required=False, is_flag=True)
@click.option('-z', help="Limit number of flows", default=0, required=False)
@click.option('-l', help="packets number a flow will send", required=False)
@click.option('-w', help="Tx Delay value (ns)", default=0, required=False)
@click.option('-a', help="Script will not reset generator's state, but will append its config",
              required=False, is_flag=True)
@click.option('-q', help="queue mapping with irq affinity", required=False, is_flag=True)
@click.option('-o', help="tos for IPv4 or traffic class for IPv6 traffic", default=0, required=False)
@click.option('-r', help="bps rate limit per thread", required=False)
@click.option('-y', help="pps rate limit per thread", required=False)
@click.option('-e', help="frags number in skb_shared_info", required=False)
def opt_cli(i, s, d, m, p, k, t, f, c, n, b, v, x, ip6, z, l, w, a, q, o, r, y, e):
    pg = Pktgen(i, s, d, m, p, k, t, f, c, n, b, v, x, ip6, z, l, w, a, q, o, r, y, e)
    global __run_flag__

    def sig_exit(_sig, _frame):
        pg.result(True, print)
        sys.exit(0)

    tui = threading.Thread(target=ui_func, name="ui", args=(pg,), daemon=True)
    signal.signal(signal.SIGINT, sig_exit)
    pg.config_queue()
    tui.start()
    pg.start()
    __run_flag__ = False
    tui.join()
    os.kill(os.getpid(), signal.SIGINT)

def ui_func(pg):
    global __run_flag__

    while __run_flag__:
        print("")
        pg.result(False, print)
        time.sleep(1)


def main():
    opt_cli()

if __name__ == "__main__":
    main()
