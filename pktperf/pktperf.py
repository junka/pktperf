#!/usr/bin/env python
import click
import os
import signal
import threading
import time
import curses
import sys
from .pktgen import Pktgen


run_flag = True
screen_y = 0

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
def opt_cli(i, s, d, m, p, k, t, f, c, n, b, v, x, ip6, z, l, w, a, q):
    pg = Pktgen(i, s, d, m, p, k, t, f, c, n, b, v, x, ip6, z, l, w, a, q)
    global run_flag

    def sig_exit(sig, frame):
        curses.endwin()
        pg.result(True, print)
        sys.exit(0)

    stdscr = curses_gui()
    tui = threading.Thread(target=ui_func, name="ui", args=(pg, stdscr), daemon=True)
    signal.signal(signal.SIGINT, sig_exit)
    pg.config_queue()
    tui.start()
    pg.start()
    run_flag = False
    tui.join()
    os.kill(os.getpid(), signal.SIGINT)

def ui_func(pg, stdscr):
    
    global screen_y
    
    def curse_str(str):
        global screen_y
        stdscr.addstr(screen_y, 0, str)
        screen_y += 1
        
    while run_flag:
        stdscr.clear()
        screen_y = 0
        pg.result(False, curse_str)
        time.sleep(1)
        stdscr.refresh()

def curses_gui():
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    return stdscr

def main():
    opt_cli()

if __name__ == "__main__":
    main()
