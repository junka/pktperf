#!/usr/bin/env python
import sys
import re
import os
import netaddr


class Pktgen:

    def __init__(self, dev, pkt_size, dest_ip, dest_mac, dst_port, csum, threads,
                 first_thread, clone, num, burst, verbose, debug,
                 ip6, flows, flow_len, tx_delay, append) -> None:
        mod = "/proc/net/pktgen"
        is_exists = os.path.exists(mod)
        if is_exists is False:
            print("no pktgen mod\nPlease do modprobe pktgen")
            sys.exit(0)
        self.pgdev = dev
        self.pkt_size = int(pkt_size)
        self.dst_mac = dest_mac
        self.ipv6 = ip6
        if dest_ip is None:
            if ip6 is True:
                dest_ip = "FD00::1"
            else:
                dest_ip = "198.18.0.42"
        try:
            net = netaddr.IPNetwork(dest_ip)
        except:
            print("invalid ip address format")
            sys.exit()
        ip_list = list(net)
        if ip_list[0].version == 6:
            self.ipv6 = True
        self.dst_ip_min = ip_list[0]
        self.dst_ip_max = ip_list[-1]
        self.dst_port_max = None
        self.dst_port_min = None
        if dst_port is not None:
            ports = dst_port.split('-')
            if len(ports) == 2:
                self.dst_port_max = int(ports[1])
            elif len(ports) == 1:
                self.dst_port_max = int(ports[0])
            self.dst_port_min = int(ports[0])
        self.csum = csum
        self.debug = debug
        self.verbose = verbose
        self.append = append
        if clone is not None:
            self.clone = int(clone)
        self.num = int(num)
        if burst is not None:
            self.burst = int(burst)
        if threads is not None:
            self.threads = int(threads)
        if first_thread is not None:
            self.first_thread = int(first_thread)
        if tx_delay is not None:
            self.tx_delay = int(tx_delay)
        if self.os_check() is False:
            sys.exit()

    # pg_ctrl()   control "pgctrl" (/proc/net/pktgen/pgctrl)
    def pg_ctrl(self, cmd) -> None:
        pgctrl = "/proc/net/pktgen/pgctrl"
        if cmd not in ["start", "stop", "reset"]:
            print("pgctrl do not support cmd %s" % cmd)
            sys.exit(1)
        try:
            f = open(pgctrl, 'r+')
        except Exception as e:
            print("Error: Cannot open %s, error %s" % (pgctrl, e))
            sys.exit(1)
        try:
            f.write("%s\n" % cmd)
            f.flush()
            f.close()
        except Exception as e:
            print("Error: Cannot write or close fail, error %s" % e)
            sys.exit(1)

    # pg_set()    control setup of individual devices
    def pg_set(self, dev, flag) -> None:
        pgdev = "/proc/net/pktgen/%s" % dev
        try:
            f = open(pgdev, "r+")
        except:
            print("Error: Cannot open %s" % (pgdev))
            sys.exit(1)
        try:
            f.write("%s\n" % flag)
            f.close()
        except:
            print("Error: Cannot write or close fail")
            sys.exit(1)

    # pg_thread() control the kernel threads and binding to devices
    def pg_thread(self, thread, cmd) -> None:
        pgthread = "/proc/net/pktgen/kpktgend_%d" % thread
        try:
            f = open(pgthread, "w")
        except:
            print("Error: Cannot open %s" % (pgthread))
            sys.exit(1)
        try:
            f.write("%s\n" % cmd)
            f.close()
        except:
            print("Error: Cannot write or close fail")
            sys.exit(1)

    # pktgen is supported on Linux only
    def os_check(self):
        if os.name == "posix":
            return True
        else:
            return False

    def reset(self):
        self.pg_ctrl("reset")

    def config_queue(self):
        # General cleanup everything since last run
        if self.append is False:
            self.reset()

        # Threads are specified with parameter -t value in $THREADS
        for ti in range(self.first_thread, self.first_thread + self.threads): 
            # The device name is extended with @name, using thread number to
            # make then unique, but any name will do.
            dev= "%s@%d" % (self.pgdev , ti)

            # Add remove all other devices and add_device $dev to thread
            if self.append is False:
                self.pg_thread(ti, "rem_device_all")
            self.pg_thread(ti, "add_device %s" % dev)

            # Notice config queue to map to cpu (mirrors smp_processor_id())
            # It is beneficial to map IRQ /proc/irq/*/smp_affinity 1:1 to CPU number
            self.pg_set(dev, "flag QUEUE_MAP_CPU")

            # Base config of dev
            self.pg_set(dev, "count %d" % self.num)
            self.pg_set(dev, "clone_skb %d" % self.clone)
            self.pg_set(dev, "pkt_size %d" % self.pkt_size)
            self.pg_set(dev, "delay %d" % self.tx_delay)

            # Flag example disabling timestamping
            self.pg_set(dev, "flag NO_TIMESTAMP")

            # Destination
            self.pg_set(dev, "dst_mac %s" % (self.dst_mac))
            if self.ipv6 is True:
                self.pg_set(dev, "dst_min6 %s" % (self.dst_ip_min))
                self.pg_set(dev, "dst_max6 %s" % (self.dst_ip_max))
            else:
                self.pg_set(dev, "dst_min %s" % (self.dst_ip_min))
                self.pg_set(dev, "dst_max %s" % (self.dst_ip_max))

            if self.dst_port_max is not None:
            # Single destination port or random port range
                self.pg_set(dev, "flag UDPDST_RND")
                self.pg_set(dev, "udp_dst_min %d" % (self.dst_port_min))
                self.pg_set(dev, "udp_dst_max %d" % (self.dst_port_max))

            if self.csum is True:
                self.pg_set(dev, "flag UDPCSUM")

            # Setup random UDP port src range
            udp_src_min = 9
            udp_src_max = 1009
            self.pg_set(dev, "flag UDPSRC_RND")
            self.pg_set(dev, "udp_src_min %d" % (udp_src_min))
            self.pg_set(dev, "udp_src_max %d" % (udp_src_max))
            
            # hw burst
            if self.burst is not None and self.burst > 0:
                self.pg_set(dev, "burst %d" % self.burst)

    def start(self):
        if self.append is False:
            self.pg_ctrl("start")
    
    def stop(self):
        self.pg_ctrl("stop")

    def result(self):
            # Print results
        print("%d threads enabled" % self.threads)
        for ti in range(self.first_thread, self.first_thread + self.threads):
            dev= "%s@%d" % (self.pgdev,  ti)
            devpath = "/proc/net/pktgen/"+dev
            f = open(devpath, "r")
            a = f.read()
            print("thread %d result =====" % ti)
            print(a)
            f.close()

    def numa(self) -> int:
        numapath = "/sys/class/net/%s/device/numa_node" % self.pgdev
        try:
            f = open(numapath, "r")
        except:
            print("Error: Cannot open %s" % (numapath))
            sys.exit(-1)
        node = f.read()
        f.close()
        if node == '-1':
            return 0
        else:
            return node

    # def get_irqs(self):
    #     proc_intr = "/proc/interrupts"
    #     msi_irqs = "/sys/class/net/%s/device/msi_irqs" % self.pgdev
    #     f = open(proc_intr, "r")
    #     intrs = f.read()
    #     f.close()
    #     DEV_IRQ=re.compile(r'%s-.*TxRx' %(self.pgdev))
    #     match = DEV_IRQ.search(intrs)
        
    