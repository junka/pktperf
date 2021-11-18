from __future__ import division
import sys
import re
import os
import netaddr


class PktSar:
    """pkt sar stats class

    calculate the pps and bps from the text
    """
    def __init__(self, start_time:int, pkt_size:int) -> None:
        self.start = start_time
        self._pkts = 0
        self._pkt_size = pkt_size
        self._bytes = 0
        self.last_update = start_time
        self.pps = 0.0
        self.bps = 0.0

    def update(self, pkts_so_far, timestamp):
        diff_pkts = pkts_so_far - self._pkts
        self._pkts = pkts_so_far
        diff_time = ((timestamp - self.last_update)/1000000)
        self.last_update = timestamp
        if timestamp == self.start:
            self.pps = 0.0
            self.bps = 0.0
        else:
            self.pps = diff_pkts / diff_time
            self.bps = self.pps * (self._pkt_size + 4)

    def get_stats(self):
        return self.pps, self.bps

class Pktgen:
    """Pktgen class

    pktgen api class, responsible for operation on
    /proc/net/pktgen/pgctrl
    /proc/net/pktgen/kpktgend_X
    /proc/net/pktgen/ethX
    /proc/net/pktgen/ethX@Y
    """

    def __init__(self, dev, pkt_size, dest_ip, dest_mac, dst_port, csum, threads,
                 first_thread, clone, num, burst, verbose, debug, ip6, flows,
                 flow_len, tx_delay, append, queue, tos, bps_rate, pps_rate,
                 frags) -> None:
        """Init pktgen module with parameters

        Args:
            dev: nic device name
            pkt_size: packet size to generate
            dest_ip: destination IP. CIDR is also allowed
            dest_mac: destination mac address
            dst_port: destination port, port range is also allowed
            cum: UDP checksum enabled or not
            threads: number of threads to start
            first_thread: index of first thread to start
            clone: number of skb clones sent before alloc new skb
            num: number of packets to send per thread, 0 means indefinitely
            burst: hw level bursting of skbs
            verbose: verbose
            debug: debug
            ip6: send IPv6 packets
            flows: limit number of flows
            flow_len: packets number a flow will send
            tx_delay: tx delay value in ns
            append: script will not reset generator state, but will append its config
            queue: queue mapping with irq affinity
        """
        if self.os_check() is False:
            print("Can Only run in Linux system!")
            sys.exit()
        if os.getuid() != 0:
            print("pktperf should be run as root!")
            sys.exit()
        mod = "/proc/net/pktgen"
        is_exists = os.path.exists(mod)
        if is_exists is False:
            print("No pktgen module\nPlease do modprobe pktgen")
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
        self.frags = None
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
        self.queue = queue
        if clone is not None:
            self.clone = int(clone)
        self.num = int(num)
        if burst is not None:
            self.burst = int(burst)
        if threads is not None:
            self.threads = int(threads)
        self.stats = []
        if first_thread is not None:
            self.first_thread = int(first_thread)
        if tx_delay is not None:
            self.tx_delay = int(tx_delay)
        if flows is not None:
            self.flows = int(flows)
        if flow_len is not None:
            self.flow_len = int(flow_len)
        if queue is True:
            numa = self.dev_numa()
            self.irq_list = self.get_irqs()
            if len(self.irq_list) == 0:
                print("irq affinity not supported")
                sys.exit()
            self.cpu_list = self.node_cpu_list(numa)
        if tos is not None:
            self.tos = int(tos)
        self.bps_rate = bps_rate
        self.pps_rate = pps_rate
        if frags is not None:
            self.frags = int(frags)

    # pg_ctrl()   control "pgctrl" (/proc/net/pktgen/pgctrl)
    def pg_ctrl(self, cmd) -> None:
        pgctrl = "/proc/net/pktgen/pgctrl"
        if cmd not in ["start", "stop", "reset"]:
            print("pgctrl do not support cmd %s" % cmd)
            sys.exit(1)
        try:
            with open(pgctrl, 'r+') as f:
                f.write("%s\n" % cmd)
        except Exception as e:
            print("Error: Cannot open %s, error %s" % (pgctrl, e))
            sys.exit(1)

    # pg_set()    control setup of individual devices
    def pg_set(self, dev, flag) -> None:
        pgdev = "/proc/net/pktgen/%s" % dev
        try:
            with open(pgdev, "r+") as f:
                f.write("%s\n" % flag)
        except:
            print("Error: Cannot open %s" % (pgdev))
            sys.exit(1)

    # pg_thread() control the kernel threads and binding to devices
    def pg_thread(self, thread, cmd) -> None:
        pgthread = "/proc/net/pktgen/kpktgend_%d" % thread
        if cmd != "rem_device_all" and cmd.find("add_device") != 0 :
            print("pg_thread do not support cmd %s" % cmd)
            sys.exit(1)
        try:
            with open(pgthread, "w") as f:
                f.write("%s\n" % cmd)
        except:
            print("Error: Cannot open %s" % (pgthread))
            sys.exit(1)

    # pktgen is supported on Linux only
    def os_check(self) -> bool:
        return os.name == "posix"

    def config_irq_affinity(self, irq, thread):
        irq_path = "/proc/irq/%d/smp_affinity_list" % irq
        try:
            with open(irq_path, 'r+') as f:
                f.write("%d\n" % thread)
        except:
            sys.exit()
        if self.debug is True:
            print("irq %d is set affinity to %d" % (irq, thread))

    def config_queue(self) -> None:
        # General cleanup everything since last run
        if self.append is False:
            self.reset()

        # Threads are specified with parameter -t value in $THREADS
        for ti in range(self.first_thread, self.first_thread + self.threads):
            if self.queue is True:
                thr = self.cpu_list[ti]
                dev = "%s@%d" % (self.pgdev , thr)
                self.config_irq_affinity(self.irq_list[ti - self.first_thread], thr)
            else:
                # The device name is extended with @name, using thread number to
                # make then unique, but any name will do.
                dev= "%s@%d" % (self.pgdev , ti)

            # Add remove all other devices and add_device $dev to thread
            if self.append is False:
                self.pg_thread(ti, "rem_device_all")
            self.pg_thread(ti, "add_device %s" % dev)

            # select queue and bind the queue and $dev in 1:1 relationship
            if self.queue is True:
                qid = (ti - self.first_thread)
                if self.debug is True:
                    print("queue number is %d" % (qid))
                self.pg_set(dev, "queue_map_min %d" % qid)
                self.pg_set(dev, "queue_map_max %d" % qid)

            # Notice config queue to map to cpu (mirrors smp_processor_id())
            # It is beneficial to map IRQ /proc/irq/*/smp_affinity 1:1 to CPU number
            self.pg_set(dev, "flag QUEUE_MAP_CPU")

            # Base config of dev
            self.pg_set(dev, "count %d" % self.num)
            self.pg_set(dev, "clone_skb %d" % self.clone)
            self.pg_set(dev, "pkt_size %d" % self.pkt_size)
            if self.frags is not None and self.frags != 1:
                self.pg_set(dev, "frags %d" % self.frags)
            self.pg_set(dev, "delay %d" % self.tx_delay)
            if self.tos is not None and self.tos != 0:
                if self.ipv6 is True:
                    self.pg_set(dev, "traffic_class %x" % self.tos)
                else:
                    self.pg_set(dev, "tos %s" % self.tos)

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
            
            # rate limit
            if self.bps_rate is not None:
                self.pg_set(dev, "rate %s" % (self.bps_rate))
            if self.pps_rate is not None:
                self.pg_set(dev, "ratep %s" % (self.pps_rate))

    def reset(self) -> None:
        self.pg_ctrl("reset")

    def start(self) -> None:
        if self.append is False:
            self.pg_ctrl("start")

    def stop(self) -> None:
        self.pg_ctrl("stop")

    def result(self, last, print_cb) -> None:
        # Print results
        if last is True:
            print("%d cores enabled" % self.threads)
        need_init = False
        total_pkts = 0
        total_pps = 0
        total_bps = 0
        total_err = 0
        if len(self.stats) == 0:
            need_init = True
        for ti in range(self.first_thread, self.first_thread + self.threads):
            if self.queue is True:
                thr = self.cpu_list[ti]
                dev = "%s@%d" % (self.pgdev , thr)
            else:
                dev= "%s@%d" % (self.pgdev,  ti)
            devpath = "/proc/net/pktgen/%s" % dev
            with open(devpath, "r") as f:
                a = f.read()
            if last is False:
                SOFAR_FIELD = re.compile(r'pkts-sofar: (\d+)  errors: (\d+)')
                TIME_FIELD = re.compile(r'started: (\d+)us  stopped: (\d+)us')
                sofar = SOFAR_FIELD.search(a)
                tim = TIME_FIELD.search(a)
                if need_init is True:
                    ps = PktSar(int(tim.group(1)), self.pkt_size)
                    self.stats.append(ps)
                else:
                    ps = self.stats[ti - self.first_thread]
                if sofar is not None:
                    ps.update(int(sofar.group(1)), int(tim.group(2)))
                    pps, bps = ps.get_stats()
                    total_pkts += int(sofar.group(1))
                    total_pps += pps
                    total_bps += bps
                    total_err += int(sofar.group(2))
                    print_cb("Core%3d send %18d pkts: %18f pps %18f bps %6d errors" %
                             (ti, int(sofar.group(1)), pps, bps, int(sofar.group(2))))
            else:
                RESULT_FIELD = re.compile(r'Result: (\w+): \d+\([\w\+]+\) \w+, (\d+) \(\d+byte,\d+frags\)')
                THROUPUT_FIELD = re.compile(r'  (\d+)pps \d+Mb\/sec \((\d+)bps\) errors: (\d+)')
                UNRESULT_FIELD = re.compile(r'Result: (\w+)')
                res = RESULT_FIELD.search(a)
                pkt = THROUPUT_FIELD.search(a)
                other = UNRESULT_FIELD.search(a)
                if res is not None and pkt is not None:
                    total_pkts += int(res.group(2))
                    total_pps += int(pkt.group(1))
                    total_bps += int(pkt.group(2))
                    total_err += int(pkt.group(3))
                    print_cb("Core%3d send %18d pkts: %18d pps %18d bps %6d errors" %
                        (ti, int(res.group(2)), int(pkt.group(1)),
                        int(pkt.group(2)), int(pkt.group(3))))
                elif other is not None:
                    print_cb("Core%3d %s" %(ti, other.group(1)))
        print_cb("Total   send %18d pkts: %18d pps %18d bps %6d errors" %
                 (total_pkts, total_pps, total_bps, total_err))

    def dev_numa(self) -> int:
        numa_path = "/sys/class/net/%s/device/numa_node" % self.pgdev
        try:
            with open(numa_path, "r") as f:
                node = f.read().rstrip('\n')
        except:
            print("Error: Cannot open %s" % (numa_path))
            return 0
        if node == '-1':
            return 0
        return int(node)

    def node_cpu_list(self, node) -> list:
        cpu_list = "/sys/devices/system/node/node%d/cpulist" % node
        try:
            with open(cpu_list, 'r') as f:
                cpu_range = f.read()
        except:
            print("Error: Cannot open %s" % (cpu_list))
            sys.exit(-1)
        ranges = cpu_range.split(',')
        ret = []
        for i in ranges:
            l, h = i.split('-')
            for j in range(int(l), int(h) + 1):
                ret.append(j)
        return ret

    def get_irqs(self):
        proc_intr = "/proc/interrupts"
        msi_irqs = "/sys/class/net/%s/device/msi_irqs" % self.pgdev
        try:
            with open(proc_intr, "r") as f:
                intrs = f.read()
        except:
            return []
        irqs = []
        DEV_QUEUE_IRQ = re.compile(r'(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-.*TxRx-\d+' %(self.pgdev))
        match = DEV_QUEUE_IRQ.finditer(intrs)
        print(match)
        if len(DEV_QUEUE_IRQ.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        DEV_IRQ = re.compile(r'(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-\d+' %(self.pgdev))
        match = DEV_IRQ.finditer(intrs)
        if len(DEV_IRQ.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        try:
            dirs = os.listdir(msi_irqs)
            for dev_q in dirs:
                MSI_IRQ = re.compile(r'%s:.*TxRx' % dev_q)
                match = MSI_IRQ.search(intrs)
                if match is not None:
                    irqs.append(int(dev_q))
            return irqs
        except:
            return []
