"""
classes provide functions for pktgen operation
"""
import sys
import re
import os
import ipaddress
from .pktsar import PktSar


def open_write_error(filename, flag,  mode="r+"):
    """open and write a flag to file"""
    try:
        with open(filename, mode) as fp_dev:
            fp_dev.write("%s\n" % flag)
    except IOError:
        print("Error: Cannot open %s" % (filename))
        sys.exit(1)


class Pktgen:
    """Pktgen class

    pktgen api class, responsible for operation on
    /proc/net/pktgen/pgctrl
    /proc/net/pktgen/kpktgend_X
    /proc/net/pktgen/ethX
    /proc/net/pktgen/ethX@Y
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-many-arguments
    def __init__(self, dev, pkt_size, dest_ip, dest_mac, dst_port, csum,
                 threads, first_thread, clone, num, burst, verbose, debug,
                 ip6, flows, flow_len, tx_delay, append, queue, tos,
                 bps_rate, pps_rate, frags) -> None:
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
            append: script will not reset generator state, append its config
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
            print("No pktgen module\nPlease do \'modprobe pktgen\'")
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
        net = None
        try:
            net = ipaddress.ip_network(dest_ip, strict=False)
        except (ValueError, TypeError):
            ip_list = dest_ip.split('-')
            try:
                self.dst_ip_min = ipaddress.ip_address(ip_list[0])
            except (ValueError, TypeError):
                print("invalid ip address format")
                sys.exit()
            if len(ip_list) == 2:
                try:
                    self.dst_ip_max = ipaddress.ip_address(ip_list[1])
                except (ValueError, TypeError):
                    print("invalid ip address format")
                    sys.exit()
            elif len(ip_list) == 1:
                self.dst_ip_max = self.dst_ip_min
        if net is not None:
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
            numa = self.get_dev_numa()
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

    def pg_ctrl(self, cmd) -> None:
        """pg_ctrl control "pgctrl" (/proc/net/pktgen/pgctrl)"""
        pgctrl = "/proc/net/pktgen/pgctrl"
        if cmd not in ["start", "stop", "reset"]:
            print("pgctrl do not support cmd %s" % cmd)
            sys.exit(1)
        open_write_error(pgctrl, cmd)

    def pg_set(self, dev, flag) -> None:
        """pg_set control setup of individual devices"""
        pgdev = "/proc/net/pktgen/%s" % dev
        open_write_error(pgdev, flag)

    def pg_thread(self, thread, cmd) -> None:
        """pg_thread() control the kernel threads and binding to devices """
        pgthread = "/proc/net/pktgen/kpktgend_%d" % thread
        if cmd != "rem_device_all" and cmd.find("add_device") != 0:
            print("pg_thread do not support cmd %s" % cmd)
            sys.exit(1)
        open_write_error(pgthread, cmd, "w")

    # pktgen is supported on Linux only
    def os_check(self) -> bool:
        """ check if os is linux """
        return os.name == "posix"

    def config_irq_affinity(self, irq, thread):
        """ config irq affinity """
        irq_path = "/proc/irq/%d/smp_affinity_list" % irq
        open_write_error(irq_path, thread)
        if self.debug is True:
            print("irq %d is set affinity to %d" % (irq, thread))

    def config_queue(self) -> None:
        """configure queues for pktgen"""
        # General cleanup everything since last run
        if self.append is False:
            self.reset()

        # Threads are specified with parameter -t value in $THREADS
        for i in range(self.first_thread, self.first_thread + self.threads):
            if self.queue is True:
                thr = self.cpu_list[i]
                dev = "%s@%d" % (self.pgdev, thr)
                irq = self.irq_list[i - self.first_thread]
                self.config_irq_affinity(irq, thr)
            else:
                # The device name is extended with @name, using thread id to
                # make then unique, but any name will do.
                dev = "%s@%d" % (self.pgdev, i)

            # Add remove all other devices and add_device $dev to thread
            if self.append is False:
                self.pg_thread(i, "rem_device_all")
            self.pg_thread(i, "add_device %s" % dev)

            # select queue and bind the queue and $dev in 1:1 relationship
            if self.queue is True:
                qid = (i - self.first_thread)
                if self.debug is True:
                    print("queue number is %d" % (qid))
                self.pg_set(dev, "queue_map_min %d" % qid)
                self.pg_set(dev, "queue_map_max %d" % qid)

            # Notice config queue to map to cpu (mirrors smp_processor_id())
            # It is beneficial to map IRQ /proc/irq/*/smp_affinity 1:1 to CPU
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
        """ reset pktgen"""
        self.pg_ctrl("reset")

    def start(self) -> None:
        """start pktgen"""
        if self.append is False:
            self.pg_ctrl("start")

    def stop(self) -> None:
        """stop pktgen"""
        self.pg_ctrl("stop")

    def result(self, last, print_cb) -> None:
        """ Print results """
        if last is True:
            print("%d cores enabled" % self.threads)
        need_init = False
        total_pkts = 0
        total_pps = 0
        total_bps = 0
        total_err = 0
        if len(self.stats) == 0:
            need_init = True
        for i in range(self.first_thread, self.first_thread + self.threads):
            if self.queue is True:
                thr = self.cpu_list[i]
                dev = "%s@%d" % (self.pgdev, thr)
            else:
                dev = "%s@%d" % (self.pgdev, i)
            devpath = "/proc/net/pktgen/%s" % dev
            with open(devpath, "r") as fp_dev:
                stats_content = fp_dev.read()
            if last is False:
                sofar_field = re.compile(r'pkts-sofar: (\d+)  errors: (\d+)')
                time_field = re.compile(r'started: (\d+)us  stopped: (\d+)us')
                sofar = sofar_field.search(stats_content)
                tim = time_field.search(stats_content)
                if need_init is True:
                    pkt_sar = PktSar(int(tim.group(1)), self.pkt_size)
                    self.stats.append(pkt_sar)
                else:
                    pkt_sar = self.stats[i - self.first_thread]
                if sofar is not None:
                    pkt_sar.update(int(sofar.group(1)), int(tim.group(2)))
                    pps, bps = pkt_sar.get_stats()
                    total_pkts += int(sofar.group(1))
                    total_pps += pps
                    total_bps += bps
                    total_err += int(sofar.group(2))
                    print_cb("Core%3d send %18d pkts: %18f pps %18f bps %6d errors" %
                             (i, int(sofar.group(1)), pps, bps, int(sofar.group(2))))
            else:
                result_field = re.compile(r'Result: (\w+): \d+\([\w\+]+\) \w+, (\d+) \(\d+byte,\d+frags\)')
                throughput_field = re.compile(r'  (\d+)pps \d+Mb\/sec \((\d+)bps\) errors: (\d+)')
                unresult_field = re.compile(r'Result: (\w+)')
                res = result_field.search(stats_content)
                pkt = throughput_field.search(stats_content)
                other = unresult_field.search(stats_content)
                if res is not None and pkt is not None:
                    total_pkts += int(res.group(2))
                    total_pps += int(pkt.group(1))
                    total_bps += int(pkt.group(2))
                    total_err += int(pkt.group(3))
                    print_cb("Core%3d send %18d pkts: %18d pps %18d bps %6d errors" %
                             (i, int(res.group(2)), int(pkt.group(1)),
                              int(pkt.group(2)), int(pkt.group(3))))
                elif other is not None:
                    print_cb("Core%3d %s" % (i, other.group(1)))
        print_cb("Total   send %18d pkts: %18d pps %18d bps %6d errors" %
                 (total_pkts, total_pps, total_bps, total_err))

    def get_dev_numa(self) -> int:
        """ get_dev_numa returns the numa node of the device"""
        numa_path = "/sys/class/net/%s/device/numa_node" % self.pgdev
        try:
            with open(numa_path, "r") as fp_numa:
                node = fp_numa.read().rstrip('\n')
        except IOError:
            print("Error: Cannot open %s" % (numa_path))
            return 0
        if node == '-1':
            return 0
        return int(node)

    def node_cpu_list(self, node) -> list:
        """ node_cpu_list returns the cpu list of the node """
        cpu_list = "/sys/devices/system/node/node%d/cpulist" % node
        try:
            with open(cpu_list, 'r') as fp_cpu:
                cpu_range = fp_cpu.read()
        except IOError:
            print("Error: Cannot open %s" % (cpu_list))
            sys.exit(-1)
        ranges = cpu_range.split(',')
        ret = []
        for i in ranges:
            cpu_start, cpu_end = i.split('-')
            for j in range(int(cpu_start), int(cpu_end) + 1):
                ret.append(j)
        return ret

    def get_irqs(self):
        """ read out irqs """
        proc_intr = "/proc/interrupts"
        msi_irqs = "/sys/class/net/%s/device/msi_irqs" % self.pgdev
        try:
            with open(proc_intr, "r") as fp_proc:
                intrs = fp_proc.read()
        except IOError:
            return []
        irqs = []
        devq_irq = re.compile(r'(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-.*TxRx-\d+' % (self.pgdev))
        match = devq_irq.finditer(intrs)
        print(match)
        if len(devq_irq.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        dev_irq = re.compile(r'(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-\d+' % (self.pgdev))
        match = dev_irq.finditer(intrs)
        if len(dev_irq.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        try:
            dirs = os.listdir(msi_irqs)
            for dev_q in dirs:
                msi_irq = re.compile(r'%s:.*TxRx' % dev_q)
                match = msi_irq.search(intrs)
                if match is not None:
                    irqs.append(int(dev_q))
            return irqs
        except IOError:
            return []
