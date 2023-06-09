# -*- coding: UTF-8 -*-
"""
classes provide functions for pktgen operation
"""
import sys
import re
import os
import math
import platform
import ipaddress
import subprocess
import configparser
from .pktsar import PktSar


def open_write_error(filename, flag, mode="r+"):
    """open and write a flag to file"""
    try:
        with open(filename, mode, encoding="utf-8") as fp_dev:
            fp_dev.write("%s\n" % flag)
    except IOError as exc:
        print("Error: Cannot open %s" % (filename))
        raise IOError("Error writing flag %s" % flag) from exc


def modinfo_check() -> str:
    """check module version"""
    n = platform.uname()
    depfile = "/lib/modules/%s/modules.dep" % n.release
    try:
        with open(depfile, "r", encoding="utf-8") as fp_dep:
            fp_dep.readlines()
    except IOError as exc:
        print("Fail to open modules.dep, maybe you are not root privellge")
        raise IOError("Error open modules.dep") from exc
    p = subprocess.run(["modinfo", "pktgen"], stdout=subprocess.PIPE, check=True)
    if p.returncode != 0:
        return ""
    ret = p.stdout.decode("utf-8")
    ver = re.search(r"version:[\t\ ]+([\d\.]+)", ret)
    if ver is not None:
        return ver.group(1)
    return ""


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
    def __init__(self, args) -> None:
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
            flows: limit number of flows
            flow_len: packets number a flow will send
            tx_delay: tx delay value in ns
            append: script will not reset generator state, append its config
            queue: queue mapping with irq affinity

            tos, traffic_class, vni should be hex for pktgen
        """
        if self.os_check() is False:
            print("pktperf Can Only run in Linux system!")
            sys.exit()
        if os.getuid() != 0:
            print("pktperf should be run as root!")
            sys.exit()
        ver = modinfo_check()
        if ver == "":
            print("pktgen is not enabled in kernel")
            sys.exit()
        mod = "/proc/net/pktgen"
        is_exists = os.path.exists(mod)
        if is_exists is False:
            print("No pktgen module\nPlease do 'modprobe pktgen'")
            sys.exit(0)
        self.pgdev = args.interface
        self.pkt_size = int(args.size)
        self.dst_mac = args.mac
        self.dst_ip_min, self.dst_ip_max = self.__init_ip_input(args.dst)
        self.src_ip_min, self.src_ip_max = self.__init_ip_input(args.src)
        self.dst_port_min, self.dst_port_max = self.__init_port_range(args.portrange)
        self.src_port_min, self.src_port_max = 9, 1009
        self.frags = None
        self.csum = args.txcsum
        self.debug = args.debug
        self.verbose = args.verbose
        self.append = args.append
        if args.clone is not None:
            self.clone = int(args.clone)
        self.num = int(args.num)
        if args.burst is not None:
            self.burst = int(args.burst)
        if args.threads is not None:
            self.threads = int(args.threads)
        self.stats = []
        if args.firstthread is not None:
            self.first_thread = int(args.firstthread)
        self.thread_list = list(
            range(self.first_thread, self.first_thread + self.threads)
        )
        if args.delay is not None:
            self.tx_delay = int(args.delay)
        if args.flows is not None:
            self.flows = int(args.flows)
        if args.flowpkts is not None:
            self.flow_len = int(args.flowpkts)
        self.__init_irq(args.queuemap)
        if args.tos is not None:
            self.tos = int(args.tos)
        self.bps_rate = args.bps
        self.pps_rate = args.pps
        if args.frags is not None:
            self.frags = int(args.frags)
        self.vlan = args.vlan
        self.svlan = args.svlan
        self.tun_vni = args.vni
        self.tun_udpport = args.tundport
        self.tun_dst_min, self.tun_dst_max = self.__init_ip_input(args.tundst)
        self.tun_src_min, self.tun_src_max = self.__init_ip_input(args.tunsrc)
        self.inner_dmac = args.innerdmac
        self.inner_smac = args.innersmac
        self.inner_dmac_count = 0
        self.inner_smac_count = 0
        self.microburst = args.microburst
        self.imixweight = args.imix
        self.__read_config_file(args.file)
        if self.pgdev is None:
            raise Exception("No interface specified")
        if self.dst_ip_min == "":
            raise Exception("No dst ip specified")

    def __read_config_file(self, file):
        cfg = configparser.ConfigParser()
        if file is not None:
            with open(file, "r", encoding="utf-8") as f:
                config_string = "[dummy]\n" + f.read()
                cfg.read_string(config_string)
        else:
            return
        if cfg.has_option("dummy", "interface"):
            self.pgdev = cfg.get("dummy", "interface")
        if cfg.has_option("dummy", "pkt_size"):
            self.pkt_size = cfg.getint("dummy", "pkt_size")
        if cfg.has_option("dummy", "pkt_num"):
            self.num = cfg.getint("dummy", "pkt_num")
        if cfg.has_option("dummy", "threads"):
            self.thread_list = sum(
                (
                    (
                        list(range(*[int(b) + c for c, b in enumerate(a.split("-"))]))
                        if "-" in a
                        else [int(a)]
                    )
                    for a in cfg.get("dummy", "threads").split(",")
                ),
                [],
            )
            self.first_thread = self.thread_list[0]
            self.threads = len(self.thread_list)
        if cfg.has_option("dummy", "bps_limit"):
            self.bps_rate = cfg.get("dummy", "bps_limit")
        if cfg.has_option("dummy", "pps_limit"):
            self.pps_rate = cfg.get("dummy", "pps_limit")
        if cfg.has_option("dummy", "burst"):
            self.burst = cfg.getint("dummy", "burst")
        if cfg.has_option("dummy", "imix_weight"):
            self.clone = cfg.getint("dummy", "clone")
        if cfg.has_option("dummy", "dst_ip"):
            self.dst_ip_min, self.dst_ip_max = self.__init_ip_input(
                cfg.get("dummy", "dst_ip")
            )
        if cfg.has_option("dummy", "src_ip"):
            self.src_ip_min, self.src_ip_max = self.__init_ip_input(
                cfg.get("dummy", "src_ip")
            )
        if cfg.has_option("dummy", "dstmac"):
            self.dst_mac = cfg.get("dummy", "dstmac")
        if cfg.has_option("dummy", "vlan"):
            self.vlan = cfg.get("dummy", "vlan")
        if cfg.has_option("dummy", "svlan"):
            self.svlan = cfg.get("dummy", "svlan")
        if cfg.has_option("dummy", "udp_src_port"):
            self.src_port_min, self.src_port_max = self.__init_port_range(
                cfg.get("dummy", "udp_src_port")
            )
        if cfg.has_option("dummy", "udp_dst_port"):
            self.dst_port_min, self.dst_port_max = self.__init_port_range(
                cfg.get("dummy", "udp_dst_port")
            )
        if cfg.has_option("dummy", "tos"):
            self.tos = cfg["tos"]
        if cfg.has_option("dummy", "tun_vni"):
            self.tun_vni = cfg.get("dummy", "tun_vni")
        if cfg.has_option("dummy", "tun_udp_port"):
            self.tun_udpport = cfg.get("dummy", "tun_udp_port")
        if cfg.has_option("dummy", "tun_src_ip"):
            self.tun_src_min, self.tun_src_max = self.__init_ip_input(
                cfg.get("dummy", "tun_src_ip")
            )
        if cfg.has_option("dummy", "tun_dst_ip"):
            self.tun_dst_min, self.tun_dst_max = self.__init_ip_input(
                cfg.get("dummy", "tun_dst_ip")
            )
        if cfg.has_option("dummy", "inner_dstmac"):
            self.inner_dmac = cfg.get("dummy", "inner_dstmac")
        if cfg.has_option("dummy", "inner_srcmac"):
            self.inner_smac = cfg.get("dummy", "inner_srcmac")
        if cfg.has_option("dummy", "inner_dmac_num"):
            self.inner_dmac_count = cfg.getint("dummy", "inner_dmac_num")
        if cfg.has_option("dummy", "inner_smac_num"):
            self.inner_smac_count = cfg.getint("dummy", "inner_smac_num")
        if cfg.has_option("dummy", "micro_burst"):
            self.microburst = cfg.get("dummy", "micro_burst")
            self.burst = 0
        if cfg.has_option("dummy", "imix_weight"):
            self.imixweight = cfg.get("dummy", "imix_weight")

    def __init_ip_input(self, ipstr):
        """Init pktgen module ip dst"""
        if ipstr is None:
            return "", ""
        net = None
        try:
            net = ipaddress.ip_network(ipstr, strict=False)
        except (ValueError, TypeError):
            ip_list = ipstr.split("-")
            try:
                ip_min = ipaddress.ip_address(ip_list[0])
            except (ValueError, TypeError):
                print("invalid ip address format")
                sys.exit()
            if len(ip_list) == 2:
                try:
                    ip_max = ipaddress.ip_address(ip_list[1])
                except (ValueError, TypeError):
                    print("invalid ip address format")
                    sys.exit()
            elif len(ip_list) == 1:
                ip_max = ip_min
        if net is not None:
            ip_list = list(net)
            ip_min = ip_list[0]
            ip_max = ip_list[-1]
        return ip_min, ip_max

    def __init_port_range(self, portrange):
        """init port range for pktgen"""
        port_max = 65535
        port_min = 65535
        if portrange is not None:
            ports = portrange.split("-")
            if len(ports) == 2:
                port_max = int(ports[1])
            elif len(ports) == 1:
                port_max = int(ports[0])
            port_min = int(ports[0])
        return port_min, port_max

    def __init_irq(self, queuemap) -> None:
        """init irq affinity if queue mapping enabled"""
        self.queue = queuemap
        if queuemap is True:
            numa = self.__get_dev_numa()
            self.irq_list = self.__get_irqs()
            if len(self.irq_list) == 0:
                print("irq affinity not supported")
                sys.exit()
            self.cpu_list = self.__node_cpu_list(numa)

    @staticmethod
    def pg_ctrl(cmd) -> None:
        """pg_ctrl control "pgctrl" (/proc/net/pktgen/pgctrl)"""
        pgctrl = "/proc/net/pktgen/pgctrl"
        if cmd not in ["start", "stop", "reset"]:
            print("pgctrl do not support cmd %s" % cmd)
            sys.exit(1)
        open_write_error(pgctrl, cmd)

    @staticmethod
    def pg_version() -> str:
        pgctrl = "/proc/net/pktgen/pgctrl"
        try:
            with open(pgctrl, "r", encoding="utf-8") as f_ctl:
                cont = f_ctl.read()
                m = re.search(r"Version: (\d.\d+)", cont)
        except IOError:
            return ""
        if m is not None:
            return m.group(1)
        return ""

    def pg_set(self, dev, flag) -> None:
        """pg_set control setup of individual devices"""
        if dev.find(self.pgdev) < 0:
            print("device not match")
            sys.exit(1)
        pgdev = "/proc/net/pktgen/%s" % dev
        open_write_error(pgdev, flag)

    def __pg_get_devpath(self, index) -> str:
        """get dev path for thread index"""
        if self.queue is True:
            dev = "%s@%d" % (self.pgdev, self.cpu_list[index])
        else:
            dev = "%s@%d" % (self.pgdev, index)
        devpath = "/proc/net/pktgen/%s" % dev
        return devpath

    @staticmethod
    def pg_thread(thread, cmd) -> None:
        """pg_thread() control the kernel threads and binding to devices"""
        pgthread = "/proc/net/pktgen/kpktgend_%d" % thread
        if cmd != "rem_device_all" and cmd.find("add_device") != 0:
            print("pg_thread do not support cmd %s" % cmd)
            sys.exit(1)
        open_write_error(pgthread, cmd, "w")

    @staticmethod
    def os_check() -> bool:
        """check if os is linux"""
        return os.name == "posix"

    def __config_irq_affinity(self, irq, thread):
        """config irq affinity"""
        irq_path = "/proc/irq/%d/smp_affinity_list" % irq
        open_write_error(irq_path, thread)
        if self.debug is True:
            print("irq %d is set affinity to %d" % (irq, thread))

    def __config_tos(self, dev) -> None:
        """config tos"""
        if self.tos is not None and self.tos != 0:
            if self.ipv6 is True:
                self.pg_set(dev, "traffic_class %0x" % self.tos)
            else:
                self.pg_set(dev, "tos %0x" % self.tos)

    def __config_vlan(self, dev) -> None:
        """config vlan related parameter"""
        if self.vlan is not None and 0 <= int(self.vlan) < 4096:
            self.pg_set(dev, "vlan_id %d" % int(self.vlan))
        if self.svlan is not None and 0 <= int(self.svlan) < 4096:
            self.pg_set(dev, "svlan_id %d" % int(self.svlan))

    def __config_udp_portrange(self, dev) -> None:
        """config udp port range"""
        if self.dst_port_max is not None:
            # Single destination port or random port range
            self.pg_set(dev, "flag UDPDST_RND")
            self.pg_set(dev, "udp_dst_min %d" % (self.dst_port_min))
            self.pg_set(dev, "udp_dst_max %d" % (self.dst_port_max))

        if self.csum is True:
            self.pg_set(dev, "flag UDPCSUM")

        # Setup random UDP port src range
        self.pg_set(dev, "flag UDPSRC_RND")
        self.pg_set(dev, "udp_src_min %d" % (self.src_port_min))
        self.pg_set(dev, "udp_src_max %d" % (self.src_port_max))

    def __config_ip_dst(self, dev) -> None:
        # Destination
        if self.dst_ip_min.version == 6:
            self.pg_set(dev, "dst_min6 %s" % (self.dst_ip_min))
            self.pg_set(dev, "dst_max6 %s" % (self.dst_ip_max))
        else:
            self.pg_set(dev, "dst_min %s" % (self.dst_ip_min))
            self.pg_set(dev, "dst_max %s" % (self.dst_ip_max))

    def __config_ip_src(self, dev) -> None:
        if self.src_ip_min == "":
            return None
        if self.src_ip_min.version == 6:
            self.pg_set(dev, "src_min6 %s" % (self.src_ip_min))
            self.pg_set(dev, "src_max6 %s" % (self.src_ip_max))
        else:
            self.pg_set(dev, "src_min %s" % (self.src_ip_min))
            self.pg_set(dev, "src_max %s" % (self.src_ip_max))

    def __config_imix(self, dev) -> None:
        if self.imixweight is not None:
            weight = self.imixweight.replace(",", " ").replace(":", ",")
            self.pg_set(dev, "imix_weights %s" % weight)

    def __config_burst_mode(self, dev) -> None:
        if self.microburst is not None:
            self.pg_set(dev, "micro_burst %s" % self.microburst)
            self.burst = 0
        # hw burst
        if self.burst is not None and self.burst > 0:
            self.pg_set(dev, "burst %d" % self.burst)

    def __config_tun_meta(self, dev) -> None:
        if self.tun_vni is not None:
            vni = self.tun_vni.split("-")
            if len(vni) == 2:
                vni_max = vni[1]
            elif len(vni) == 1:
                vni_max = vni[0]
            vni_min = vni[0]
            self.pg_set(dev, "tun_meta_min %06x" % int(vni_min))
            self.pg_set(dev, "tun_meta_max %06x" % int(vni_max))
            self.pg_set(dev, "tun_udp_dst %d" % int(self.tun_udpport))
            if self.tun_src_min != "":
                self.pg_set(dev, "tun_src_min %s" % self.tun_src_min)
            if self.tun_src_max != "":
                self.pg_set(dev, "tun_src_max %s" % self.tun_src_max)
            if self.tun_dst_min != "":
                self.pg_set(dev, "tun_dst_min %s" % self.tun_dst_min)
            if self.tun_dst_max != "":
                self.pg_set(dev, "tun_dst_max %s" % self.tun_dst_max)
            if self.inner_smac is not None:
                self.pg_set(dev, "inner_src_mac %s" % self.inner_smac)
            if self.inner_dmac is not None:
                self.pg_set(dev, "inner_dst_mac %s" % self.inner_dmac)
            if self.inner_dmac_count > 0:
                self.pg_set(dev, "inner_dmac_num %d" % self.inner_dmac_count)
            if self.inner_smac_count > 0:
                self.pg_set(dev, "inner_smac_num %d" % self.inner_smac_count)

    def __config_ratelimit(self, dev) -> None:
        # rate limit
        if self.bps_rate is not None:
            self.pg_set(dev, "rate %s" % (self.bps_rate))
        if self.pps_rate is not None:
            self.pg_set(dev, "ratep %s" % (self.pps_rate))

    def config_queue(self) -> None:
        """configure queues for pktgen"""
        # General cleanup everything since last run
        self.reset()

        # Threads are specified with parameter -t value in $THREADS
        for i in self.thread_list:
            if self.queue is True:
                dev = "%s@%d" % (self.pgdev, self.cpu_list[i])
                irq = self.irq_list[i]
                self.__config_irq_affinity(irq, self.cpu_list[i])
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
                qid = i - self.first_thread
                if self.debug is True:
                    print("queue number is %d" % (qid))
                self.pg_set(dev, "queue_map_min %d" % qid)
                self.pg_set(dev, "queue_map_max %d" % qid)

            # Notice config queue to map to cpu (mirrors smp_processor_id())
            # It is beneficial to map IRQ /proc/irq/*/smp_affinity 1:1 to CPU
            self.pg_set(dev, "flag QUEUE_MAP_CPU")

            # Base config of dev
            self.pg_set(dev, "count %d" % math.ceil(self.num / self.threads))
            self.pg_set(dev, "clone_skb %d" % self.clone)
            self.pg_set(dev, "pkt_size %d" % self.pkt_size)
            if self.frags is not None and self.frags != 1:
                self.pg_set(dev, "frags %d" % self.frags)
            self.pg_set(dev, "delay %d" % self.tx_delay)

            self.__config_tos(dev)

            # Flag example disabling timestamping
            self.pg_set(dev, "flag NO_TIMESTAMP")

            self.__config_tun_meta(dev)
            self.pg_set(dev, "dst_mac %s" % (self.dst_mac))
            self.__config_ip_dst(dev)
            self.__config_ip_src(dev)
            self.__config_udp_portrange(dev)
            self.__config_vlan(dev)

            self.__config_ratelimit(dev)

            self.__config_imix(dev)
            self.__config_burst_mode(dev)

    def reset(self) -> None:
        """reset pktgen"""
        if self.append is False:
            self.pg_ctrl("reset")

    def start(self) -> None:
        """start pktgen"""
        if self.append is False:
            self.pg_ctrl("start")

    def stop(self) -> None:
        """stop pktgen"""
        self.pg_ctrl("stop")

    @staticmethod
    def result_last(core_id, fp_dev, print_cb):
        """print last result"""
        tpkts = 0
        tpps = 0
        tbps = 0
        tbps = 0
        stats_content = fp_dev.read()
        result_field = re.compile(
            r"Result: (\w+): \d+\([\w\+]+\) \w+, (\d+) \(\d+byte,\d+frags\)"
        )
        throughput_field = re.compile(
            r"  (\d+)pps \d+Mb\/sec \((\d+)bps\) errors: (\d+)"
        )
        unresult_field = re.compile(r"Result: (\w+)")
        res = result_field.search(stats_content)
        pkt = throughput_field.search(stats_content)
        if res is not None and pkt is not None:
            tpkts = int(res.group(2))
            tpps = int(pkt.group(1))
            tbps = int(pkt.group(2))
            tbps = int(pkt.group(3))
            print_cb(
                "Core%3d send %18d pkts: %18d pps %18d bps %6d errors"
                % (
                    core_id,
                    int(res.group(2)),
                    int(pkt.group(1)),
                    int(pkt.group(2)),
                    int(pkt.group(3)),
                )
            )
        else:
            other = unresult_field.search(stats_content)
            if other is not None:
                print_cb("Core%3d %s" % (core_id, other.group(1)))
        return tpkts, tpps, tbps, tbps

    def result_transient(self, need_init, core_id, fp_dev, print_cb):
        """print result during"""
        stats_content = fp_dev.read()
        sofar_field = re.compile(r"pkts-sofar: (\d+)  errors: (\d+)")
        time_field = re.compile(r"started: (\d+)us  stopped: (\d+)us")
        sofar = sofar_field.search(stats_content)
        tim = time_field.search(stats_content)
        if need_init is True:
            pkt_sar = PktSar(int(tim.group(1)), self.pkt_size)
            self.stats.append(pkt_sar)
        else:
            pkt_sar = self.stats[core_id - self.first_thread]
        if sofar is not None:
            pkt_sar.update(int(sofar.group(1)), int(tim.group(2)))
            pps, bps = pkt_sar.get_stats()
            print_cb(
                "Core%3d send %18d pkts: %18f pps %18f bps %6d errors"
                % (core_id, int(sofar.group(1)), pps, bps, int(sofar.group(2)))
            )
            return int(sofar.group(1)), pps, bps, int(sofar.group(2))
        return 0, 0, 0, 0

    def result(self, last, print_cb) -> int:
        """Print results"""
        if last is True:
            print("%d cores enabled" % self.threads)
        need_init = False
        total_pkts = 0
        total_pps = 0
        total_bps = 0
        total_err = 0
        if len(self.stats) == 0:
            need_init = True
        for i in self.thread_list:
            with open(self.__pg_get_devpath(i), "r") as fp_dev:
                if last is False:
                    sg_pkts, sg_pps, sg_bps, sg_err = self.result_transient(
                        need_init, i, fp_dev, print_cb
                    )
                else:
                    sg_pkts, sg_pps, sg_bps, sg_err = self.result_last(
                        i, fp_dev, print_cb
                    )
                total_pkts += sg_pkts
                total_pps += sg_pps
                total_bps += sg_bps
                total_err += sg_err
        print_cb(
            "Total   send %18d pkts: %18d pps %18d bps %6d errors"
            % (total_pkts, total_pps, total_bps, total_err)
        )
        if last is False and self.num > 0 and total_pkts >= self.num:
            return 1
        return 0

    def __get_dev_numa(self) -> int:
        """__get_dev_numa returns the numa node of the device"""
        numa_path = "/sys/class/net/%s/device/numa_node" % self.pgdev
        try:
            with open(numa_path, "r") as fp_numa:
                node = fp_numa.read().rstrip("\n")
        except IOError:
            print("Error: Cannot open %s" % (numa_path))
            return 0
        if node == "-1":
            return 0
        return int(node)

    @staticmethod
    def __node_cpu_list(node) -> list:
        """__node_cpu_list returns the cpu list of the node"""
        cpu_list = "/sys/devices/system/node/node%d/cpulist" % node
        try:
            with open(cpu_list, "r") as fp_cpu:
                cpu_range = fp_cpu.read()
        except IOError:
            print("Error: Cannot open %s" % (cpu_list))
            sys.exit(-1)
        ranges = cpu_range.split(",")
        ret = []
        for i in ranges:
            cpu_start, cpu_end = i.split("-")
            for j in range(int(cpu_start), int(cpu_end) + 1):
                ret.append(j)
        return ret

    def __get_irqs(self):
        """read out irqs"""
        proc_intr = "/proc/interrupts"
        msi_irqs = "/sys/class/net/%s/device/msi_irqs" % self.pgdev
        try:
            with open(proc_intr, "r") as fp_proc:
                intrs = fp_proc.read()
        except IOError:
            return []
        irqs = []
        devq_irq = re.compile(
            r"(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-.*TxRx-\d+" % (self.pgdev)
        )
        match = devq_irq.finditer(intrs)
        print(match)
        if len(devq_irq.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        dev_irq = re.compile(r"(\d+):[ \d]+ [\w-]+ \d+-edge[ ]+%s-\d+" % (self.pgdev))
        match = dev_irq.finditer(intrs)
        if len(dev_irq.findall(intrs)) > 0:
            for i in match:
                irqs.append(int(i.group(1)))
            return irqs
        try:
            dirs = os.listdir(msi_irqs)
            for dev_q in dirs:
                msi_irq = re.compile(r"%s:.*TxRx" % dev_q)
                match = msi_irq.search(intrs)
                if match is not None:
                    irqs.append(int(dev_q))
            return irqs
        except IOError:
            return []
