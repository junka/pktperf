# pktperf
pktgen is very useful for network performance test, especially when we don't have 
multiple nics for dpdk. And for ```vm2vm``` test, it would be easy to use for end-user.

Pktperf is a very thin layer for pktgen (the kernel version).

It makes use of the sample scripts in linux kernel [https://github.com/torvalds/linux/tree/master/samples/pktgen]

All ```cmds``` in [https://www.kernel.org/doc/Documentation/networking/pktgen.txt]

## install
```pip3 install pktperf```

## usage
```
python3 -m pktperf.pktperf 
```

It keeps parameters the same with sample scripts.
```
Usage: pktperf.py [OPTIONS]

Options:
  -i TEXT     output interface/device  [required]
  -s INTEGER  packet size
  -d TEXT     destination IP. CIDR is also allowed
  -m TEXT     destination MAC-addr
  -p TEXT     destination PORT range is also allowed
  -k          enable UDP tx checksum
  -t INTEGER  threads to start
  -f INTEGER  index of first thread
  -c INTEGER  SKB clones send before alloc new SKB
  -n INTEGER  num messages to send per thread, 0 means indefinitely
  -b INTEGER  HW level bursting of SKBs
  -v          verbose
  -x          debug
  -ip6        IPv6
  -z INTEGER  Limit number of flows
  -l TEXT     packets number a flow will send
  -w INTEGER  Tx Delay value (ns)
  -a          Script will not reset generator's state, but will append its
              config
  -q          queue mapping with interrupts affinity
  -o INTEGER  tos for IPv4 or traffic class for IPv6 traffic
  -r TEXT     bps rate limit per thread
  -y TEXT     pps rate limit per thread
  --help      Show this message and exit.
```

A simple sample command would be 
```
python3 -m pktperf.pktperf -i eth0 -s 64 -m 00:78:0a:fa:34:12 -t 12 -c 1200 -d 192.168.10.100 -n 0
```

During pktgen running, all stats will be display with 1 sec interval
```
Core  0 send                 10894413 pkts: 904722 pps 463217664 bps 0 errors
Core  1 send                 10865308 pkts: 902305 pps 461980160 bps 0 errors
Core  2 send                 10859822 pkts: 901849 pps 461746688 bps 0 errors
Core  3 send                 10778662 pkts: 896297 pps 458904064 bps 0 errors
Core  4 send                 10894414 pkts: 904721 pps 463217152 bps 0 errors
Core  5 send                 10872270 pkts: 902882 pps 462275584 bps 0 errors
Core  6 send                 10859791 pkts: 901846 pps 461745152 bps 0 errors
Core  7 send                 10906863 pkts: 905754 pps 463746048 bps 0 errors
Core  8 send                 10868798 pkts: 902594 pps 462128128 bps 0 errors
Core  9 send                 10872302 pkts: 902885 pps 462277120 bps 0 errors
Core 10 send                 10859437 pkts: 901817 pps 461730304 bps 0 errors
Core 11 send                 10907599 pkts: 905816 pps 463777792 bps 0 errors
Total   send                130439679 pkts: 10833488 pps 5546745856 bps  0 errors
```


## Todo
(Consider )A client show packet loss stats