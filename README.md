# pktperf
pktperf is a very thin layer for pktgen (the kernel version).
It makes use of the sample scripts in linux kernel [https://github.com/torvalds/linux/tree/master/samples/pktgen]
All ```cmds``` in [https://www.kernel.org/doc/Documentation/networking/pktgen.txt]

## install
```pip install pktperf```

## usage
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
  -q          queue mapping with irq affinity
  --help      Show this message and exit.
```

## Todo
A realtime gui show PPS stats
A client show packet loss stats