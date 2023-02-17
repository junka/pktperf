# pktperf
pktgen is very useful for network performance test, especially when we don't have 
multiple nics for dpdk. And for ```vm2vm``` test, it would be easy to use for end-user.

Pktperf is scripts repacked for pktgen (the kernel version).

It makes use of the sample scripts in linux kernel [https://github.com/torvalds/linux/tree/master/samples/pktgen]

All ```cmds``` in [https://www.kernel.org/doc/Documentation/networking/pktgen.txt]

## install
```pip3 install pktperf```

## usage
A simple sample command would be 
```
pktperf -i eth0 -s 64 -m 00:78:0a:fa:34:12 -t 12 -c 1200 -d 192.168.10.100 -n 0
```


It keeps parameters the same with sample scripts.
```
usage: pktperf.py [-h] -i INTERFACE [-s SIZE] [-d DEST] [-m MAC]
                  [-p PORTRANGE] [-k] [-t THREADS] [-f FIRSTTHREAD] [-c CLONE]
                  [-n NUM] [-b BURST] [-v] [-x] [--ipv6] [-z FLOWS]
                  [-l FLOWPKT] [-w DELAY] [-a] [-q] [-o TOS] [-r BPS] [-y PPS]
                  [-e FRAGS]

pktgen python scripts

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        output interface/device
  -s SIZE, --size SIZE  packet size
  -d DEST, --dest DEST  destination IP. CIDR is also allowed
  -m MAC, --mac MAC     destination MAC-addr
  -p PORTRANGE, --portrange PORTRANGE
                        destination PORT range is also allowed
  -k, --txcsum          enable UDP tx checksum
  -t THREADS, --threads THREADS
                        threads to start
  -f FIRSTTHREAD, --firstthread FIRSTTHREAD
                        index of first thread
  -c CLONE, --clone CLONE
                        SKB clones send before alloc new SKB
  -n NUM, --num NUM     num messages to send per thread, 0 means indefinitely
  -b BURST, --burst BURST
                        HW level bursting of SKBs
  -v, --verbose         verbose
  -x, --debug           debug
  --ipv6                IPv6
  -z FLOWS, --flows FLOWS
                        Limit number of flows
  -l FLOWPKT, --flowpkt FLOWPKT
                        packets number a flow will send
  -w DELAY, --delay DELAY
                        Tx Delay value (ns)
  -a, --append          Script will not reset generator's state, but will
                        append its config
  -q, --queuemap        queue mapping with irq affinity
  -o TOS, --tos TOS     tos for IPv4 or traffic class for IPv6 traffic
  -r BPS, --bps BPS     bps rate limit per thread
  -y PPS, --pps PPS     pps rate limit per thread
  -e FRAGS, --frags FRAGS
                        frags number in skb_shared_info
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


```pkts``` are exactly the number sent out the each queue, if you see any of them less than
the others, there could be a rate limit for the port or the queue.


By default, the flows contain packets with udp src port 9 to 1009. It means sending
1k flows. With ```-p``` you can specify udp dst port range. So if you want send 100k
flows, put ```-p 200-300``` into the parameters.


```-d``` specifies the destination ip address, with ```192.168.0.100/31```, the pktgen will
send packets to both 192.168.0.100 and 192.168.0.101. Or you can use range like port range 
above ```192.168.0.100-192.168.0.101``` instead.


the limit options ```-y``` and ```-r``` seems not working for pktgen now.


I don't see any verbose print with ```-x``` or ```-v```, maybe remove them later.


With ```-b``` the pktgen could get more performance gain.