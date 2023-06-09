# pktperf
pktgen is very useful for network performance test, especially when we don't have multiple nics for dpdk in a vm.

It makes use of the sample scripts in linux kernel [samples/pktgen](https://github.com/torvalds/linux/tree/master/samples/pktgen)

All ```cmds``` in [networking/pktgen.txt](https://www.kernel.org/doc/Documentation/networking/pktgen.txt)

---

Pktperf is python scripts for pktgen (the kernel version).
Also it provides a out of tree pktgen module (tested on kernel 5.4, but supposed to be compatible with 4.15 at mininum). During pip install, it will try builing the module and if not only the original pktgen function can be supported.


## install
```pip3 install pktperf```

## usage
A simple sample command would be 
```
pktperf -i eth0 -s 64 -m 00:78:0a:fa:34:12 -t 12 -c 1200 -d 192.168.10.100 -n 0
```
By default, the flows contain packets with udp src port 9 to 1009. It means sending
1k flows. With ```-p``` you can specify udp dst port range. So if you want send 100k
flows, put ```-p 200-300``` into the parameters.


```-d``` specifies the destination ip address, with ```192.168.0.100/31```, the pktgen will
send packets to both 192.168.0.100 and 192.168.0.101. Or you can use range like port range 
above ```192.168.0.100-192.168.0.101``` instead.



Also, you can use a config file to set packet fields, see ```example.cfg```
```
pktperf -i eth0 --file example.cfg -n 0 -c 10 -t 12
```


Also provide some scenario testcase

Internet mix test case:

```imix_weights size_1:weight_1,size_2:weight_2,...size_n:weight_n```

For example: 
```
imix_weights 40:7,576:4,1500:1

The pkt_size "40" will account for 7 / (7 + 4 + 1) = ~58% of the total
packets sent.

```


micro burst test case:

```microburst duration_poll,duration_idle```

```
microburst 200,100

pktgen will be sending 200ms and then keep 100ms idle, loop follow the pattern
```


During pktgen running, all stats will be display with 1 sec interval
```
Core  0 send                 10894413 pkts: 904722 pps 463217664 bps 0 errors
Core  1 send                 10865308 pkts: 902305 pps 461980160 bps 0 errors
...
Core 11 send                 10907599 pkts: 905816 pps 463777792 bps 0 errors
Total   send                130439679 pkts: 10833488 pps 5546745856 bps  0 errors
```


```pkts``` are exactly the number sent out the each queue, if you see any of them less than
the others, there could be a rate limit for the port or the queue.


