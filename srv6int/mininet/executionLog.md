```
~/SRv6_Computer_Networks/p4-srv6-updated$ sudo python3 mininet/topo.py 
Unable to contact the remote controller at 10.0.0.1:6653
Unable to contact the remote controller at 10.0.0.1:6633
Setting remote controller to 10.0.0.1:6653
2001:1:1::ff/64 00:00:00:00:00:11
Assigned 2001:1:1::ff/64 to r1:r1-eth1
2001:1:1::fe/64 00:00:00:00:00:12
Assigned 2001:1:1::fe/64 to r1:r1-eth2
2001:1:2::fe/64 00:00:00:00:00:21
Assigned 2001:1:2::fe/64 to r2:r2-eth1
2001:1:2::ff/64 00:00:00:00:00:22
Assigned 2001:1:2::ff/64 to r2:r2-eth2
.......⚡️ simple_switch_grpc @ 99962
...⚡️ simple_switch_grpc @ 100001
```

```
mininet> c0 /home/p4/src/p4dev-python-venv/bin/python3 mininet/set_flow_tables.py
```

```
teardown failed
LPM value was transformed to conform to the P4Runtime spec (trailing bits must be unset)
field_id: 1
lpm {
  value: " \001\000\001\000\001\000\000\000\000\000\000\000\000\000\000"
  prefix_len: 64
}

param_id: 1
value: "\020"

Routing_v6 entry added: 2001:1:1::1/64 -> next hop 00:00:00:00:00:10
field_id: 1
exact {
  value: "\020"
}

param_id: 1
value: "\001"

Unicast entry added: 00:00:00:00:00:10 -> port 1
LPM value was transformed to conform to the P4Runtime spec (trailing bits must be unset)
field_id: 1
lpm {
  value: " \001\000\001\000\002\000\000\000\000\000\000\000\000\000\000"
  prefix_len: 64
}

param_id: 1
value: "!"

Routing_v6 entry added: 2001:1:2::1/64 -> next hop 00:00:00:00:00:21
field_id: 1
exact {
  value: "!"
}

param_id: 1
value: "\002"

Unicast entry added: 00:00:00:00:00:21 -> port 2
param_id: 1
value: "\001"

switch IP set to 1
LPM value was transformed to conform to the P4Runtime spec (trailing bits must be unset)
field_id: 1
lpm {
  value: " \001\000\001\000\001\000\000\000\000\000\000\000\000\000\000"
  prefix_len: 64
}

param_id: 1
value: "\021"

Routing_v6 entry added: 2001:1:1::1/64 -> next hop 00:00:00:00:00:11
field_id: 1
exact {
  value: "\021"
}

param_id: 1
value: "\001"

Unicast entry added: 00:00:00:00:00:11 -> port 1
LPM value was transformed to conform to the P4Runtime spec (trailing bits must be unset)
field_id: 1
lpm {
  value: " \001\000\001\000\002\000\000\000\000\000\000\000\000\000\000"
  prefix_len: 64
}

param_id: 1
value: " "

Routing_v6 entry added: 2001:1:2::1/64 -> next hop 00:00:00:00:00:20
field_id: 1
exact {
  value: " "
}

param_id: 1
value: "\002"

Unicast entry added: 00:00:00:00:00:20 -> port 2
param_id: 1
value: "\002"

switch IP set to 2
```

```
mininet> h1 ping6 h2
PING 2001:1:2::1(2001:1:2::1) 56 data bytes
64 bytes from 2001:1:2::1: icmp_seq=1 ttl=62 time=47.6 ms
64 bytes from 2001:1:2::1: icmp_seq=2 ttl=62 time=18.2 ms
64 bytes from 2001:1:2::1: icmp_seq=3 ttl=62 time=14.6 ms
^C
--- 2001:1:2::1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 14.588/26.827/47.646/14.796 ms
```

```
mininet> h2 python3 mininet/reciever.py --int h2-eth0 &
mininet> h1 python3 mininet/sender.py --int h1-eth0 00:00:00:00:00:10 2001:1:1::1 00:00:00:00:00:20 2001:1:2::1
```

```
arguments parsed
interface : h1-eth0
src MAC : 00:00:00:00:00:10
src IP : 2001:1:1::1
dst MAC : 00:00:00:00:00:20
dst IP : 2001:1:2::1
INt header : 400c0000
Sent: 000000000020000000000010ffff400c00006000000000003b402001000100010000000000000000000120010001000200000000000000000001
```

```
mininet> exit
```


In temp/received.txt :

```
Received: b'000000000020000000000021ffff402c0000010102016000000000003b3e2001000100010000000000000000000120010001000200000000000000000001'
```

So,

|           | packet (hex) |
| --------- | ------------ |
|Sent by h1 | `000000000020` `000000000010` `ffff` `400c0000`            `6000000000003b40` `20010001000100000000000000000001` `20010001000200000000000000000001`|
| at h2     | `000000000020` `000000000021` `ffff` `402c0000` `0101` `0201` `6000000000003b3e` `20010001000100000000000000000001` `20010001000200000000000000000001`|
