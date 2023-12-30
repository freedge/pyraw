Make sure server is allowed to send all the data
```
ip route add 192.168.254.1/32  via 192.168.42.254 dev enx00155d343121 initcwnd 100 initrwnd 100
```

To help check proper TCP window on firewall, we assume a server running with
```
dd if=/dev/zero count=150 bs=1024 | nc -l 8000
```

we code our own client, that will ACK packets for the first 20000 bytes, then lets the server sends packets, and only ack the last one.
tcpdump should show all the packets sent from the server side.

```
# we make sure Linux does not steal TCP packets received by our client
ip netns exec palo  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# we make sure the session is reused on server side, alernatively
# we can also drop the FIN packets sent by the server so that the session is still ACTIVE when the client reconnect.
set session timeout-tcp-time-wait 120

# run a first time
ip netns exec palo python rawsocket.py  11000 1000000000

# it completes successfully, we close client and server, wait for the server socket to fin:
watch ss -napoi dport eq :11000

# we restart the server, then reuse the session, with a different seq number
ip netns exec palo python rawsocket.py  11000 2000000000

# check if the firewall dropped any packet
```
