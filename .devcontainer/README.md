```
iptables --table nat --append PREROUTING --proto tcp --dport 18080 --jump REDIRECT --to-ports 4143
```
