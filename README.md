# dhcp6dump
CLI utility for dumping captured DHCPv6 packets in PCAP format (captured by tcpdump or Wireshark).



# Usage
PHP 7+ is required.

0) `apt-get install php-cli`
1) Download [latest PHAR](https://github.com/milo/dhcp6dump/releases/latest) archive.
2) `chmod 755 dhcp6dump.phar`
3) `tcpdump -nn -i eth0 -s 0 -w - port 546 or port 547 | ./dhcp6dump.phar`

If you don't set execution bit, you can invoke PHAR by `php dhcp6dump.phar`.

Utility has few CLI options. Run `./dhcp6dump.phar -h` to show them.



# Speed!
I'm live parsing ~40-50 packets/second (I have no higher traffic), ~1500-2000 packets/second offline.   



# What `TODO` means?
There is a many DHCPv6 message types and a lot of options. A `TODO` in the output means
that I didn't implement parsing for it. You will see only plain hex dump.
Open an [issue](https://github.com/milo/dhcp6dump/issues) for it, ideally with captured packets. 



# An example output
(some MAC or IP addresses are anonimized) 
```
No.4 (2017-08-07 19:51:30.567414 UTC)

Eth Src: bc:30:5b:da:b1:16
Eth Dst: 3c:8a:b0:85:d3:b3

IPv6 Src: 2002:817:2:0012::129:28
IPv6 Dst: 2002:817:2:2222::1

Message type: 13 (RELAY-REPLY)
Hop count: 0
Link address: 2002:817:2:1111::1
Peer address: fe80::223:5eff:feb7:d6ba
Option: 9 (RELAY_MSG)
        Message type: 7 (REPLY)
        Transaction ID: 0x0072E9
        Option: 3 (IA_NA)
            IAID: 0x00000001
            T1: 0s
            T1: 0s
            Data:
                00 05 00 18 20 01 07 18 00 02 11 11  (............)

        Option: 1 (CLIENTID)
            Type: 3 (DUID-LL)
                HW Type: 1 (ethernet)
                MAC: 00:23:5e:b7:d6:ba

        Option: 2 (SERVERID)
            Type: 1 (DUID-LLT)
                Time: 2016-11-23 14:02:14 GMT
                HW Type: 1 (ethernet)
                MAC: bc:30:5b:da:b1:16

        Option: 7 (PREFERENCE)
            255 (0xFF)

        Option: 23 (DNS_SERVERS)
            2002:817:2:0012::125:18
            2002:817:2:0012::135:16

        Option: 24 (DOMAIN_LIST)
            my.example.com

        Option: 17 (VENDOR_OPTS)
            Enterprise Number: 9 (Cisco Systems)
            Vendor Option: 1 (TFTP)
                2002:915:9:3305::199
                2002:915:9:3305::200
```
