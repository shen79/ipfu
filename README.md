# ipfu - IP kung-FU - another packet crafting tool

## TL;DR - what's dis
It's a packet crafting tool written in python, using scapy.
Kinda modular, at the moment we have the following modules:
- arpsub - broken? ... i dont remember
- gwscan - try to find a (gate)way to a different network
- tracemap - broken/unfinished
- flagfuzzer - TCP flag fuzzing for firewall auditing and messing with the netstack
- udpholepunch - broken/unfinished
- lvsdetect - LVS/IP.id measuring
- rr - IP Options Record Route feature - like traceroute but -forexample- leaks internal IP addresses, etc. - see below
- tsfu - IP Options timestamp feature to map remote (internal) networks
- synfinfu - iptables firewall "--syn" bypass (Only match TCP packets with the SYN bit set and the ACK,RST and FIN bits cleared.)
- arping - i dont remember.

## short story
I wrote this tool a few years ago.
Originally it was publicated at https://gitorious.org/buherablog/packet-fu.git/
The techniques implemented in this tool were mostly discussed on BuheraBlog:
- [packet-fu#1|http://buhera.blog.hu/2013/01/27/packet-fu]
- [packet-fu#2|http://buhera.blog.hu/2013/02/11/packet-fu_341]
- [packet-fu#3|http://buhera.blog.hu/2013/03/04/packet-fu_513]
- [packet-fu#4|http://buhera.blog.hu/2013/12/07/packet-fu_538]
