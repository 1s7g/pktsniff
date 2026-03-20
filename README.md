# pktsniff

packet sniffer written in C for linux. captures and parses network packets at layer 2.

i made this to learn how raw sockets work. it actually works pretty well now lol

## what it does

- captures packets from network interface (ethernet layer)
- parses ethernet, ipv4, tcp, udp, icmp, arp headers
- shows hex dump + ascii of packet data
- filter by protocol or port
- shows stats when you exit

## requirements

- linux (or wsl2 on windows)
- gcc
- root access (raw sockets need it)

## building

```bash
gcc sniffer.c parse.c util.c -o sniffer
```

thats it. no external libs needed, just standard linux headers

## usage

basic:

```bash
sudo ./sniffer
```

with filters:

```bash
sudo ./sniffer -t # only tcp
sudo ./sniffer -u # only udp
sudo ./sniffer -i # only icmp
sudo ./sniffer -a # only arp
sudo ./sniffer -p 443 # filter by port (src or dst)
sudo ./sniffer -x # hide hex dump
sudo ./sniffer -t -x # tcp only, no hex
```

you can combine filters like `-t -p 80` for tcp on port 80

ctrl+c to stop and see stats

## how it works

uses `AF_PACKET` socket with `SOCK_RAW` to capture at layer 2. grabs everything before the kernel processes it.

parses the headers manually by casting buffer to structs from `linux/` headers. 

the hex dump function took forever to get right dont @ me

## limitations

- linux only (uses AF_PACKET which is linux specific)
- ipv6 not fully parsed yet, just shows the header
- no pcap file output (might add later idk)
- probably some edge cases i havent hit yet

## troubleshooting

**"ERROR creating socket"** - you need root. use `sudo`

**"no packets showing up"** - make sure theres actual traffic. try pinging something in another terminal while sniffer runs

**wsl2 specific** - sometimes tcp doesnt show up immediately, just wait a sec or generate traffic with curl/wget

## files

- `sniffer.c` - main loop, arg parsing, filtering
- `parse.c` - packet parsing (eth/ip/tcp/udp/icmp/arp)
- `parse.h` - header for parse.c
- `util.c` - hexdump and other helpers
- `util.h` - header for util.c

split it up when sniffer.c got too long

## todo

- [ ] pcap output format
- [ ] ipv6 full support
- [ ] payload search (like grep but for packets)
- [ ] tcp stream reassembly maybe?
- [ ] better display for DNS queries

## license

idk do whatever you want with it. MIT i guess

---

made by me while learning network programming. if theres bugs lmk or just fix it yourself