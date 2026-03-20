# pktsniff

packet sniffer in C. linux/wsl2 only

## build

```bash
gcc sniffer.c parse.c util.c -o sniffer
```

## run

```bash
sudo ./sniffer
sudo ./sniffer -t # tcp only
sudo ./sniffer -u # udp only
sudo ./sniffer --port 443 # filter by port
sudo ./sniffer -t -x # tcp, no hexdump
sudo ./sniffer -h # help
```

needs root for raw sockets