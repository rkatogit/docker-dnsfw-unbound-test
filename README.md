# docker-dnsfw-unbound-test

## Overview
Simple test for Unbound with ThreatSTOP(SIEM Integration;ThreatList csv format) using Docker.

## Installation

```
$ docker build -t unbound-test:1 .
$ docker run -p 53:53/udp --name unbound_ts -it unbound-test:1
$ docker exec -it unbound_ts bash
```
## Usage
Run in debug mode.
```
$ unbound -dd -vvv
```
### Check
```
$ dig @127.0.0.1 bad.threatstop.com         

; <<>> DiG 9.9.4-RedHat-9.9.4-61.el7_5.1 <<>> @127.0.0.1 bad.threatstop.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 13285
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bad.threatstop.com.		IN	A
```

## Link
[ThreatSTOP documentation](https://docs.threatstop.com/)  
[NVC](https://www.nvc.co.jp)

