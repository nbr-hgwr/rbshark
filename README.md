# rb_packet_capture
## 概要
パケットキャプチャーを行うrubyスクリプトです

## 実行例
```
$ ruby packet_capture.rb eth1
Ethernet Header-----------------
  dst: 08:00:27:f6:35:a0
  src: 08:00:27:a3:85:d1
  type: 2048 (IP)
IP Header-----------------------
  dst: 192.168.33.12
  src: 192.168.33.11
  type: 1 (ICMP)
  version: 4, header_len: 5, tos: 0
  len: 84, id: 20001, flag_off: 16384
  ttl: 64, check: 10528
ICMP----------------------------
  type: 8 (Echo Request)
  code: 0
  check: 9357
  
```

## サンプル
```
$ vagrant box add centos/7

$ vagrant up

```
