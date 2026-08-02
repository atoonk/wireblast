# 011 - the IMIX ceiling

IMIX at unlimited rate: how much realistic traffic can this box actually push.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

At a 362-byte average, 10G line rate is about 3.27 Mpps. If you reach that, the box can
saturate 10G with a realistic mix. If you don't, example 019 helps you find the limit.

## Safety

Unlimited rate on a default-route interface will starve the host, and Wireblast will
make you confirm it. Use a test NIC.
