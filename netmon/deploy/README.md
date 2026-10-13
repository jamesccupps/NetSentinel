# Running netmon as a service

Two units, deliberately. tcpdump captures; netmon analyses. A crash in the
analysis loses analysis, which can be redone, and not the capture, which cannot.

## 1. The capture

Get the command, filter and all:

```
python -m netmon capture --profile /etc/netmon/site.yaml \
    --dir /var/lib/netmon/capture --command
```

Put what it prints into `netmon-capture.service`. It needs root to open the
socket and drops to the `netmon` user immediately after (`-Z`).

Before you trust the filter, check it on this machine:

```
tcpdump -i mirror0 -c 20000 -w /tmp/sample.pcap        # no filter
python -m netmon bpf --profile /etc/netmon/site.yaml --verify /tmp/sample.pcap
rm /tmp/sample.pcap
```

It will tell you which VLANs the filter keeps and which it drops. BPF's 802.1Q
handling differs between libpcap and Npcap, so this is the only way to know.

## 2. The analysis

`netmon.service` runs `python -m netmon serve`, which analyses each capture file
as it rotates, checks the controller configuration every few hours, follows the
canary log, prunes the ring buffer and serves the UI on localhost.

It needs no privileges beyond reading the capture directory.

## The capture interface

No address, no routes, no protocol bindings. A capture NIC left configured puts
DHCP, NBNS, LLMNR, mDNS, SSDP and EAPOL onto the mirrored VLAN, which
contaminates every baseline built from it.

```
ip link set mirror0 up
ip addr flush dev mirror0
sysctl -w net.ipv6.conf.mirror0.disable_ipv6=1
```

List its MAC under `sensor_macs` in the profile and the `sensor_chatter` rule
will tell you if it ever transmits anyway.

## Secrets

`/etc/netmon/secrets.json`, mode 600, owned by `netmon`:

```json
{
  "ntfy_server": "https://ntfy.your-server.example",
  "ntfy_topic": "occ-alerts",
  "ntfy_token": "tk_...",
  "anthropic_api_key": "sk-ant-..."
}
```

netmon refuses a secrets file readable beyond its owner, and refuses to publish
to a public ntfy topic without a token.

`UNIFI_API_KEY` goes in the unit's `Environment=` or an `EnvironmentFile=`
(also mode 600). Use a view-only UniFi account.
