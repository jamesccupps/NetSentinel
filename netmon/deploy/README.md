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
It exits 3 if anything from a metadata-only segment — by tag or by address —
got through; do not start the capture unit until it exits 0. On the same
sample, `python -m netmon bpf --diagnose-untagged /tmp/sample.pcap` says which
untagged form this stack honours (exit 4: capture tagged and untagged
separately).

## 2. The analysis

`netmon.service` runs `python -m netmon serve`, which analyses each capture file
as it rotates, checks the controller configuration every few hours, follows the
canary log, prunes the ring buffer and serves the UI on localhost.

It needs no privileges beyond reading the capture directory. Everything it
keeps is under `/var/lib/netmon` (`ReadWritePaths`); the home directory is not
writable (`ProtectHome`), which is why the summariser's spend lives under
`--state`.

Its UI is read-only unless you add `--allow-edit` (the editors and the
acknowledge/snooze/maintenance buttons) and has no model button unless you add
`--allow-summarise`. Each is a deliberate decision; add it to `ExecStart` if
you want it.

## GeoIP (optional)

```
pip install maxminddb
sudo -u netmon python3 -m netmon geoip --update --dir /var/lib/netmon/geoip
```

and `geoip: directory: /var/lib/netmon/geoip` in the profile. DB-IP publishes
monthly; re-run `--update` monthly (a cron entry or a timer as the `netmon`
user). It downloads the two DB-IP Lite files and sends nothing about the site.
The running service picks up new files by itself.

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

  "smtp_host": "smtp.your-provider.example",
  "smtp_port": 587,
  "smtp_security": "starttls",
  "smtp_username": "sensor@your-site.example",
  "smtp_password": "...",
  "smtp_from": "sensor@your-site.example",
  "smtp_to": ["ops@your-site.example"],

  "anthropic_api_key": "sk-ant-...",
  "summariser_daily_tokens": 200000,
  "summariser_hourly_sends": 6
}
```

Every block is optional. The `smtp_*` keys turn on the email digest, over
STARTTLS (587) or SMTPS (`"smtp_security": "ssl"`, 465) with the certificate
verified; the SMTP credentials are read from this file only.

netmon refuses a secrets file readable beyond its owner, refuses to publish
to a public ntfy topic without a token, and refuses SMTP without TLS except to
a relay on this machine with no credentials.

`UNIFI_API_KEY` goes in the unit's `Environment=` or an `EnvironmentFile=`
(also mode 600). Use a view-only UniFi account.
