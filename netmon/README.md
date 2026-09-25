# netmon

A passive monitor for one building's network: building automation, access
control, video, kiosks, parking — the flat, unsegmented, unencrypted things that
run a site and were never designed to be watched.

It reads a mirror port or a capture file, says what it sees, and changes
nothing. No inline blocking, no firewall automation, no TLS interception. The
output is advisory.

Everything site-specific lives in a YAML profile, so the same rules mean
something at a second site. Point it at a different profile and the rules still
apply.

---

## Try it

```
python -m netmon.analyze --profile netmon/profiles/example-site.yaml \
                         --unifi flows.csv
```

The shipped `example-site.yaml` is a fictional site that exists to document the
schema. Copy it, fill in your own, and **keep the result out of version
control** — see *Your profile is sensitive* below.

For the web UI:

```
python -m netmon.web --profile my-site.yaml --unifi flows.csv
```

It binds to localhost and will not write anything without `--allow-edit`.

---

## What it does

| | |
|---|---|
| `profile.py` | the site: VLANs, devices, roles, expected flows, allowlists |
| `bpf.py` | VLAN-aware capture filters, verified against tcpdump |
| `events.py` | one event type for every source, plus enrichment |
| `rules_engine.py` | the YAML rule language |
| `handlers.py` | the rules that need memory |
| `rules/core.yaml` | 21 detection rules |
| `sources/unifi_csv.py` | UniFi flow exports |
| `analyze.py` | the offline analyzer |
| `web.py` | the local UI |

Each module's docstring explains what it is for and what will go wrong if you
change it carelessly. Those are the real documentation; this file is the map.

---

## Your profile is sensitive

A completed profile is a map of your network: VLANs, device inventory, which
systems are unencrypted, what is reachable from where. That is the document an
attacker would most like to be handed.

`.gitignore` already excludes `netmon/profiles/*.yaml` except the example. Keep
yours somewhere else and pass its path:

```
mkdir -p ~/.config/netmon
cp netmon/profiles/example-site.yaml ~/.config/netmon/my-site.yaml
python -m netmon.profile ~/.config/netmon/my-site.yaml     # validate it
```

Captures are excluded too. Some segments carry credentials or cardholder data in
the clear; a test fixture must be synthetic, and every fixture in
`netmon_tests/` is.

---

## Segments whose payload must never be stored

Mark a VLAN `store_payload: false` and nothing from it is written to disk,
extracted, logged, or included in anything sent anywhere. Set it on any segment
carrying regulated or credential-bearing traffic — badge readers, payment
kiosks.

```yaml
vlans:
  40:
    name: access-control
    subnet: 10.10.40.0/24
    store_payload: false      # metadata only: who, when, how much. Never what.
```

The prohibition is resolved once, during enrichment, and any payload already
attached is dropped rather than left for a rule to remember not to read.
Metadata from those segments is still used — a door controller reaching the
internet is worth knowing about — it is the contents that are never kept.

No rule may name a credential-, cookie-, card- or payload-bearing field in its
evidence, description or key. A test checks every shipped rule, because those
three all end up in logs, alerts and AI prompts.

---

## Capture filters

BPF handles 802.1Q badly enough that hand-written filters are usually wrong in
ways that fail silently. Two forms that read correctly:

```
not vlan or (vlan and (tag == 5 or tag == 6))    matches ONLY untagged
(vlan and (tag == 5 or tag == 6)) or not vlan    matches EVERYTHING
```

The second is the dangerous one: a filter written to capture two HVAC VLANs
silently captures the restricted VLAN too. `bpf.py` never emits either, and
both are kept as executable documentation in `netmon_tests/test_bpf.py`, which
runs them against tcpdump and asserts on what came out.

Since stacks disagree — `ether[12:2] != 0x8100` is reported not to exclude
tagged frames under Npcap, where it does under libpcap — verify on the machine
that will run it:

```
python -m netmon.bpf --profile my-site.yaml --verify sample.pcap
```

Take the sample with no filter at all, on that machine, and it will tell you
what your candidate actually keeps, per VLAN.

---

## Writing rules

```yaml
- id: bacnet_control
  title: A BACnet command outside the write allowlist
  severity: critical
  tier: push
  grounded_in: BACnet/IP has no authentication. Anything that can reach it can command a controller.
  when:
    kind: bacnet
    service: [WriteProperty, WritePropertyMultiple]
  unless:
    bacnet_write_allowed: true
  device: dst_name
  key: "{src_ip}->{dst_ip}/{object}"
  describe: "{src_name} sent {service} to {dst_name}, object {object}"
  next_check: "tshark -r <pcap> -Y 'bacapp.type == 0 && ip.src == {src_ip}'"
```

`when` must all match; `unless` cancels it. Operators: a bare value is equality,
a list is membership, and a mapping is `gt` `gte` `lt` `lte` `matches`
`contains` `not` `in` `not_in` `exists`, with `any` and `all` for nesting.
Nothing is evaluated as code.

Everything the profile knows was resolved before the rule ran, so `src_role`,
`src_zone`, `flow_expected`, `bacnet_write_allowed`, `quiet_hours` and
`direction` are all just fields.

Validate before you rely on it:

```
python -m netmon.rules_engine --check my-rules.yaml
```

Two conventions the tests enforce on the shipped rules: every rule says what it
is **grounded in** — a rule nobody can trace to a real observation is one nobody
will trust enough to act on — and every rule offers a **next check**, because an
alert with no suggested next step is a notification, not a finding.

---

## Reading a UniFi export

Two things about the format will cost you a day if nobody tells you.

**"Bytes Sent" is what the source downloaded. "Bytes Rec." is what it
uploaded.** The labels are from the gateway's point of view. Taking them at face
value inverts every upload rule, so exfiltration reads as a download. The
importer maps them to `bytes_to_dst` and `bytes_to_src`, which cannot be
misread.

**The totals undercount long-lived sessions**, by about fourfold in a measured
24-hour export. Every event carries a flag saying so. Treat them as a floor.

Also: it is semicolon-delimited, the timestamp column mixes precisions within
one file, `Dst. Domain` is inferred and unreliable (kept as `domain_hint` so no
rule matches it by accident), and traffic the gateway itself sends or receives
is absent. Absence of a flow in an export is not evidence it did not happen.

---

## Status

Phase 1 works: profile, rules, UniFi import, offline analysis, the UI, and the
capture-filter builder.

Not built yet: live capture, pcap replay through protocol parsers, ntfy
alerting, the Claude API summariser, UniFi API device sync, and the
protocol-specific rules (Siemens P2, Otis, Gallagher, parking kiosks) that need
those parsers.

Test it with `python -m unittest discover -s netmon_tests -t .` from the
repository root.
