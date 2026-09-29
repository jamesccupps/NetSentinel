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
                         --unifi flows.csv --pcap capture.pcapng
```

Either source alone works. They answer different questions: a flow export covers
every device for a day but carries no protocol detail, while a capture carries
BACnet commands, TLS server names and DNS but only sees one mirror port.

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
| `sources/pcap.py` | capture files and live mirror ports |
| `protocols/bacnet.py` | BACnet/IP: commands, objects, broadcast tables |
| `analyze.py` | the offline analyzer |
| `redact.py` | what may leave the building |
| `alerting.py` | ntfy push and the daily digest |
| `summarise.py` | asking a model to triage the findings |
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

## Alerting

```
export NETMON_NTFY_SERVER=https://ntfy.your-server.example
export NETMON_NTFY_TOPIC=occ-alerts
export NETMON_NTFY_TOKEN=tk_...          # or omit, for a server only you can reach

python -m netmon.analyze --profile my-site.yaml --pcap capture.pcapng \
                         --notify --digest
```

Add `--dry-run` to see what would be sent. Settings can also live in a JSON file
passed with `--secrets`, which must be mode 600 — the environment overrides it.

**Publishing to a public ntfy topic is refused.** ntfy.sh has no access control
on a topic: anyone who guesses or overhears the name receives everything sent to
it, forever. These alerts name devices, addresses and weaknesses, so a guessable
topic is a live feed of the site's soft spots. Use an access token, or host your
own server.

Push is reserved for the `push` tier and, by default, `high` and above. A
notification for something that can wait is how push gets muted, after which
nothing gets through at all.

---

## What leaves, and where it goes

Every outbound path goes through `redact.py`, which has two audiences because
the rules differ:

**Alerts** may name devices, addresses, VLANs and what happened — that is the
alert. They may not carry payload, credential values, cookies, card or RFID
data. Metadata from a restricted segment *is* allowed: "a door controller
reached the internet at 3am" is exactly what those segments exist to produce,
and contains nothing regulated.

**A summary sent to a model** gets all of the above, and nothing at all from a
restricted segment — not the addresses, not the device names, not the fact that
something happened there. The count of what was withheld is included, so the
omission cannot be read as "nothing happened there".

Evidence fields are allowlisted, not denylisted. Rules are edited by site
operators and can name any field they like, so the question has to be "is this
known to be safe", not "is this known to be dangerous" — a denylist is a list of
the mistakes someone already made.

A test fires every shipped rule against an event stuffed with a password, a
session cookie, a card number and a private key, then audits the redacted
output. Adding a rule that names a value-bearing field fails there.

---

## Model triage

```
export ANTHROPIC_API_KEY=sk-ant-...
python -m netmon.analyze --profile my-site.yaml --pcap capture.pcapng --summarise
python -m netmon.analyze --profile my-site.yaml --pcap capture.pcapng \
                         --investigate ahu-controller-1
```

The rules detect; the model prioritises and explains. It is told to be willing
to call something benign — a triage that agrees with every rule is worth
nothing.

Model, daily token budget, API base URL and redaction level are all configurable
(`NETMON_SUMMARISER_MODEL`, `NETMON_SUMMARISER_DAILY_TOKENS`,
`ANTHROPIC_BASE_URL`, `NETMON_SUMMARISER_REDACTION=minimal`), so a local model
can be substituted and an unattended cron job cannot run up a bill. Set the base
URL and the request drops the API-specific options a local model would reject.

Three things it deliberately does not do:

**It does not write commands.** It says in prose what to check; the command
comes from the rule, which is authored in this repository. An allowlist was the
first attempt and it does not hold — `python3 -c` runs anything, `tcpdump -z`
executes a program, `ip link set` changes the network — and filtering per-command
flags means writing a shell parser and being right about every tool. A monitor's
output is exactly what someone pastes into a root shell without reading twice.

**It does not write BPF.** It returns which VLANs, hosts and ports to watch, and
`netmon.bpf` builds the filter. One of the two wrong VLAN forms silently
captures a segment the site forbids storing; that is not a judgement to
delegate.

**It does not act.** Nothing it returns is executed, and it is told not to
recommend changes to the network — only what to look at.

The findings sent to it contain device and server names taken from the network
being watched. They are fenced and labelled as data in the prompt, and the
response is checked before anything is shown.

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

In a description, `[...]` containing a `{field}` disappears when that field is
empty — `[, object {object}]` for the BACnet services that have no object.
Brackets with no placeholder are left alone, so a `next_check` carrying
`ether[14:2]` survives intact.

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

Working: the profile, the rule engine and 21 rules, UniFi flow import, capture
reading with BACnet / TLS / DNS / DHCP / ARP parsing, offline analysis, the web
UI, and the capture-filter builder.

Not built yet: ntfy alerting, the Claude API summariser, UniFi API device sync,
a rolling capture ring buffer, and the remaining site protocols (Siemens P2,
Otis, Gallagher, parking kiosks).

Test it with `python -m unittest discover -s netmon_tests -t .` from the
repository root.

---

## Two things about reading a trunk mirror

**Every routed packet appears twice** — once arriving from the sender on the
source VLAN, once leaving the router on the destination VLAN. In a measured
seven-second sample, 3,178 packets appeared on both sides. Counting both doubles
every byte total and attributes half the traffic to the router. List your
routers under `router_macs` and the relayed copy is dropped.

**The capture interface should be silent.** No address, no protocol bindings.
One left configured puts DHCP, NBNS, LLMNR, mDNS, SSDP and EAPOL onto the
mirrored VLAN, contaminating every baseline built from it. List its MAC under
`sensor_macs` and the `sensor_chatter` rule will say so if it ever transmits.
