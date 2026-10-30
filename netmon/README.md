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
pip install pyyaml scapy          # all it needs
python -m netmon                  # what there is
python -m netmon analyze --profile netmon/profiles/example-site.yaml \
                         --unifi flows.csv --pcap capture.pcapng
```

Every command is also a module — `python -m netmon.drift …` — which is what a
unit file or a cron entry should use.

Either source alone works. They answer different questions: a flow export covers
every device for a day but carries no protocol detail, while a capture carries
BACnet commands, TLS server names and DNS but only sees one mirror port.

The shipped `example-site.yaml` is a fictional site that exists to document the
schema. Copy it, fill in your own, and **keep the result out of version
control** — see *Your profile is sensitive* below.

For the web UI:

```
python -m netmon.web --profile my-site.yaml --unifi flows.csv
python -m netmon.web --profile my-site.yaml --state /var/lib/netmon/state --allow-edit
```

It binds to localhost, refuses any request whose Host header is not a loopback
name while it does (so a page elsewhere cannot rebind its own hostname to
127.0.0.1 and read it), and will not write anything without `--allow-edit`.
`--state` points it at the service's state directory, so it shows — and with
`--allow-edit` changes — the acknowledgements and snoozes the running service
applies. `--allow-summarise` adds the model-triage button; see *Model triage*.

---

## What it does

| | |
|---|---|
| `profile.py` | the site: VLANs, devices, roles, expected flows, allowlists |
| `bpf.py` | VLAN-aware capture filters, verified against tcpdump |
| `events.py` | one event type for every source, plus enrichment |
| `rules_engine.py` | the YAML rule language |
| `handlers.py` | the rules that need memory |
| `rules/core.yaml` | 26 detection rules |
| `rules/cloudflare-ranges.txt` | Cloudflare's published ranges, dated, never fetched |
| `geoip.py` | country and network (ASN) from DB-IP Lite, offline |
| `leakcheck.py` | restricted segments on disk, and outside their VLAN |
| `window.py` | the day's findings, deduplicated and kept across restarts |
| `sources/unifi_csv.py` | UniFi flow exports |
| `sources/pcap.py` | capture files and live mirror ports |
| `sources/unifi_api.py` | bootstrapping a profile from the controller |
| `protocols/bacnet.py` | BACnet/IP: commands, objects, broadcast tables |
| `protocols/site.py` | naming the systems a building runs |
| `analyze.py` | the offline analyzer |
| `redact.py` | what may leave the building |
| `canary.py` | hits on a host that has no legitimate users |
| `drift.py` | what the network is *allowed* to do, and what changed |
| `ringbuffer.py` | the rolling capture: what to run, keep and extract |
| `alerting.py` | ntfy push and the daily digest |
| `summarise.py` | asking a model to triage the findings |
| `service.py` | the recurring work, as one process |
| `web.py` | the local UI |
| `deploy/` | two systemd units and what to check before trusting them |

Each module's docstring explains what it is for and what will go wrong if you
change it carelessly. Those are the real documentation; this file is the map.

---

## Starting a profile from the controller

Typing out a dozen VLANs and however many devices is where the mistakes are.
The controller already knows most of it.

```
# once: get the controller's certificate fingerprint
python -m netmon.sources.unifi_api --host https://unifi.example --print-fingerprint

export UNIFI_API_KEY=...
python -m netmon.sources.unifi_api --host https://unifi.example \
    --fingerprint AA:BB:... --out ~/.config/netmon/my-site.yaml
```

Then fill in the three things the controller cannot know: a **zone** on each
VLAN (rules say "into the management zone", not "into VLAN 30", which is what
makes them portable), **`store_payload: false`** on segments carrying
credentials or cardholder data, and **`expected_flows`** for the cross-VLAN
traffic you know about.

Re-running merges. Names, roles, notes and everything the controller does not
know are kept; new devices are added, and devices that were not seen are kept
and listed rather than deleted — one that is merely switched off should not
vanish, and one that has genuinely gone is a decision for a person.

**Read-only, structurally.** The client class has one method, `get`. There is no
post, put or delete to reach for by accident. Use a view-only UniFi account as
well; this is the second lock, not the first.

**Pin the certificate rather than skipping verification.** A UniFi gateway on
your own network presents a self-signed certificate, and the usual advice is
`--insecure` — which turns "this is the controller" into "this is whatever
answered", on the one connection about to hand over an API key. `--fingerprint`
is one command to obtain and is a stronger guarantee than a public CA would give
for an internal service. `--insecure` exists, says what it gives up, and is not
the default.

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

**Each finding pushes once.** The service keeps the day's findings on disk
(`findings.json` under `--state`, owner-only), one per rule, device and key,
across capture files and restarts. A finding that recurs — every rotation, or
after a restart — adds to its count instead of pushing again. A push nobody
has acknowledged stays open: it is listed in every digest until a silence
covers it or it has not been seen for a week, and while it is open it does not
push again.

### The digest

Once a day, by ntfy and by email, whichever are configured. It leads with an
**open-items checklist** — pushes not yet acknowledged, configuration that is
wrong now (from the last controller check), and the silences in effect, each
with its reason and end — and then lists the day's findings worst first, with
acknowledged and maintenance findings marked as such. "Events" is packets and
flows read since the last digest. The day's findings are kept until a digest
is delivered, so one that could not be sent does not take them with it.

### Email

Add these to the secrets file; the credentials are read from there and nowhere
else, under the same owner-only check:

```json
{
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,
  "smtp_security": "starttls",
  "smtp_username": "sensor@example.com",
  "smtp_password": "...",
  "smtp_from": "sensor@example.com",
  "smtp_to": ["ops@example.com"]
}
```

`smtp_security` is `starttls` (587, the default) or `ssl` (SMTPS, 465); the
server's certificate is verified. `none` is refused except to a relay on this
machine with no credentials, because the digest names devices and weaknesses
and a password sent in the clear is given away. `email_digest: false` turns it
off without removing the settings. `analyze --digest` emails too when these
are set.

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
omission cannot be read as "nothing happened there". A finding counts as from a
restricted segment if anything about it points there — its VLANs, its event's
addresses and MACs, the device it names, the VLAN, zone, network or address in
its evidence, or an address in its text — which is what catches canary hits and
configuration findings, neither of which carries resolved VLAN fields.

Evidence fields are allowlisted, not denylisted. Rules are edited by site
operators and can name any field they like, so the question has to be "is this
known to be safe", not "is this known to be dangerous" — a denylist is a list of
the mistakes someone already made.

A test fires every shipped rule against an event stuffed with a password, a
session cookie, a card number and a private key, then audits the redacted
output. Adding a rule that names a value-bearing field fails there.

---

## Canary hits

```
python -m netmon.canary --profile my-site.yaml --log /var/log/opencanary.log --notify
```

A canary has no legitimate users. Every other finding here needs a judgement
about whether the traffic was normal; this one does not. Something connected to
a service that exists only to be connected to, and that is the whole finding —
always high, always push.

**Read the log file if you can.** OpenCanary writes JSON lines, and reading them
needs no listener, no open port and no shared secret. `--listen HOST:PORT` runs
a webhook for when the canary cannot reach the sensor's disk: one route, one
verb, a token compared with `compare_digest`, a capped body and a capped rate.
A `GET` returns 405 rather than a status page — it listens on a network the
canary is on, and anything it says is something an attacker learns for free.

**The username is reported; the password never is.** A scanner using
`admin/admin` and someone using your real service account are very different
problems, and the username is how you tell. The password is not logged, alerted,
stored, or counted beyond "a password was supplied" — and not even that when the
field was blank, since a blank one is a scanner working through a list. If it
happens to be a real password, writing it into an alert is the same mistake as
finding one in a packet and keeping it.

The fields of a canary's `logdata` are allowlisted, because OpenCanary's modules
each add their own keys and the next version will add more. A test stuffs every
plausible credential key into a record and checks none of it comes out, through
the parser, the finding, and redaction into an alert.

---

## Configuration drift

The packet rules watch what the network does. This watches what it is *allowed*
to do, which changes without any packet being unusual.

```
python -m netmon.drift --profile my-site.yaml --host https://unifi.example \
    --fingerprint AA:BB:... --state ~/.local/state/netmon/unifi.json --notify
```

A port profile switched to "allow all" exposes every VLAN on that port and
produces no odd traffic until something is plugged in. A new port forward opens
a path from the internet and looks like nothing until it is used. A firewall
rule disabled "temporarily" six months ago is now the configuration.

Two kinds of finding:

**Standing** — wrong now, reported until fixed. These need no baseline: a
profile allowing every VLAN is wrong on the first run too, and a check that only
fired the moment it changed would miss every site that was already
misconfigured. Push the first time, digest after — reported either way, because
a standing misconfiguration that stops being mentioned stops being fixed, but
pushing the same one nightly is how push gets muted.

**Drift** — what changed. Needs a baseline, so the first run records one and
says so; reporting the whole configuration as new would be true and useless.

When something is both newly wrong *and* a change, the change wins: "a port
forward appeared" is strictly more informative than "a port forward exists", and
reporting both would be two alerts for one event.

A three-run sequence settles: the first run pushes what it found, the second
pushes what changed, and the third pushes nothing while still listing every
standing problem in the digest.

The snapshot is the network's defences written down — every firewall rule, every
forward, every port's VLAN membership — so it is kept owner-only, and the
findings carry rule names and port numbers rather than the rules themselves.

---

## The rolling capture

A day or two of packets on disk, so that when a rule fires there is something to
look at.

```
python -m netmon.ringbuffer --profile my-site.yaml --dir /var/lib/netmon/capture --command
```

That prints the tcpdump invocation to put in a unit file — filter, snap length,
rotation and privilege drop included. netmon owns the policy; tcpdump owns the
plumbing. At 5,000 packets a second a Python capture loop is the wrong tool, and
writing one would mean reimplementing what libpcap already does well.

```
python -m netmon.ringbuffer --profile my-site.yaml --dir ... --status
python -m netmon.ringbuffer --profile my-site.yaml --dir ... --prune
```

Pass `--ring <dir>` to `netmon.analyze --notify` and each pushed alert gets the
packets around it written out and named, narrowed to the devices involved — a
hundred thousand packets become the few dozen someone will read. A failed
extract never stops the alert.

**Restricted segments are excluded by the filter, not omitted from it.** A
capture that happens not to select VLAN 40 is one edit away from selecting it.
The generated filter names every metadata-only segment in a `not` term, so it
wins even where the `capture:` section explicitly selects that VLAN — and the
tests demonstrate exactly that case. Extraction applies the same exclusion
again, because a file on disk was written under whatever profile was current
then.

**And by address.** The filter also carries `not net` for each restricted
subnet, written by byte offset for untagged, single-tagged and QinQ frames.
The access-control subnet's traffic also arrives untagged (when it is the
trunk's native VLAN), under another VLAN's tag (a routed copy, or a port in the
wrong VLAN) or inside a QinQ frame, and none of those carries the tag the VLAN
exclusion looks for. The VLAN exclusion itself checks both positions of a
stacked tag and all three tag types (0x8100, 0x88a8, 0x9100): a filter that only
knew 0x8100 read a QinQ frame as untagged and let it through.

**And it is checked.** Every rotated file the service analyses is read for
frames from a metadata-only segment — by any tag in the stack, or by address —
and any there are is `restricted_capture_leak`, critical and pushed: the filter
that wrote it is not the one `--command` prints, or this stack is not honouring
it, and the file holds what it must not. An extract for an alert that had to
leave such frames out raises the same finding. Separately, a restricted
address seen untagged, under another VLAN's tag or inside QinQ is
`restricted_outside_vlan` wherever it is seen; a listed router's relayed copy
is routing and is left out, and with no `router_macs` only frames carrying the
restricted device's own MAC are judged.

`analyze --pcap` treats a file as an unfiltered sample — which is what a sample
taken for `bpf --verify` is meant to be — so its restricted frames are read as
metadata only and counted in a line of output, not reported as a leak. Pass
`--from-ring` when the file came from the rolling capture to have it judged as
the service judges one.

Pruning never removes the newest file. It is the one being written, and deleting
it leaves the capture writing to a deleted inode with no error anywhere. Age
comes from the filename rather than the mtime, because a file still being
written has an mtime of now and a name from an hour ago — pruning by mtime would
keep exactly the wrong ones.

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

**The budget is enforced.** The day's spend is kept under `--state`
(`summariser-spend.json`; `analyze` takes `--state` too, and falls back to the
home directory for an interactive run). It used to live in `~/.cache`, which a
systemd unit with `ProtectHome` cannot write, so every recording failed and the
budget was silently zero; a location that cannot record spend now refuses the
request instead. The check, the request and the recording happen under a lock,
and a second request while one runs is refused. Output is capped at what the day
has left, so a request overshoots by its input and a small floor at most, and
there is an hourly cap (`summariser_hourly_sends` / `NETMON_SUMMARISER_HOURLY_SENDS`,
default 6) and a timeout (`summariser_timeout`, default 120 seconds per attempt).

### The button

```
python -m netmon serve ... --allow-summarise
python -m netmon.web --profile my-site.yaml --unifi flows.csv \
    --state /var/lib/netmon/state --secrets /etc/netmon/secrets.json --allow-summarise
```

Off unless `--allow-summarise`. The *Model triage* tab's first button sends
nothing: it shows the exact message that would leave the sensor — redacted,
nothing from a metadata-only segment, and the count of what was withheld —
with an estimate of its size made locally (the API's token counter would mean
sending it to count it) and where the day's budget stands. Only the second
button sends that message, unchanged and once; a preview expires after ten
minutes. Both are POSTs with the page's token and the Host and Origin checks of
every other write, and the button's request has a 90-second timeout with no
retries. What comes back is put on the page as text.

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
python -m netmon.bpf --diagnose-untagged sample.pcap
```

Take the sample with no filter at all, on that machine, and it will tell you
what your candidate actually keeps, per VLAN. With `--profile`, it also counts
what the filter kept from the metadata-only segments, by tag and by address,
and **exits 3 if anything got through** — so it can gate a deployment script.
`--diagnose-untagged` runs both ways of selecting untagged frames over the same
sample and says which this stack honours; it exits 4 when the mixed
tagged-and-untagged filters cannot be trusted here, in which case capture the
two separately.

One more trap, found by checking the builder against libpcap's own compiler:
the `vlan` keyword shifts offsets for everything after it, `and` as much as
`or`, so two both-forms terms in a row (drop a host, then a port) left the
second one's untagged branch reading the wrong bytes. The builder now folds
every term that needs the keyword into one block, last.

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

## Telling it "I know"

```
python -m netmon ack         --rule bacnet_control --device ahu-controller-1 --key ...
python -m netmon snooze      --device ahu-controller-1 --hours 4 --reason commissioning
python -m netmon maintenance --device chiller-controller --reason "vendor on site"
python -m netmon silence list
```

**ack** covers one finding. It stops that finding pushing for 30 days, and the
finding stays in the digest. **maintenance** stops everything about a device or
rule pushing, but it all still goes in the digest, so the work leaves a record.
**snooze** hides a device or rule completely, so it must end, and it is capped
at 30 days. Anything longer belongs in the profile with a note saying why.

Nothing can silence everything, and a silence file that cannot be read applies
no silences. Both choices err towards noise. A running service picks up a
change on its next pass, and silences apply to findings already kept as well as
new ones: a snooze added this afternoon hides this morning's finding from the
UI and the digest.

In the UI, each finding has **Acknowledge**, **Snooze** and **Maintenance**
buttons (or **Clear**, when one already covers it), with a reason box and a
snooze length, and the silences in effect are listed. They need `--allow-edit`
and somewhere to keep the silences: `serve --allow-edit` for the service's own
UI, or `netmon web --state <the service's --state> --allow-edit` for a
standalone one. Without `--allow-edit` the silences are shown and cannot be
changed.

---

## Running it on a sensor

```
python -m netmon serve --profile /etc/netmon/site.yaml \
    --ring /var/lib/netmon/capture --state /var/lib/netmon/state \
    --canary-log /var/log/opencanary.log --secrets /etc/netmon/secrets.json \
    --unifi-host https://unifi.example --fingerprint AA:BB:...
```

One process doing the recurring work: analyse each capture as it rotates, check
the controller configuration every few hours, follow the canary log, prune the
ring buffer, push what needs attention, send a daily digest, serve the UI.

`--once` does a single pass and exits, for a cron entry. `--allow-edit` lets its
UI write (the editors and the silence buttons); `--allow-summarise` adds the
model-triage button. Both are off by default.

Under `--state` it keeps: `processed.json` (which captures are done),
`findings.json` (the day's findings and the open pushes), `silences.json`,
`summariser-spend.json`, the canary read position and the controller snapshot.

**It does not capture packets.** tcpdump does, under its own unit, with the
filter `netmon capture --command` prints. Keeping them separate means a crash
here loses analysis — which can be redone — and not the capture, which cannot.
`deploy/` has both units and the checks worth doing before trusting them.

Each job is independent. One failing — the controller unreachable, the canary
log rotated out from under it — is logged, rescheduled, and does not stop the
others; the alternative is a sensor that goes quiet for a reason nobody
notices.

Progress is kept on disk, so a restart does not re-analyse yesterday or
re-alert on what was already sent. A service nobody dares restart is a service
nobody updates.

---

## Status

Everything the spec listed is built: the profile, 26 rules, UniFi flow import,
capture reading with BACnet / TLS / DNS / DHCP / ARP / site-protocol parsing,
the rolling capture and its leak check, configuration drift, canary hits, ntfy
and email alerting with an open-items digest, GeoIP, model triage from the
command line and the UI, the web UI with its silence buttons, the
capture-filter builder, and the service that runs them.

Not yet checked on the real site: the owner's captures, `netmon sync` for the
real profile, `netmon bpf --verify` on the sensor, and whether a UniFi export
records a port-forwarded flow under the WAN or the internal address.

Test it with `python -m unittest discover -s netmon_tests -t .` from the
repository root.

---

## Naming the systems

A finding that says "TCP 7000" is one nobody acts on. One that says "Otis
elevator control" goes to the lift contractor.

netmon recognises BACnet, Siemens P2, Gallagher, Otis, Exacq, parking kiosks,
UniFi Protect and discovery, WeatherFlow, Sentinel licensing, Tailscale,
WireGuard, OpenVPN, the common remote-access tools, and the cleartext protocols
worth naming. Add your own under `services:` in the profile — they are checked
first, because your building beats the default.

Identification goes by magic number, then hostname, then port, in that order of
how much the answer is worth. Unrecognised traffic is left unnamed rather than
guessed at: an invented label is worse than none.

Three protocols are read a little further. Siemens P2 yields the roster — which
panels are announcing themselves, which is the whole point on a protocol with no
authentication. Otis yields the frame type and nothing else, because the
protocol has no public specification and guessing at fields would produce
findings nobody could verify. ESET update traffic yields the Windows build,
which is the only place on the wire it appears.

**Parking kiosks are metadata only, structurally.** Those broadcasts carry
cardholder and credential data. The parser matches two named elements by regular
expression and never walks the document, so there is no path by which another
field could be read — it is not a filter applied afterwards. Its test fixture is
synthetic and stuffed with obviously-fake card numbers, PINs and tokens, and the
tests check none of it comes out, through the parser and again through the whole
capture-to-alert path.

---

## Where an address is

```
pip install maxminddb
python -m netmon geoip --update --dir /var/lib/netmon/geoip
python -m netmon geoip --dir /var/lib/netmon/geoip              # what is installed
python -m netmon geoip --dir /var/lib/netmon/geoip --lookup 203.0.113.9
```

then, in the profile:

```yaml
geoip:
  directory: /var/lib/netmon/geoip
```

Country and network (ASN) for internet addresses, from **DB-IP Lite** — IP
Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0 — read offline with
`maxminddb`. Lookups never leave the sensor. `--update` is the only network call:
it downloads the two files from DB-IP, sends nothing about this network, and is
run by a person (or a monthly timer they set up), never by the service. Each
file is downloaded beside the installed one, checked, and renamed into place,
so a running service sees the old file or the new one and picks the new one up
within five minutes; a failed or bogus download leaves the old one alone.

Enrichment adds `dst_country`, `dst_asn` and `dst_as_org` (and `src_*` for
inbound). A UniFi export's own `Src./Dst. Region` columns are kept as
`src_region` / `dst_region`, and a two-letter one stands in for the country
when there are no files. New-destination findings say where the destination
is, and a role's `allowed_asns` is enforced: the `egress_unexpected_network`
rule reports a device reaching a network its role does not list. Without the
files, or without a list, it stays silent.

---

## Inbound around Cloudflare

For a site that publishes services through Cloudflare, an origin should hear
on 443 only from Cloudflare's ranges. List the origins in the profile:

```yaml
cloudflare:
  origins: [bas-server]          # names, addresses, CIDRs or roles
  # ranges: [...]                # replaces the shipped list for this site
```

and `inbound_https_bypass` reports a day on which an origin received well above
its usual level from anywhere else (1 MB floor, four times its median day).
Scanners reach every address on 443, so some of that is normal; a day of only
Cloudflare traffic counts as a zero, so an origin that usually hears from
nobody else still has a baseline. Cloudflare's ranges ship dated in
`rules/cloudflare-ranges.txt` and are never fetched. Inert until `origins` is
set.

**Port forwards in a UniFi export — unverified.** In a capture from the inside,
a port-forwarded connection carries the internal destination (the translation
has happened). Whether a UniFi flow export records such a flow under the WAN
address or the internal one has not been checked. If it is the WAN address,
the flow reads as transit (both ends public), resolves to no device, and this
rule does not see it in an export; check one known forwarded connection in an
export before relying on it there.

---

## Two things about reading a trunk mirror

**Every routed packet appears twice** — once arriving from the sender on the
source VLAN, once leaving the router on the destination VLAN. In a measured
seven-second sample, 3,178 packets appeared on both sides. Counting both doubles
every byte total and attributes half the traffic to the router. List your
routers under `router_macs` and the relayed copy is dropped.

Except a frame from the internet. It crosses the mirror once, on its way in,
with the router's MAC and the remote address — the shape of a relayed copy, but
with no first copy unless the WAN port is mirrored too. Those are kept; until
they were, every inbound internet frame was dropped, downloads were missing
from the byte counts, and nothing could see a connection arrive from outside.

**The capture interface should be silent.** No address, no protocol bindings.
One left configured puts DHCP, NBNS, LLMNR, mDNS, SSDP and EAPOL onto the
mirrored VLAN, contaminating every baseline built from it. List its MAC under
`sensor_macs` and the `sensor_chatter` rule will say so if it ever transmits.
