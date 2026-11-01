# NetSentinel Changelog

## Unreleased — A third day of real alerts

**2144 unit tests** plus 14 integration checks. A day of 1.9.1 raised 36 alerts,
none CRITICAL. Three new devices on the network were real; the nine HIGH alerts
were not, and neither was most of the rest. Each fix has a test that fails on
1.9.1.

### The HIGH ones
- **Fast-flux follows CNAMEs.** api.weather.gov and Xbox's catalogue point at
  Akamai through CNAMEs (edgekey.net, akamaiedge.net, edgesuite.net), and
  Akamai publishes no address list, so its addresses in 23.x looked like many
  unrelated networks: HIGH six times in a day. A name whose answer goes through
  a known CDN's domain is the CDN's; the resolver follows the CNAME to the
  CDN's own servers, so the name cannot be borrowed.
- **A port scan is many ports, service ports among them, on one host.** The
  two were checked across hosts: Tailscale reaching three peers behind one NAT,
  each on its own high port, plus DNS to the router and HTTPS elsewhere, was a
  scan of the NAT.
- **Name poisoning counts only answers to lookups.** Responder answers what
  others ask for. Home Assistant announcing its own names unasked (its
  hostname, instance ID, Matter name, an add-on) was a HIGH. Names a host's own
  service and reverse-lookup records point to are its own too. Lookups are told
  from this PC's ordinary DNS, which can leave from port 5353 or 5355.

### The rest
- **A port names a service only on its transport:** Tailscale's encrypted
  WireGuard to a peer's NAT port 8081 was "Unencrypted HTTP-Alt".
- **ESET's LiveGrid** (eset.systems) is known like eset.com: its lookups carry
  no User-Agent and a body ESET encrypts itself.
- **OCSP checks sent by GET** are recognised from the request (a DER request in
  the path), whoever answers them: status.thawte.com, oneocsp.microsoft.com.
  So are Windows Update downloads from a cache server addressed by IP.
- **One insecure-service alert per service name a day**, not one per address:
  Steam's client config and ESET were five each, one per CDN address.
- **A server's version banner is LOW** (an end-of-life version stays HIGH), and
  so is a request without a User-Agent: what a device runs, not an exposure.
- **DNS volume is judged on the lookups.** Run on the QUIC handshakes that
  followed a page load, it skipped the exemption for this PC's own resolver
  and raised two alerts a second apart, naming Google's servers.

## v1.9.1 — A day of real alerts, and what they were

**2124 unit tests** plus 14 integration checks. A day of 1.9.0 on a real
network raised 263 alerts; none was an attack, and every rule behind them is
fixed here, each with a test that fails on 1.9.0.

### ARP: a remembered address is not spoofing

Two smart-home devices that each remembered 192.168.1.80 from the network they
were set up on announced it once whenever they rejoined Wi-Fi, hours apart, and
NetSentinel called it a CRITICAL "ARP Spoofing": the address had gone back to a
MAC that held it before, and that counted however long ago it was.
- An address now changes hands only when the new MAC claims it twice within two
  minutes; a spoofer repeats itself every few seconds to keep caches poisoned.
- It is spoofing only while the previous owner is still using the address
  (heard in the last ten minutes).
- A device that is not the gateway is no longer met with "verify your gateway".
- The traffic saved with an ARP alert now holds the ARP that raised it.
- This computer's MAC, pinned as a "gateway" before 1.9.0 read the route table
  properly, is dropped from the saved pins.

### The rest of the day's alerts

All false, and all from rules that misread ordinary traffic:
- **Services are named by the server's port.** The capture now records which
  end of each TCP connection is the server, from the handshake. For one
  already open, this computer is the server only if it listens on the port.
  - Windows here is set to give outgoing connections local ports from 1024 up,
    so replies came back to ports like 5900 and 9050. Google "ran a VNC server"
    on this PC (CRITICAL), and a Raspberry Pi "connected to Tor" on it.
  - The same went for MSSQL, an admin page, a printer, a malware port, and
    "Redis" from an HTTP request sent from local port 6379.
- **Redis** needs a Redis command: `a and b or c` let any "GET" count.
- **Modbus** needs a real MBAP header. A few bytes on port 502, from a printer
  and a router answering the audit's probe, were CRITICAL "unauthenticated
  Modbus".
- **BACnet** is UDP: a web client whose port happened to be 47808 made a local
  web server "BACnet".
- **Fast-flux** needs addresses spread over at least four unrelated networks,
  and goes by the largest TTL seen. A caching router hands out what is left of
  a TTL, down to 1 second. api.weather.gov and Xbox's catalogue, both on Akamai
  (8 addresses in two networks), were HIGH every five minutes all night. A name
  is reported at most once an hour.
- **Port scans** raise one alert per scanner, about its main target. A
  7-second audit raised 87, naming internet servers as "targets".
- **SYN flood** needs 300 SYNs in ten seconds, not 50. A program retrying a
  Raspberry Pi's service five times a second was CRITICAL.
- **ESET's hourly update login** (HTTP Digest, hashed) is noted once a day as
  "likely safe". The verifier had confirmed every captured credential, which
  raised it from LOW to HIGH.
- **Certificate checks** over plain HTTP are not insecure services, like
  updates: revocation lists, OCSP and issuer certificates are signed by design.

## v1.9.0 — Watching this PC's own traffic, review mode, and an audit of your network

**2100 unit tests** (up from 1456) plus 14 integration checks. The suite no
longer downloads threat feeds, so it runs in about a minute.

### This PC's own traffic is inspected

The gateway, the DNS servers (8.8.8.8 and 1.1.1.1 included) and this computer's
own addresses used to skip almost every rule. On a PC that mostly sees its own
traffic, that was nearly all of it: port scans, DNS tunnels, uploads and gateway
ARP spoofing on the machine NetSentinel protects were never looked at. Now only
multicast, broadcast, link-local and discovery chatter, and devices you list as
known, are skipped; the few rules that misfire on infrastructure exempt it
themselves. **Expect more alerts.** Review mode is the way to sort them.

Also in live detection:
- Browsers have SNI and JA3/JA4 again. Post-quantum ClientHellos span two TCP
  segments and are now joined; QUIC Initial packets are decrypted for their server
  name; ports 8443 and 5061 are parsed.
- Capture files go through the live parser, on packet time: files get SNI, DNS
  answers and IPv6 ports, and replaying a capture no longer looks like a flood.
- Malware URLs are matched exactly on plain HTTP, live and in files.
- New detections: ARP spoofing with the gateway's MAC pinned across restarts;
  rogue DHCP, IPv6 router advertisements and DHCPv6; LLMNR, NBT-NS and mDNS
  poisoning (the Responder pattern); lateral movement over SMB, RDP, WinRM and RPC;
  uploads far above a host's own baseline; new devices, with their vendor; DNS
  tunnelling by length, volume and TXT rate; cryptocurrency mining pools;
  self-signed and expired server certificates; newly registered domains (WhoisDS's
  free daily list, checked locally).
- GeoIP, off until you turn it on: country and network operator of destinations
  from DB-IP Lite, downloaded monthly and looked up on this machine. IP Geolocation
  by DB-IP, CC BY 4.0.
- Fewer feed false alarms, the github.com pattern again: one alert per connection,
  not one per direction; lists of attacking hosts no longer condemn cloud and CDN
  addresses you connect to (shipped, dated ranges); delisted entries expire and a
  week-old cache is not trusted; DShield's /24 blocks match; file hosts and URL
  shorteners are never malicious domains; dynamic DNS matches on label boundaries
  (`myfooddns.net` is not a ddns.net host); fast-flux leaves CDNs alone.
- Quieter: curl and okhttp are no longer CRITICAL; IOC-DGA, IOC-DOH-BYPASS and
  IOC-TOR stop repeating, and port 9001 alone is not Tor; IOC and ML alerts get the
  same cooldown as the IDS's.
- Bounded: forensics findings, the device table (now keyed by MAC) and capture
  buffers. A stop on a quiet interface really stops, and a restart no longer leaves
  the last run's capture threads going.
- URLhaus's keyless export is gone (HTTP 410). It now needs a free abuse.ch
  Auth-Key (`threat_intel.abuse_ch_auth_key`); abuse.ch's terms allow free
  not-for-profit use. A feed that answers 410 or 404 is not retried for a week.

### Review mode: give Claude your alerts and the traffic behind them

`--review DIR`, or Settings → Review mode, keeps what it takes to judge alerts:
a capture of the traffic around every alert whatever its severity (cut before
verification can lower it), a rolling full capture within a disk budget, and
alerts.jsonl, written once each alert's verdict is final.

Build Review Bundle (desktop Review menu, the dashboard's Alerts page, or
`python -m src.review build`) writes a folder and a zip under 20 MB and 30 files:
a README telling the reviewer how to answer, a summary that points at rules firing
over and over on one host, the redacted alerts, and a text digest per group, one
line per packet with DNS names, TLS server names and HTTP host and path. Query
strings, cookies, credentials, tokens and user names in paths are never written;
LAN addresses can be replaced by labels; every file is audited for secret shapes
before it is written.

Verdicts come back the other way: Real or False positive on any alert in the
dashboard, or import the JSON the README asks for (Review → Import verdicts). A
false positive is never raised again for that rule and that host or domain.

### An audit of your own network, when you ask

Settings → Network audit, then the Audit page: finds the devices on networks this
computer is on (ARP, or TCP without Npcap), scans 83 common ports at a limited
rate, and flags risky services (Telnet, FTP, SMB on workstations, RDP, VNC, UPnP,
WinRM, exposed databases, controller protocols, admin pages without TLS), each
with why it matters and how to fix it. It reads every TLS certificate, including
the TLS 1.3 ones the passive monitor cannot see, and compares each audit with the
last so new devices and newly opened ports stand out. Gentle mode (16 ports, 5 a
second) is for building and industrial controllers. It never tries a password,
never runs on its own, and only scans private networks of a /16 or smaller that
sit on one of this computer's interfaces. CLI: `python -m src.audit --network
192.168.1.0/24`. Its own probes are labelled as such in the alerts they cause.

### File scans

- Secrets no longer leak through URLs in the report: query values, tokens before
  the @, token-shaped path segments, webhook paths and Azure SAS signatures are
  masked, and URLs end at a comma, so a browser password export cannot spill a
  password into the URL list. Browser and password-manager CSV exports are
  recognised and every saved password is reported masked.
- Weak feed guesses (dynamic DNS, a high-abuse TLD) are "suspicious" at LOW, not
  known-bad at HIGH: `window.top` no longer raises a HIGH alert. Internal names are
  never sent to threat feeds; UNC paths and internal host names are listed.
- New secrets: Azure storage keys and SAS tokens, GCP service-account keys, Twilio,
  SendGrid, Mailgun, npm and .npmrc, PyPI, GitLab, Discord and Slack webhooks,
  Telegram bot tokens, Docker registry auths, bearer tokens, and `DB_PASSWORD=`
  style settings and .env files. Windows leaks: unattend.xml passwords, Group Policy
  cpassword (decrypted and masked at once), Wi-Fi keys, KeePass databases, PuTTY
  keys. High-entropy values in settings.
- Scripts: encoded PowerShell is decoded and scanned; download cradles and
  certutil, mshta, regsvr32, rundll32 and bitsadmin abuse are flagged, and Defender
  tampering. Office macros, .evtx event logs, and your own YARA rules if
  yara-python is installed.
- Archives by content: tar, gzip, bzip2, xz, 7z and zip-shaped files (.jar, .apk),
  nested three deep, with a decompression budget and a zip-bomb check. RAR is
  reported as not opened. Every file gets a SHA-256, checked against known-bad hash
  lists you put in `~/.netsentinel/data/hash_lists` (MalwareBazaar now requires a
  key even for its exports).
- An ignore list for false positives, per value (by keyed hash) or, for cards and
  SSNs, per file and line. One alert per kind of secret per file. Folder scans run
  at background priority and give way between files.

### Runs in the tray, and restarts itself

Closing the window used to stop monitoring and exit. Now it hides NetSentinel
to the system tray and monitoring carries on; the tray icon opens the window or
the dashboard, starts or stops monitoring, restarts, and quits (Settings →
Performance turns this off). **Restart** (in the window, the tray menu, and
offered after saving settings) starts a fresh copy with the same arguments and
resumes monitoring if it was running, so settings that apply at start take
effect without hunting for the process. `--monitor` starts monitoring as soon as
the window opens. A dashboard tab left open across a restart picks up the new
copy's token by itself, rather than answering every button with "missing or
wrong token" until it is reloaded. The tray uses pystray (LGPL-3.0) and Pillow.

The mouse wheel scrolls whatever is under the pointer. Three pages bound it for
the whole window, so one turn scrolled all three, on whatever tab each was on,
while the Incidents, ML, Settings and Forensics lists did not scroll at all.

### What the first review of real alerts found

The first exe with review mode raised eight alerts in ten minutes, every one a
false positive. Fixed:
- **This computer was taken for a gateway.** The default-route parser read every
  address on the line, the interface's included.
- **A web server's version banner was "Sensitive Data in Transit".** Plain-HTTP
  fetches from ESET, Windows Update, Let's Encrypt and Steam each raised a
  "[LIKELY THREAT]". Banners are now reported only for servers on your network.
- **Signed software updates were insecure services.** Windows Update, Edge's
  updater and others download over plain HTTP by design. A server stops counting
  as an updater the moment anything else is fetched from it.
- **A WebRTC call was name poisoning.** Browsers answer mDNS for random UUID
  names standing for their own addresses; those no longer count.
- **The verifier called every sensitive-data finding "LIKELY THREAT 70%".** It
  now goes by the kind of finding: card data, keys and control writes are
  confirmed; cookies and attack patterns are likely threats; banners, devices
  and uncommon HTTP clients (a headless browser run by a test, here) are left
  for you to judge.
- **Review bundles built from the command line could not read the traffic.**
  Every packet was "Raw". And when an alert involved this computer, the saved
  traffic was all of its traffic, and the alert's own connection fell past the
  digest's 400-line cut. Each digest now opens with the alert's own connection.

### The dashboard can do things, on this computer only

Start and stop monitoring, acknowledge alerts, record verdicts, build review
bundles, run audits and manage the scan ignore list from the browser. These need
the token the dashboard page carries and are refused unless the server is bound
to localhost; configuration still cannot be changed over HTTP. The dashboard also
shows what NetSentinel costs (CPU, memory, threads, dropped and sampled-out
packets), and `performance.low_priority` runs it below normal priority.

### netmon

- The web UI refuses foreign Host headers while bound to localhost, closing a DNS
  rebinding path to its page token. Acknowledge, snooze and maintenance buttons
  (`serve --allow-edit`, `web --state ... --allow-edit`).
- A model-triage button behind `--allow-summarise`: it shows the exact redacted
  payload and an estimate first, and only a second click sends it. The daily
  budget is enforced and kept under `--state`, with an hourly cap and a timeout.
  Canary and configuration findings from metadata-only segments never reach the
  model.
- The daily digest opens with an open-items checklist and marks acknowledged and
  maintenance findings; findings are kept across restarts and pushed once, not on
  every capture rotation; optional email digest over STARTTLS or SMTPS.
- GeoIP from DB-IP Lite (`netmon geoip --update`); role `allowed_asns` enforced.
- Inbound internet traffic is no longer dropped by router deduplication; new
  `inbound_https_bypass` rule for origins published through Cloudflare.
- Packet-side VLAN leak check: restricted frames on disk and restricted traffic
  outside its VLAN are reported; the capture filter also excludes restricted
  subnets and QinQ; `netmon bpf --verify` exits 3 on a leak. A capture filter with
  both host and port exclusions let untagged frames through; fixed.

### Fixes

- Starting twice ran everything twice; a quick stop and start left the last run's
  loops going; a failed capture left the window saying MONITORING; the feature
  store stopped for good after a stop; alerts reached disk only on a clean stop.
- Alert captures matched only untagged Ethernet, so on a network that delivers
  VLAN-tagged frames an alert got a capture of everyone's traffic.
- The baseline whitelist learned by the last two labels, so one github.io or
  .co.za site whitelisted all of them; it learns registrable domains now.
- config.json saved by Notepad (UTF-8 with a BOM, or a non-ASCII name) failed to
  load and every setting fell back to defaults.
- The Settings threshold row edited a key the engine ignores; reloaded incidents
  said "0 alerts"; one incident kept every alert it absorbed.
- The elevated relaunch on Windows started in System32, so relative paths in
  arguments broke.
- CI's GitHub actions run on Node 24.

## v1.8.0 — A browser dashboard, scan any file for leaks, and a Windows download

**1456 unit tests** (up from 384) plus 14 integration checks.

### A dashboard in the browser

NetSentinel now serves a dashboard at `http://127.0.0.1:8737/` whenever it runs,
and the desktop app's new **Open in Browser** button opens it. Overview (live
traffic and bandwidth charts, protocols, top talkers, threat level, recent
alerts), Alerts (severity filters, search, evidence on click), Devices, Incidents,
and Scan Files. `--headless` serves the same dashboard with no window, so the
program can run as a server and be watched from a browser. Plain HTML, CSS and
JavaScript served by the standard library: no framework, nothing fetched from the
internet, and a Content-Security-Policy that allows only its own scripts.
Everything that came off the network or out of a scanned file is shown as text.

The server still binds to localhost and still cannot change configuration or
monitoring. New: while on localhost it refuses any Host header but a loopback
name, which closes DNS rebinding, and the one thing a POST can do, upload files
to scan, needs a token only the dashboard page carries, so no other web page can
drive it. The plain-text summary moved from `/` to `/status.txt`.

### Scan any files for leaks

**Scan Files** in the dashboard (drag and drop files or whole folders) and **Scan
Files / Zips** and **Scan Folder** in the desktop app's File Analyzer tab (was
PCAP Analyzer) take anything: logs, configs, Word and Excel files, PDFs, exports,
zips, and packet captures. One report lists every IP address (public or
private), domain, URL, email and MAC address found and which files held it, any
the threat feeds know as bad, and every private key, cloud or API token,
password in a setting or URL, card number (Luhn-checked) or US SSN that looks
leaked, masked, with file and line. Captures still get the full PCAP analysis,
and their talkers and DNS names join the lists. Download the lists as CSV or the
whole report as JSON. Headless: `python -m src.batch_scan PATH... [--skip GLOB]
[--json]`; `--skip 'flash*'` keeps files you should not be opening out of it.

Secrets are masked where they are found and the raw value never enters the
report. An indicator that overlaps a secret is dropped, so `user:pass@host`
never surfaces the password as an email. Zip members are never extracted under
their own names, but streamed into numbered files in a private temporary
folder, capped at 2 GB each, scanned and deleted one at a time; uploaded names
are reduced to safe path components. Nested archives and password-protected
members are reported, not opened, and folders are walked without following
symlinks.

### A Windows build on every release

Pushing a `v*` tag now builds `NetSentinel.exe` on a Windows runner and attaches it,
with a SHA-256 checksum, to that tag's GitHub release. Install Npcap first. A
manual run of the `release` workflow builds the exe without releasing it.
`build_exe.bat` no longer waits for a key press under CI, and quotes the PyInstaller
version so cmd does not read `>=` as a redirect.

### netmon, a site monitor

`netmon/` is a new, separate tool for watching one site's network from a Linux
sensor: a YAML site profile, a VLAN-aware capture filter, a rule engine with 24
rules, UniFi flow and API import, BACnet and site-protocol parsing, configuration
drift, canary hits, ntfy alerting behind a redaction gate, optional model triage,
a rolling capture, a web UI, and acknowledge, snooze and maintenance mode. See
`netmon/README.md`. It ships with a fictional example profile only.

### Fixes

- github.com was "known-bad". URLhaus lists malware *links*, many hosted on GitHub,
  Google Drive, Dropbox and the like, and every link's host became a malicious
  domain, so ordinary traffic to those platforms alerted in live monitoring as
  well as in scans. Shared hosting platforms are no longer listed by host; the
  exact bad URLs still match.
- The desktop app's header said v1.0 whatever the version; it now reads it.
- A UniFi timestamp with one or two fractional digits (`13:05:01.5Z`) did not parse
  on Python 3.10, and the row fell back to the local-time column, four hours out.
- CI never installed PyYAML, so netmon's tests could not run there.
- On Windows the dashboard could lose its own error messages. A refused upload
  was answered before its body was read, and Windows resets a connection closed
  with data unread, which threw the answer away: the browser showed a network
  error instead of "another scan is running". A refusal is now read to the end,
  for up to 2 seconds, before the connection closes. netmon's canary listener had
  the same flaw and kept the connection open, so a refused body was then read as
  a second request.
- The log file was written in the Windows code page, and a line holding a
  character outside it (an international domain name, a file name) was dropped.
  It is UTF-8 now, and so is the File Analyzer's CSV export, which failed
  outright on such a name.
- netmon's canary-log tailer counted the bytes of decoded text: one short a line
  for a log with Windows line endings, and over for every byte that is not UTF-8,
  so it reported empty lines or skipped real ones. It counts the file's bytes.
- The dashboard's port is 8737, not 8787, which localcast and RStudio Server use.
- The tests now also run on Windows in CI. They only ran on Linux before, which is
  how the above got through.

## v1.7.0 — Detection that survives evasion, and a sensor you can deploy

Three items the v1.6.0 review named as next. One of them, run for real, found
that packet capture had been broken on main for several releases.

**384 unit tests** (up from 280) plus 14 integration checks. Coverage 45% → 48%.

### Beaconing that jitter does not defeat

The old rule flagged a destination when `std(intervals)/mean(intervals)` fell
below 0.05. Measured against synthetic beacons that catches a beacon with no
jitter and almost nothing else — 5% at Cobalt Strike's default, 0% at Sliver's.
Every mainstream C2 framework enables jitter, so it only ever caught naive
scripts.

`src/beaconing.py` scores three properties that survive jitter: Bowley skewness
of the intervals (jitter is symmetric, human traffic is right-skewed), median
absolute deviation scaled so random arrivals score zero, and payload-size
consistency — weighted highest, because it is what separates a C2 check-in from
an app that legitimately polls. 0%, 10%, 20%, 35% and 50% jitter now all score
0.78-0.98 against a 0.75 threshold; Poisson arrivals, browsing and streaming
score 0.

It deliberately does not decide whether a beacon is malicious. NTP scores 0.90
and should — it is a beacon. Separating the two needs context the scorer does
not have, so eligibility is handled by the caller: globally routable
destination, not a known polling service, not already beaconing during baseline
learning. A test asserts NTP still scores high, so nobody later "fixes" the
scorer to hide it.

### DNS response analysis

Only queries were inspected, and capture was discarding nearly everything a
response carries: one rdata string, no rcode, no TTL, and no question name —
so an answer could not even be tied to what was asked. Two bugs surfaced while
fixing that: answers were walked through `record.payload`, but Scapy 2.7 exposes
the section as a list subclass, so only the first answer was ever read; and the
monitor seeded its prune timer from the wall clock while observations carry
caller-supplied timestamps, so a PCAP replay would never have pruned.

`src/dns_analysis.py` reports NXDOMAIN bursts (DGA) and fast-flux hosting. The
benign cases drove the thresholds more than the malicious ones: Chrome issues
three random lookups at startup to detect ISP hijacking, Windows multiplies one
failure by its search suffixes, and CDNs answer with 60-second TTLs by design.
So a burst needs 15 failures across 5+ distinct registrable domains in 60
seconds, and a short TTL is only ever combined with address churn on the same
name. The DGA name heuristic flags 0/20 realistic names and catches ~65% of
generated ones.

### Headless mode

`python main.py --headless` runs the engine with no GUI and serves a read-only
HTTP API — status, alerts, incidents, devices, and Prometheus metrics. It binds
to localhost by default because the output contains captured credentials.

### The regression that found

Launching headless for real failed immediately:

    Capture error: L2Socket.__init__() got an unexpected keyword argument 'snaplen'

Wiring up `capture.snap_length` in v1.5.0 passed `snaplen=` to `sniff()`, which
forwards unrecognised kwargs straight to the socket constructor. No Linux listen
socket accepts it. **Packet capture had been dead on every start since that
commit**, with the watchdog retrying ten times.

No test caught it because none of them call `sniff()` — that needs a live
interface. Twelve seconds of a real run found it. Options are now filtered
against the socket's actual signature, and a `TypeError` sets a fatal flag so
the watchdog stops retrying something restarting cannot fix.

---

## v1.6.0 — Seeing encrypted traffic

v1.5.0 fixed what was broken. This adds what the review identified as missing: the
ability to say anything useful about the ~85% of traffic that is encrypted.

**280 unit tests** (up from 190) plus 14 integration checks. Coverage 43% → 45%.

### TLS ClientHello inspection

The ClientHello is plaintext even under TLS 1.3, so a monitor that reads it gets
two things the encrypted payload will never give up:

- **SNI** — the destination hostname, as a direct IP → name mapping that does not
  depend on observing a DNS lookup. It survives DNS-over-HTTPS, which otherwise
  silently disables five of the fifteen detection rules.
- **JA3 / JA4 fingerprints** — hashes over the offered ciphers, extensions and
  curves. These identify the client *stack* rather than the site, so malware using
  its own TLS library is distinguishable even when everything it sends is opaque.

JA3 is retained because public threat intel is still keyed on it, but it hashes
unsorted lists and Chrome deliberately shuffles extension order, so it changes per
connection. JA4 sorts first and stays stable; a test pins exactly that difference.

Parsing goes through a bounds-checked reader that raises rather than slicing short,
strips GREASE values, and rejects an SNI that is not plausibly a hostname so a
crafted one cannot carry control characters into alerts. Truncation at every offset
of a real ClientHello and 600 random payloads are covered.

Wired through: threat-intel domain matching, the DNS heuristics and the domain
blacklist now run on SNI, so they can fire on HTTPS at all for the first time.
A new `TLS-FINGERPRINT` rule matches `ids.blocked_ja3` / `ids.blocked_ja4`.
DeviceLearner and the baseline whitelist learn SNI names. QUIC on UDP/443 is
recognised instead of being classified as generic UDP with no flags.

**The default BPF filter had to be fixed first.** It matched "ACK set, SYN clear",
which also catches PSH+ACK data segments — so it discarded the very packet this
feature reads. The replacement drops only pure ACKs. Verified with tcpdump against
synthetic packets.

Measured on a synthetic session of 40 TLS connections, 12 DNS lookups and 20 QUIC
flows: connections carrying a destination name went from **12/72 (17%) to 52/72
(72%)**. The prefilter costs 90 ns on non-handshake packets; the full parse costs
18.5 µs and runs only on the first packet of a connection.

### PCAP-on-alert

A CRITICAL alert used to leave you with a rule name and an IP. The ring buffer
already holds the traffic, so it is now written out when a serious alert fires and
the path attached to the alert evidence — narrowed to the hosts involved, because a
scan or flood is unreadable with the rest of the network mixed in. Gated on
severity, rate-limited per rule+source, pruned on disk, and the filename is
sanitised because `rule_id` reaches it.

### Presentation logic extracted from the GUI

`gui.py` was the one module no test could reach: 1,772 statements at 0%, because
formatting, thresholds and filtering were interleaved with widget calls. Those are
pure functions, and they now live in `src/presentation.py`, which imports no
toolkit. 42 tests cover them.

Two behaviours the extraction fixed on the way: protocol bar fractions are computed
against the full total rather than the truncated top-N, so a chart of the top 8 no
longer overstates each slice; and equal counts now sort deterministically.

### Capture thread no longer re-serialises packets

`info.length = len(packet)` and `bytes(packet)` for the ring buffer both run
Scapy's `build()`, re-serialising every layer. A packet dissected from the wire
already carries its bytes in `.original`. Measured on fresh packet objects:
`len(packet)` 11.6 µs against `len(packet.original)` 0.2 µs, paid twice per packet,
on the thread that must not stall.

Worth recording how this was measured, because the first attempt reported no
difference: benchmarking one packet object in a loop lets Scapy cache the built
bytes after the first call. Only fresh objects — what the capture thread actually
receives — show the cost. A test hooks `build()` and fails if the capture path calls
it at all.

### Payload extraction no longer depends on how Scapy dissected the packet

Found by an end-to-end run after the TLS work, and it turned out to predate it.

`packet.haslayer(Raw)` is only true when Scapy had *no* dissector for the payload.
`from scapy.all import *` loads the TLS and DNS layers, so on a real capture
port-443 traffic dissects into a TLS layer and port-53 into a DNS layer — and the
extraction that keyed off `Raw` therefore reported **payload_size = 0 for both**.
That is most of a real capture, and it silently starved the exfiltration byte
counting and the `payload_ratio` ML feature.

The payload is now read from the TCP/UDP layer directly, which works however Scapy
chose to dissect it.

Only *dissected* packets show this: a packet built in memory keeps its Raw layer,
which is exactly why 273 unit tests passed over it and a smoke test against
wire-format frames caught it in one line. Seven regression tests now cover both
dissection modes.

### Test isolation

Every test module installed its own Scapy stub, which left `src.capture` holding
`IP = TCP = UDP = Raw = None` while `SCAPY_AVAILABLE` still read `True`. Whichever
module imported first decided what the rest of the suite got, so the TLS tests
passed alone and failed under discovery. `_test_support.py` now owns the shared
temp HOME and tries the real library first, stubbing only if it genuinely cannot
import. Verified in isolation, in order, and in reverse order.

---

## v1.5.0 — Audit remediation

A full review of the codebase (see `AUDIT.md`) found one exploitable security bug,
several defects that silently defeated the detection logic, and a set of documented
features that were not actually wired up. This release fixes all of them and adds
regression tests so they stay fixed.

**144 unit tests** (up from 100) plus 14 integration checks. CI runs the suite on
Python 3.10, 3.11 and 3.12.

### Security

- **Command injection in the Authenticode check (critical).**
  `process_verify._check_signature` interpolated an executable path into a PowerShell
  `-Command` string. The path comes from `psutil.Process(pid).exe()`, PowerShell expands
  `$(...)` inside double-quoted strings, and `$`, `(` and `)` are legal in Windows
  filenames — so an unprivileged user could get code execution in a process that ships
  with `--uac-admin`. The path is now passed in an environment variable and read with
  `-LiteralPath`; the PowerShell program is a module constant.
- **Credential vault storage policy.** Full plaintext secrets were written to disk for
  20+ protocols. Only **masked** values are stored now; raw storage is opt-in via
  `forensics.store_raw_credentials`.
- **Vault key derivation.** The key is still hostname+username by default (documented
  clearly as obfuscation, not confidentiality), but setting `forensics.vault_passphrase`
  now switches to scrypt over a random salt. The home-grown XOR fallback is gone —
  `cryptography` is required and the vault fails closed.
- **The README claimed AES-256.** Fernet is AES-128-CBC + HMAC-SHA256. Corrected
  everywhere, including in the GUI.
- **File permissions.** `~/.netsentinel/` is created `0700` and sensitive files `0600`
  where the platform supports it. Previously `0644`.
- **`forensics_log.json` no longer contains credential material.** It stored
  `value_masked` despite documenting "metadata only"; `_mask()` reveals the leading
  characters of short secrets.
- **Model files are authenticated.** `pickle.load()` from a user-writable directory in
  an elevated process was a privilege-escalation primitive. Models now carry an HMAC
  keyed outside the data directory, and a feature-count mismatch is detected on load
  instead of silently disabling scoring.
- **Threat feed downloads are bounded** (64 MB) and refuse to follow a redirect off HTTPS.

### Detection correctness

- **The baseline whitelist never stopped learning.** `app._on_packet` fed it
  unconditionally, so any domain or IP seen three times marked itself "normal" and
  permanently suppressed DNS tunnelling, bad-TLD, beaconing and full-severity exfil
  alerts for it — an attacker's own infrastructure whitelisted itself after four packets.
  Observation is now gated on `is_learning`.
- **ML rate features were pinned to constants.** The analysis loop passed a rolling
  5000-packet buffer while claiming a 5-second window, so `packets_per_sec` was
  `5000/5 = 1000.0` regardless of real traffic. The window is now time-bounded and the
  extractor divides by the span the packets actually cover.
- **`direction_asymmetry` was always 0.** It computed `abs(N - N)` by counting packets
  per source and per destination. It now measures byte imbalance relative to local hosts.
- **`DATA-EXFIL` fired on downloads.** Bytes were accumulated against `dst_ip` with no
  direction check, so a large download raised a HIGH "data sent to *your own IP*". Only
  traffic leaving the local network is counted now.
- **TLD checks matched substrings.** `query.endswith(tld.lstrip('.'))` flagged `laptop`,
  `desktop`, `rooftop`, `network`, `forest`, `webcam`, `uplink` and `homework` — all of
  which occur as single-label LLMNR/NetBIOS lookups. Matching is now label-based in both
  the IDS and the threat-intel engine.
- **`ODD-HOURS` hourly suppression lasted 150 seconds.** Its marker lived in
  `_alert_cooldowns`, which the pruner clears at `cooldown_sec * 5`, so the rule fired
  roughly 24x/hour instead of once. Long-lived suppressions have their own store.
- **`rules/default_rules.json` was never loaded.** Shipped, bundled by PyInstaller and
  documented, but nothing read it. It is now loaded at import, with a user copy in
  `~/.netsentinel/rules/` taking precedence. `.info` and `.biz` were removed from its
  TLD list as too noisy.
- **`ml.anomaly_threshold` controlled two unrelated things** — Isolation Forest
  `contamination` and the alert gate — in opposite directions. Split into
  `ml.contamination` and `ml.alert_threshold`; the old key is still honoured.
- **Process attribution was blank for almost every packet.** The throttle gated the
  lookup rather than the refresh, so roughly one packet per 5 seconds got a process name.
  The psutil enumeration now runs on a background thread and every packet reads the cache.
- **`startswith('172.')` covers 172.0.0.0/8**, not 172.16.0.0/12, so public addresses in
  172.0-15 and 172.32-255 were treated as private. Replaced with proper `ipaddress` checks.
- **BACnet service names were wrong.** Confirmed and unconfirmed services are separate
  namespaces that both start at 0; a single dict meant `Time-Synchronization` and
  `Who-Has` resolved to `CreateObject` and `DeleteObject`.

### Reliability and performance

- **Slow verification moved off the packet thread.** IOC alerts triggered file hashing,
  a PowerShell call and a VirusTotal lookup — each with a 10-second timeout — inline on
  the packet worker, so detecting something suspicious stalled the whole pipeline.
  Alerts now publish immediately and deepen asynchronously.
- **Forensics alert scanning is incremental.** It re-scanned every finding on every
  packet; it now reads from a cursor. Duplicate credentials no longer re-encrypt and
  rewrite the entire vault on each repeat packet.
- **Beaconing detection is a single pass.** It rebuilt the source set per destination by
  rescanning the whole window — O(packets x destinations) every cycle.
- **`DeviceLearner` only profiles local devices.** Every remote internet IP used to
  become a "device on your network": one browsing session produced 3000+ profiles and a
  1.2 MB JSON file. Per-device sets are now trimmed as well.
- **Alert history.** `save_alerts()` hardcoded `[:500]` while `max_stored` defaults to
  5000, and `_load_alerts` inverted the order on restore. Both fixed, plus periodic
  autosave so a crash no longer discards the session.
- **Desktop notifications flush on a timer.** The batch only flushed when the *next*
  alert arrived, so a burst followed by silence — what an incident looks like — was
  never delivered.
- **All persistence is atomic** (temp file + fsync + rename). Every save path was a
  full rewrite, so an interruption truncated the file and the loader silently started
  from empty.
- **`get_stats()` returns a real snapshot.** `dict()` is shallow, so callers received
  the live containers the worker keeps mutating.
- **PCAP writer.** A failed rotation left recording permanently dead against a closed
  handle; file I/O no longer happens under the buffer lock; the link type is
  configurable instead of hardcoded to Ethernet; and old recordings are pruned
  (`capture.pcap_max_files`) so continuous capture cannot fill the disk.
- **Dead state removed:** `_recent_connections`, `_recent_dns`, `_dhcp_devices`,
  `_smb_versions`, the IDS's never-written mDNS/LLMNR trackers, `_connection_timings`,
  `BaselineProfile._history` and `_dns_pairs`. The ARP table and the escalating exfil
  thresholds are now pruned.

### Configuration

All 56 keys in `DEFAULT_CONFIG` are now read by the code. Sixteen were dead, including
`forensics.enabled`, `forensics.save_credentials`, `forensics.retention_days`,
`verification.check_signatures`, `whitelists.domains`, `whitelists.processes` and
`blacklists.domains` — setting any of them appeared to work and did nothing. Retention
is now enforced at startup, and a new `BL-DOMAIN` rule backs the domain blacklist.

### Tests and project

- New `test_regressions.py`: 42 tests, one per audit finding.
- `test_live.py` had a failing assertion and called `sys.exit()` at import, which broke
  `unittest discover` and pytest collection. Fixed and moved to
  `tools/integration_check.py`; `test_detections.py` (which contributed 0 tests) moved
  to `tools/simulate_attacks.py`.
- Added GitHub Actions CI, `pyproject.toml`, `SECURITY.md` and a ruff configuration.
- Version strings reconciled (`main.py`, `src/__init__.py`, `setup.bat` disagreed).

---

## v1.4.0

## New: Passive Network Learning (Zero-Config)

NetSentinel now **learns your network automatically**. No hardcoded IPs, domains, or device lists.
Drop it on any network — home, office, data center — and it adapts.

### Device Discovery (`src/device_learner.py`)
- Passively discovers all devices from ARP, DHCP, mDNS, and traffic patterns
- Classifies each device as **gateway, workstation, IoT, printer, camera, server, or database**
  based purely on observed behavior (port usage, DNS patterns, traffic profiles)
- Detects gateways by observing which IPs respond to ARP for many targets
- Persists device inventory to `~/.netsentinel/data/learned_devices.json`
- New **Devices tab** in GUI with device table and auto-refresh

### Baseline Whitelist Learning (`src/baseline_whitelist.py`)
- During the ML baseline learning period (default 2 hours), records every domain,
  IP, port, and periodic beacon pattern observed as "normal for this network"
- After learning completes, the IDS and ML engine automatically suppress false positives
  for learned-normal patterns:
  - DNS tunnel and suspicious TLD rules skip learned domains
  - Beaconing detection skips learned periodic patterns
  - Data exfiltration alerts downgrade to MEDIUM for learned destinations
- Persists to `~/.netsentinel/data/baseline_whitelist.json`
- Supports user-configured additions via `config.json` → `whitelists.dga_whitelist_suffixes`
  and `whitelists.dga_whitelist_exact`

### Alert Correlation (`src/alert_correlator.py`)
- Groups related alerts into **Incidents** by source IP and time proximity (5-min window)
- Detects **escalation chains**: Recon → Attack, Threat Intel → Exfiltration,
  Credential Exposure → Brute Force
- Escalation incidents automatically bump to at least HIGH severity
- Turns 50 noisy alerts into 1 clear incident with a narrative summary
- New **Incidents tab** in GUI showing incident timeline with severity coloring

### PCAP Export (`src/pcap_writer.py`)
- **Ring buffer** of raw packets (last ~5 minutes at 500 pps)
- **"Export Last 5 Min"** button exports buffer to standard `.pcap` file
- **Continuous recording** with Start/Stop and auto-rotation at 100 MB
- **Capture file browser** in the new **Capture tab**
- Files saved to `~/.netsentinel/captures/`
- Buffer size and file rotation configurable via `config.json` → `capture.pcap_buffer_packets`
  and `capture.pcap_max_file_mb`

---

## Additional Fixes (post-test review)

- **DeviceProfile Counter trimming** — `dst_ports_used`, `dns_domains`, and `protocols_used`
  Counters are now trimmed to top-100/20 entries during periodic classification to prevent
  unbounded memory growth on long-lived devices.
- **AlertCorrelator persistence** — Incidents are now saved to `incidents.json` on shutdown
  and restored on restart (last 200 incidents preserved).
- **BaselineWhitelist `_dns_pairs` cap** — Capped at 50,000 entries to prevent unbounded growth.
- **PcapWriter configurable buffer** — Ring buffer size and max file size now configurable
  via `config.json` instead of hardcoded values.

---

## Bug Fixes (22 total)

### Critical (data corruption / incorrect behavior)
1. **Alert ID race condition** — `Alert._counter += 1` was not thread-safe.
   Replaced with `itertools.count()` (atomic in CPython).
2. **Capture stats race** — `stats['packets_captured'] += 1` ran without locks
   from the capture thread. Added dedicated atomic counters synced under lock.
3. **Forensics dedup collision** — credentials and sensitive data shared
   `_forensics_alerted_creds`. Split into separate sets.
4. **Unbounded `NetworkFlow.packet_sizes`** — plain list grew forever for long-lived flows.
   Removed entirely (was never consumed).

### Performance (hot-path optimizations)
5. **Set literals rebuilt per packet** — `CREDENTIAL_PORTS`, `COMMON_SERVICE_PORTS`,
   `STANDARD_OUTBOUND_PORTS`, `_PORT_NAMES`, `_SERVICE_NAMES` moved to module-level
   `frozenset`/dict constants. Eliminates ~500 set constructions/sec.
6. **O(n) DNS reverse scan → O(1)** — DNS-to-IP inference scanned up to 2,000 deque
   entries per packet. Replaced with `_latest_dns_by_ip` dict index.
7. **Cleanup runs every packet → every 1000** — `_periodic_cleanup()` called
   `time.time()` on every packet. Now uses a counter to skip the check.
8. **`_FEATURE_INFO` dict** — 18-entry dict rebuilt on every ML alert. Moved to module level.
9. **`top_talkers` pruned** — `defaultdict(int)` grew unbounded. Now pruned to top 500
   during flow cleanup.
10. **`dns_queries` list** — manual truncation replaced with `deque(maxlen=1000)`.

### Correctness
11. **Entropy calculation** — `entropy_dst_port` computed entropy of a unique *set*
    (always `log2(n)`). Now uses the frequency *distribution* of port usage.
12. **IPv6 blind spot** — IPv6 packets got `protocol="IPv6"` with no port extraction.
    Now extracts TCP/UDP ports, flags, and payload from IPv6 packets identically to IPv4.
13. **Data exfil counter reset** — after alerting, counter reset to 0 (lost evidence).
    Now uses escalating thresholds: 100 → 200 → 400 MB. Also baseline-aware.
14. **Time-of-day alert spam** — any 10KB+ packet at 3 AM triggered an alert.
    Now requires 50KB minimum and limits to 1 alert per source IP per hour.
15. **Config deep-merge** — `_deep_merge` used shallow copy. Override values with nested
    mutables were shared by reference. Now uses `copy.deepcopy`.
16. **Alert restore from disk** — `_load_alerts` loaded JSON but never reconstructed
    `Alert` objects. Historical alerts were silently discarded on restart. Fixed.
17. **`is_admin()` fallback** — returned `True` on unknown platforms. Now returns `False`.

### Reliability
18. **Splash screen dual-Tk** — `show_splash()` created a second `tk.Tk()` instance.
    Now uses `Toplevel` under a single root that's reused for the main GUI.
19. **Desktop notification spam** — 50 HIGH alerts in 10s = 50 notifications. Added
    batching (15s window) that summarizes: "12 new HIGH alerts in the last minute."
20. **Alert sound spam** — CRITICAL sounds had no cooldown. Added 10-second minimum.
21. **Feature store file handle** — no `__del__` or error recovery. Added safety net
    and flush error handling that resets file state on write failure.
22. **Bare `except:`** in GUI → `except Exception:` to avoid catching `SystemExit`.

---

## Architecture Improvements

- **GUI accepts reusable `tk_root`** — eliminates dual-`Tk()` bug and speeds startup
- **Capture engine accepts `raw_packet_callback`** — feeds PCAP writer without
  modifying the packet processing pipeline
- **IDS + ML engines accept `baseline_whitelist`** — injected by app after init,
  queried before raising heuristic alerts
- **Alert gateway feeds correlator** — every alert passes through correlation
  before reaching the GUI
- **Status bar** shows device count, active incidents, PCAP buffer size
- **3 new GUI tabs**: Devices, Incidents, Capture
- All learned data (devices, whitelist, alerts, incidents) saved on shutdown, restored on startup

---

## Test Suite

**100 tests total** (38 original + 62 new), all passing. Coverage includes:
- Thread safety: concurrent Alert ID creation from 4 threads (2000 IDs, zero duplicates)
- All 4 new modules: DeviceLearner, BaselineWhitelist, AlertCorrelator, PcapWriter
- All 22 bug fixes verified individually
- IDS + baseline whitelist integration (learned .xyz domains skip bad-TLD, unknown still fire)
- Edge cases: empty packets, None/empty fields, broadcast addresses, binary PCAP data
- Persistence roundtrips: save → reload → verify for devices, whitelist, alerts, incidents
- Escalation chain detection: Recon→Attack, ThreatIntel→Exfiltration
