# NetSentinel Changelog

## v1.16.4 — This network, on both dashboards

**2638 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button.

- **"This network"** is a panel on the browser dashboard's overview and a
  card on the desktop Dashboard tab: this PC's address on the network it
  watches, the subnet, gateway, DHCP and DNS servers, the network adapter,
  and this PC's other addresses (a VPN's, virtual adapters'). NetSentinel
  always found these when it started, and used them for detection, but
  neither dashboard showed them. Link-local addresses (169.254.x.x, fe80::)
  are left out: Windows gives one to every adapter that is connected
  nowhere. The desktop card refreshes every 30 seconds, monitoring or not.
- "This PC" is the address of the adapter NetSentinel captures on. The
  summary it was taken from kept only five of the PC's addresses, picked
  arbitrarily, and could leave out the one that matters: on a PC with
  Tailscale and virtual adapters, the VPN's address came out as "This PC".

Your public internet address is not shown: finding it means asking an
outside service, and NetSentinel sends nothing out beyond downloading its
threat lists.

## v1.16.3 — Gateway alerts this PC started

**2625 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button.

- **When this PC starts what the gateway caught, the alert says so.** An SSH
  client on the owner's desktop retried an address on another private network
  five times, and the UniFi gateway blocked it as "ET SCAN Potential SSH Scan
  OUTBOUND". NetSentinel's alert had it backwards: with both addresses
  private, it took the other one for this network's, put the desktop on the
  far side, and said to check what the other address runs on port 22. Now:
  - this PC's own addresses decide which side is here, then private against
    public, then the gateway's direction;
  - an event this PC started reads "This PC started it: ssh.exe (process
    4242) connected to ... on port 22", and the check says a program on this
    PC did what the gateway matched;
  - the program comes from the connection itself, which NetSentinel now
    remembers for five minutes with where it went, since the gateway's report
    arrives after the fact. When it can't tell, the alert says so.
- **No server names for this PC.** A website's name had been filed under this
  PC's own address, which made the desktop "outlook.office365.com" in that
  alert. Names are never filed under, or shown for, this PC's addresses.
- "NetSentinel saw this address too" looks at the far side, not this PC.

## v1.16.2 — Building automation, and a window that keeps up

**2610 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button. On a PC that runs a building's HVAC
controls, 1.16.1 raised almost nothing but BACnet, and the desktop window
barely opened or scrolled, with monitoring on or off. The browser dashboard
was fine. Each fix has tests that fail on 1.16.1.

- **A BACnet setting.** Settings → Building automation (`bacnet.mode`):
  - **Watch it**, the default and what NetSentinel did before: discovery from
    another computer, writes and device resets are alerts.
  - **This PC runs the building's controls**: its own discovery, polling and
    writes are expected, and BACnet is not listed as an unencrypted service.
    Resets, and writes from any other computer, are still alerts.
  - **Off**: BACnet is left out of the capture, so none of it is even read.
  If you added `not udp port 47808` to `capture.bpf_filter` as a stopgap,
  take it out and use the setting.
- **No more BACnet "credentials".** Every controller answering discovery was
  stored in the vault as a credential, and alerted as "[CONFIRMED] Plaintext
  Credential (BACnet)": filed under the broadcast address, with the source
  port shown as 0, saying to change a password nobody had sent. BACnet and
  Modbus write commands were filed as credentials too. None of them holds a
  secret. A controller that announces itself is now a building controller in
  the device list, and a write is a finding only. What was filed that way
  before is dropped from the vault and the Exposures page when NetSentinel
  starts.
- **A broadcast address is no device.** Controllers answer discovery to the
  broadcast address, which became an "Unencrypted BACnet Service" of its own.
- **The desktop window keeps up.** Timed on the real window:
  - The Forensics Vault drew every entry as its own row of widgets, a second
    after the window opened: 10 seconds for 500 entries, about 3 minutes for
    5,000, with the window frozen throughout. It is a table now, newest first
    (under a tenth of a second), loaded when you open the tab.
  - Each alert was a block of a dozen widgets, and the dashboard rebuilt its
    five most recent for every new one: 0.3 to 0.55 seconds of frozen window
    per alert, and a building network raises them by the hundred. The Alerts
    tab, the dashboard's recent alerts and the File Analyzer's list are
    tables now, and new alerts are added twice a second in one batch: 4 to
    25 ms an alert, a burst of 300 in 29 ms. With 5,000 stored alerts the
    window opens in under a second instead of 3.3, and the Alerts tab lists
    the latest 1,000, not 200, with an Ack column.
  - The Devices, Exposures, Incidents and Capture tabs rebuilt themselves
    every five seconds whether shown or not. Now only the one on screen does.
- **Open in vault.** A credential alert's window and a plaintext login on the
  Exposures page open the vault at that entry, to see what was actually
  caught. By default the vault keeps only the masked value; the full one only
  with `forensics.store_raw_credentials` on.

## v1.16.1 — A day on a work laptop, and four false alarms gone

**2574 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button. A few hours of 1.16.0 on a work laptop
running PingerPlot, a path monitor, raised 56 HIGH "ICMP Flood" and two
CRITICAL "SYN Flood" alerts, a HIGH DGA, a HIGH fast-flux, and a certificate
exposure filed under the laptop itself. None was an attack. Each fix has tests
that fail on 1.16.0, and the detection corpus keeps the attacks each rule is
for.

- **Path probes are not floods.** Traceroute, mtr and path monitors step the
  TTL up from 1 so that each router on the way answers, and no system starts
  its packets below 32. A packet from this network to the internet with a TTL
  of 30 or less is now a probe, left out of the ICMP and SYN flood counts:
  every probe but the last dies at a router before the target. A flood at a
  normal TTL still alerts, and so does a low TTL on the LAN, where no router
  stands in the way, or arriving from the internet.
- **DGA looks at the name someone registered.** Malware's generated names
  have to be registered to be any use, so that is where their randomness
  shows. Random labels under a domain someone else owns are that owner's
  naming: SharePoint and Azure SignalR hosts, Google's ad frames, Claude's
  artifact frames. Scoring every label made an evening of web pages a HIGH
  alert. OneDrive's numbered storage accounts (`onedrive...prod...NNNNN` under
  `blob.core.windows.net`) are allowed by name. Random registered domains,
  under `.co.uk` or a dynamic-DNS service too, still alert.
- **Fast-flux needs addresses that change.** An ad server's name gave 67
  addresses in a single answer, and was HIGH. A pool handed out whole is load
  balancing however big it is, so only the addresses beyond the largest single
  answer now count, and the alert says how large that was. With GeoIP on, one
  company under two AS numbers (velia.net's AS29066 and AS30083) counts as one
  network.
- **A bad certificate is an exposure of the server.** Certificate alerts were
  filed under this PC, at the random port it connected from, so each hourly
  repeat was a new entry on the Exposures page. They are filed under the
  server now, and repeats add to one entry. The misfiled entries are dropped
  when NetSentinel starts.

Before release, nine of the laptop's alert captures were replayed through
1.16.0 and this version: 38 ICMP Flood, 3 SYN Flood and the fast-flux alert
are gone, and every other alert is the same. The DGA alert did not recur in
the replay on either version, so its fix is checked by its tests and the
corpus.

## v1.16.0 — The gateway's threat detections, and three false alarms gone

**2550 unit tests** plus 14 integration checks.

- **UniFi's IDS/IPS detections are NetSentinel alerts.** The gateway already
  sent each "Threat Detected" and "Threat Detected and Blocked" event over the
  syslog NetSentinel receives, and NetSentinel stored them and did nothing
  more: the owner learned of a block from the UniFi phone app. Each is now a
  **UNIFI-IPS** alert with the signature and its number, the policy, UniFi's
  risk and action, and what NetSentinel adds:
  - when the gateway's "incoming" is a reply (from a remote service port to an
    ephemeral one here), it says this side most likely sent first;
  - NetSentinel's own alerts about the same address, at the same time;
  - its check rates a reputation-list hit on a shared Cloudflare, Akamai or
    Fastly address as likely someone else's listing (LOW), and an attack
    signature as a likely threat.
  - A threat event keeps its whole message: the first 400 characters, all
    that was kept, stopped before the signature.
- **Discord testing its voice servers is not a known malicious IP.** It pinged
  25 Cloudflare addresses once each; two are on the CINS Army list of hosts
  seen attacking sensors, and NetSentinel raised two HIGH alerts. Attacker
  lists were already skipped for this PC reaching a published cloud or CDN
  range, but 104.29.0.0/16 is Cloudflare's own and not in its CDN list. With
  GeoIP on, an address in Cloudflare's, Akamai's or Fastly's own network now
  counts as shared too. C2 lists still alert there, and so does a listed
  attacker connecting in.
- **ICMP Flood is one target hit hard.** It counted ICMP per source across all
  destinations, so Tailscale timing its 29 relay servers at a few pings a
  second each was 160 HIGH alerts in four minutes. It now counts per source
  and target, over 50 in ten seconds, one alert per pair per five minutes. A
  host pinging 20 or more local addresses in 30 seconds is its own MEDIUM
  **PING-SWEEP** alert, which the old count caught as a "flood".
- **A lost route is not a flood either.** In the same minutes, Tailscale's
  exit node lost its uplink and answered each HTTPS connection this PC tried
  with "host unreachable": 492 in four and a half minutes, one more HIGH alert.
  ICMP errors (unreachable, time exceeded and the like) answer traffic the
  target sent, so they now count as a flood only at attack rates, over 1,000
  in ten seconds (BlackNurse runs to tens of thousands a second).

Before release, the 23 hours of the owner's traffic around these alerts were
replayed through 1.15.0 and this version: the same alerts, less 160 ICMP Flood,
and no PING-SWEEP.

## v1.15.0 — Fewer false alarms, and nothing real missed

**2515 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button. A week of 1.14 on the owner's network raised
277 alerts for 62 distinct things, nearly all of them routine. This release
reports each thing once, says why it alerted, and adds a test
(`test_detection_corpus.py`) that replays the attacks each rule exists for: a
change that quiets a false alarm and an attack with it fails there.

In the first days after updating, each exposure already on your network is
alerted once more as it is listed, and each routine upload is reported once
while its history builds up.

- **Exposures, kept apart from alerts.** A plaintext login, an unencrypted
  service, a device answering SNMP's default community, software with a known
  exploited flaw or a bad certificate is a standing condition, not an event.
  248 of the week's alerts were 43 of these repeated: Home Assistant's token
  over plain HTTP on four days, an energy monitor's Modbus port as CRITICAL.
  - Each is now one entry per device and issue, in a new **Exposures** tab and
    dashboard page, with when it was first and last seen and how often.
  - A new one raises one alert; a repeat only updates its entry. It alerts
    again only if it gets worse, or comes back after you mark it fixed.
    **Accept** one you have decided to live with.
  - Exposures are rated at most HIGH. CRITICAL is for signs of an attack, and
    verification no longer raises a confirmed MEDIUM exposure to HIGH.
- **Large uploads judged by their own history.** The rule counted bytes per
  address and started again at 100 MB every day, so Tailscale to one peer,
  Chrome Remote Desktop and Claude were 13 HIGH alerts. It now keeps 30 days of
  uploads per program and destination (a service's many addresses share one
  history through the domain this PC's own DNS lookups gave them). A program's
  first large upload to a destination is reported; after that only a day past
  four times its biggest, and within a day at four times each level, not two.
  - The check looks at the uploading program's signature. A signed program
    counts in its favour, an unsigned one against, a broken signature heavily
    against; general-purpose tools attackers upload with (curl, PowerShell,
    certutil, rclone and the like) get no credit for being signed.
  - Volume counts only past 1 GB and 5 GB a day. A VPN to its peer is no longer
    a "LIKELY THREAT" because it moved 400 MB.
  - Marking an upload **Real** holds that pair: it is reported from 100 MB
    again and learns nothing.
- **Every alert says what it matched.** "Suspicious User Agent found in
  unencrypted traffic" now names the user agent, what in it matched, and the
  site (with any token in the request hidden). One site behind several
  addresses is one alert. Card numbers, SSNs, cookies and parking credentials
  never reach an alert, only what is safe to show.
  - Those five HIGH user-agent alerts were Edge running headless for its own
    background job, fetching from edge.microsoft.com. A headless browser asking
    its own maker is no longer flagged, and does not use up the once-per-source
    note, so automation to any other site still is.
- **A verdict acknowledges, and each rule keeps a record.** Real and False
  positive acknowledge the alert as well, in the dashboard and now in the
  desktop app's alert window, which had no way to judge an alert before.
  **Rule record** (desktop) and **How each rule has done** (dashboard) show per
  rule how many alerts were judged real or false: where detection needs work.
- **A device answering SNMP's default community was missed** when it was the
  first device the sender asked: its alert matched the sender's in the app's
  once-a-day check and was dropped as a repeat.
- New dashboard endpoints: `GET /api/exposures`, `GET /api/rules`, and the
  token-gated `POST /api/exposures/state?id=&state=open|accepted|fixed`.

## v1.14.2 — Signed by James Cupps

`NetSentinel.exe` is now code-signed, so Windows, and the administrator prompt
it raises at every start, name the publisher, James Cupps, instead of "Unknown
publisher". Nothing else changes. From 1.10.x or later this installs from the
Update button.

- **Authenticode signature.** Signed in Azure Artifact Signing, with the
  certificate James Cupps's other Windows apps carry, by a release job that
  installs nothing from PyPI and never runs the program. The checksum
  (`NetSentinel.exe.sha256`) and the updater's signature are of the signed exe.
  The built-in updater still checks its own Ed25519 signature before it
  installs anything, as before.
- Four new tests keep the release workflow to those rules.

## v1.14.1 — A scan is one alert, and one owner is one network

**2435 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button. Two false alarms from a few days of 1.14.0,
each fixed with tests that fail on 1.14.0.

- **SNMP's default community is one alert per sender, not one per device.** A
  building-controls scanner on this PC sent the community `public` to 310
  addresses. No device answered, and that was 159 CRITICAL "Plaintext
  Credential (SNMP)" alerts, each saying to change a password; analysing the
  same traffic from a capture gave 262. The default community is no secret, so
  what matters is who sends it and which devices answer to it:
  - Sending it is one MEDIUM a day per sender (HIGH for a write), saying it is
    a scan or a monitoring tool, and verification no longer marks it
    "[CONFIRMED]".
  - A device that answers to it is its own alert, once a day per device: HIGH
    for `public`, CRITICAL for `private`, which is often the write community.
  - The community is read from the SNMP header. It used to count anywhere in
    the packet, so a device description containing "public" matched.
  - Captures you analyse get the same once-a-day rule as live monitoring.
- **Fast-flux counts a network's owner, not its address blocks.** A name only
  looks like fast-flux when its short-lived addresses span four unrelated
  networks, and networks were counted by /16. An ad network's cookie-sync name
  gave 23 addresses in six /16s, all one company's (AS25751), and was HIGH.
  With GeoIP on, addresses now count by their owner (ASN), and the alert names
  the owners it counted. Addresses GeoIP doesn't know, and every address with
  GeoIP off, still count by /16.

## v1.14.0 — Fixes from an outside review

**2416 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button.

An outside review of 1.13.0 (2026-11-05) found these; each was checked against
the code before it was fixed, and each fix has a test (`test_outside_review.py`).

- **RFID tags and card digits stay out.** The parking parser put whole RFID tag
  numbers into alerts, the timeline and review bundles. Tags now show only their
  agency and last two digits, and review bundles drop card and tag fields, mask the
  digits a masked card still shows, and keep text from nested evidence only under
  known keys.
- **The UniFi key goes only to the pinned console.** The API key was sent before
  the certificate was compared with the pin, so a device answering for the console's
  address got it. The pin is now checked after the handshake, before the request.
- **Windows tools by absolute path.** NetSentinel runs as Administrator and ran
  `route`, `ipconfig`, `powershell` and `tshark` by bare name, which Windows looks
  up first in the exe's own folder (usually Downloads). They now run from System32
  and Program Files, as Windows reports them.
- **The ML model is no longer saved.** It was a pickle signed with a key kept beside
  it, so a program running as you could have run code as Administrator. Startup
  already trains from the feature history; the old files are deleted.
- **Only signatures that verify count.** A self-signed "Microsoft Corporation"
  scored as Microsoft, and "Reset Ltd" as ESET. Now a signature must verify, the
  publisher must match by name, and the writable folders under Windows count as
  suspicious, not as system folders.
- **A false-positive verdict is about the actor.** On an inbound alert it was keyed
  to this PC, which silenced that rule for every source. Verdicts now name the
  sender for scans, floods and spoofing, and never this PC's own addresses.
- **Names have to vouch for an address.** A TLS handshake naming drive.google.com,
  or a DNS answer nobody asked for, could make a C2 server a "Shared Cloud IP" at
  LOW. Only a DNS answer to this side's own query, or a TLS name inside its owner's
  published ranges, can lower an alert now, and reverse DNS never does.
- **A typo in Settings no longer switches the IDS off.** A threshold saved as `15x`
  silently skipped most rules on every connection, and other typos stopped
  NetSentinel starting. Settings refuses a non-number in a number field, and saved
  values fall back to their defaults with a warning.
- **Hostile files and syslog can't freeze the app.** A PDF built to stall the stream
  search held the whole app for minutes (1 MB: about a quarter of an hour), and a
  forged CEF message with long runs of whitespace for about a second each. Both are
  read in one pass now, and macro recovery from Office files reads each compressed
  chunk once, noting in the report when it hit its limits.
- **Syslog can't fill the disk.** Today's log file is capped at half of
  `syslog.max_mb`; past that its own oldest records go and the newest are kept, so
  older days are no longer deleted to make room. The drops are counted on the Threat
  data and Device traffic pages, "today" is the clock's date, one bad message no
  longer stops the receiver (a stopped one shows as Failed), a typo in its numbers no
  longer stops NetSentinel starting, and a day's export streams from disk.
- **The release build can't reach the signing key.** Building, signing and publishing
  are separate jobs; dependencies are pinned by hash (`requirements-build.lock`), only
  `cryptography` is installed next to the key, and actions are pinned by commit.
- The About dialog shows the real version.

**netmon** (the Linux site sensor):

- Drift: an endpoint that fails, or answers empty where it had rows, keeps the last
  run's copy, so a controller reboot no longer reports every rule deleted and every
  forward new. If nothing can be read, the check fails and saves nothing.
- A push that can't reach ntfy is retried, backing off to hourly; the UI and the
  digest show it as "push failed". An hourly push budget (20, with 5 kept for
  critical findings and canary hits) holds the rest for the digest, and a port scan
  is one finding per source and destination.
- The UniFi importer keeps only a URL's scheme, host and path, so a password in a URL
  no longer reaches a push or the summariser.
- The web UI checks the Host header on every bind, not only loopback; a 0.0.0.0 or ::
  bind needs the new `--allowed-host`.
- Names from the network are quoted or withheld in suggested commands.
- `bacnet_control` matches only Confirmed-Request, so a controller's SimpleACK no
  longer raises a critical push.
- Alert extracts are no longer taken for captures, and are pruned by age and count.
- The digest keeps its hour instead of moving an hour earlier each day, and a DST
  change no longer sends it twice.
- The capture unit starts on a fresh install.

## v1.13.0 — Your UniFi gateway's log, kept here

**2284 unit tests** plus 14 integration checks. From 1.10.x or later this
installs from the Update button. To use it: in UniFi (CyberSecure → Traffic
Logging) choose SIEM Server with this PC's address and a UDP port, let that port
in through Windows Firewall from the gateway's address, then turn it on in
Settings → UniFi traffic log over syslog.

- **Your gateway's traffic log, kept here.** A UniFi gateway without a drive keeps its
  traffic log briefly and will not export it, but it can send it over syslog as it
  happens. NetSentinel can now receive it (Settings: UniFi traffic log over syslog,
  off by default; `src/syslog_receiver.py`).
  - It listens only on the address and UDP port you set, and accepts only the
    gateway's address. It never answers.
  - It reads CEF (UniFi's SIEM output), iptables-style and key=value lines, and stores
    each day as JSON lines under `data/unifi_logs/`, within 30 days and 500 MB.
  - The new **Device traffic** page lists what each device tried to reach and how
    often, by its UniFi name, and exports any stored day.
  - Checked against a real UDM Pro on UniFi Network 10.6: it sends the connections
    its firewall policies block (device, domain, policy and zones), Wi-Fi, DHCP,
    admin and system events, but not the connections it allows (only NetFlow
    exports those). So block a device for a day and the page shows what it needs.

## v1.12.0 — Your UniFi names, and no more false passwords

**2266 unit tests** plus 14 integration checks. From 1.10.x or 1.11.0 this
installs from the Update button.

- **Device names from UniFi.** Opt-in and read only: with a UniFi console's address
  and an API key made in its Integrations settings (Settings → UniFi), NetSentinel
  reads the console's client list every 5 minutes (`src/unifi.py`).
  - The Devices page shows the name the owner gave each device.
  - Alerts name both ends ("192.168.1.10 (Office 3D Printer)").
  - The Threat data page says whether the console is connected.
  - Only the sites and clients endpoints are read, with GET; the API's firewall
    and ACL writes are never called.
  - It talks only to a console at a private address, and pins the console's
    certificate on first use.
  - The key is masked in Settings and never logged.
  - Review bundles drop the names, since they are often people's.

- **A Windows Update download is not a password.** On 1.11.0's first afternoon,
  Delivery Optimization fetched a Visual Studio update over plain HTTP from a
  cache server, and two "[CONFIRMED] Plaintext Credential (HTTP Form)" alerts,
  CRITICAL, came of it. The credential checks read the server's side too, and
  27,000 packets of compressed data held "Token:" and "pwD:" by chance.
  1.10.x had skipped most of such downloads under its 500-packet cap. Now
  logins, tokens, keys and form fields are looked for only in what a client
  sends, and form fields only in text: a binary upload can match by chance
  the same way. Replayed, the two captures raise nothing, and ESET's hashed
  update login in the same kind of traffic is still found.

## v1.11.0 — Threat data you can see, CVE checks, and HTTPS back in view

**2247 unit tests** plus 14 integration checks. From 1.10.x this installs from
the Update button. After it, put a free abuse.ch key in Settings → Threat data
to turn on URLhaus, ThreatFox and MalwareBazaar.

- **A better browser dashboard.** The charts drew only what the page had seen
  since it opened, with no axes and no readout: a fresh page showed one line.
  - NetSentinel now keeps a day of traffic, sampled every 5 seconds from the
    capture counters (every packet, before the analysis cap). The charts pick
    15 minutes, 1 hour, 6 hours or 24 hours, and are full the moment the page
    opens.
  - Both charts have time and value axes, and a now / average / peak line.
    Pointing at one gives the time, the rate, and the peak within that bucket.
    A stopped stretch shows as a gap, not a dive to zero.
  - The six summary cards sit in one row, or three, or two on a phone. The
    alert, flow and device cards open their pages.
  - The Engine panel is grouped, with the drop counts explained.
  - Alerts open to their evidence as labelled fields with the advice first,
    instead of raw JSON, and say how long ago they fired.
  - Devices sort by any column; addresses sort as numbers.
  - The browser tab title counts open alerts.
  - The tab bar no longer scrolls sideways at middling widths, and on a phone
    the header scrolls away.
  - Incidents read "1 alert", and give the span only when there is one: they
    said "1 alerts ... within 0s".

- **HTTPS was nearly invisible on installs from before September, and analysis
  stopped at 500 packets a second.** A saved `config.json` keeps every value it
  was first written with, so two fixed defaults never reached existing installs:
  - The capture filter dropped every established HTTPS packet. Only the opening
    SYN of each connection was seen, so the TLS hello, with its server name and
    JA3/JA4, never was. Fixed in the defaults on 2026-09-24.
  - `max_pps` stayed at the old 500: 6% of packets went unanalysed with the CPU
    at 1%.

  Both are now replaced once, at start, while they still hold the old default
  exactly (`config.STALE_DEFAULTS`, recorded in `migrations.applied`), so a
  value set on purpose stays.
- **Over the cap, bulk data goes first.** It used to be whichever packets came
  next, so a fast download took the lookups and handshakes of everything else
  with it. Now a full data segment that told extraction nothing (no handshake,
  server name, request or certificate) is counted to its flow but not
  inspected. Everything else gets up to twice the cap. The dashboard shows why
  packets went unanalysed: over twice the cap, a full queue, or bulk not
  inspected.
- **Threat data page.** The dashboard's new Threat data tab, and Settings →
  Threat data → Threat data status, list every source with its state, last
  update and size, and why it is not in use when it isn't. URLhaus had gone
  unused since April, first for want of a key, then as too old to trust, with
  nothing to say so.
- **The abuse.ch key has a Settings field** (masked, saved as text). abuse.ch
  closed its last keyless downloads on 2026-10-22. With the free key:
  - URLhaus comes back.
  - **ThreatFox** adds C2 addresses, matched on their listed port only, plus
    domains, URLs and file hashes.
  - **MalwareBazaar's** hash lists (last 48 hours every 6 hours, all weekly) go
    to the folder file scans read.
- **New feeds:**
  - **Spamhaus DROP** (hijacked and criminal networks; credit and list date
    shown).
  - **CINS Army** (attacking hosts).
  - **The Tor Project's relay list.** A connection to a running relay is now
    IOC-TOR whatever its port, where it used to be a guess from port numbers.
- **Listed networks are found by bisection,** about 8 µs a lookup with 1,800
  networks, where every lookup used to scan them all.
- **Known exploited vulnerabilities.** CISA's KEV catalog and NVD's affected
  versions for it are downloaded daily. A LAN server whose `Server` header or
  SSH, FTP or mail greeting names a version in a listed range raises VULN-KEV:
  MEDIUM, or HIGH when ransomware is known to use the CVE. The network audit
  reports AUDIT-KEV for the same thing. Alerts say when a distribution's build
  may carry the fix, and internet servers are left alone. Settings → Threat
  data turns it off (`vulns.enabled`).
- **HTTP on a port no list names is called unencrypted HTTP:** LOW on the LAN,
  MEDIUM to the internet. Home Assistant's 8123 was never named.
- **netmon** read a segmented BACnet request's service from the wrong byte.
- **Not added:** FoxIO's JA4DB. It went behind an enterprise sign-up in 2026,
  with terms that forbid copying it.

## v1.10.1 — A fourth day of real alerts

**2195 unit tests** plus 14 integration checks. The first release 1.10.0 can
install itself, from the Update button. A day of 1.10.0 raised 13 alerts: the
CRITICAL and the HIGH were false, and a real token in plain HTTP raised
nothing. Each fix has a test that fails on 1.10.0.

- **Credentials in plain HTTP on any port.** They were looked for only on a
  list of HTTP ports. Home Assistant's API on 8123 took a long-lived Bearer
  token from a program on this PC in clear, with no alert. A request line on
  any port is now read as HTTP.
- **One credential alert a day**, per token, host and server. A program that
  sends its token on every request was a CRITICAL every 30-second cooldown.
- **AMD's telemetry key is LOW.** AMD Software's User Experience Program
  uploads over plain HTTP with its own key in the `Authorization` header, and
  it was "[CONFIRMED] Plaintext Credential, change this password immediately".
  The key is AMD's: the alert now says there is nothing to change, and how to
  turn the program off. The header is read to the end of its line; it used to
  run on into the next header's name, which went to the vault with the key. An
  empty `X-Api-Key` header no longer takes the next line as its key. Vendors
  are matched on a dot boundary, where `preset.com` used to count as ESET.
- **BACnet is known by its framing, and its services are read right.**
  - An SSDP search whose random source port was 47808 was "BACnet" HIGH.
    Anything on that port that isn't BACnet/IP (type 0x81, with its own
    length) is now nothing.
  - A confirmed request's invoke ID was read as its service. Any request
    numbered 15, 16 or 20 was a CRITICAL "BACnet WRITE" or "RESET", and real
    ones with other numbers were missed.
  - A global Who-Is, the commonest discovery, was one byte short of what the
    parser wanted, so it was never seen.
  - Forwarded broadcasts, routed packets and segmented requests are walked
    right, and network-layer messages are skipped.
  - The confirmed service names for 6, 7, 10 and 11 were wrong.
- **Alert captures are kept for good.** The traffic saved behind an alert was
  pruned: outside review mode, all but the newest 50 were deleted, and review
  mode cut its snippets to 500 MB, oldest first. So an alert from last week
  could come up for review with its traffic gone. Now nothing deletes them. They
  are small, a few hundred KB each.
  - Outside review mode they go in `captures/alerts/`, apart from the recordings
    that rotate. Review mode keeps them in `review/snippets/`, as before; only
    its rolling full capture keeps to a budget.
  - When the disk is nearly full, below `capture.alert_min_free_mb` (1 GB), a
    new capture is skipped instead, and the alert says why.
  - A repeat of an alert within its cooldown now points at the first one's
    capture in both modes. It used to get nothing outside review mode.
  - The Captures tab lists them too.
  - `capture.pcap_max_alert_files` and `review.snippet_budget_mb` are gone.

## v1.10.0 — NetSentinel updates itself

**2169 unit tests** plus 14 integration checks. Earlier versions have no
updater, so moving to this one is a manual download, the last one; later
releases install from the Update button.

- **One-click updates.** NetSentinel asks GitHub for a newer release at start
  and once a day, sending only its version (Settings → Updates turns this off).
  An **Update** button then appears in the status bar, with the release notes.
  **Install and restart**:
  - checks the release's signed manifest (Ed25519, against a key built in);
  - downloads the exe and checks its SHA-256 against the signed one, and
    against the published `.sha256`;
  - hands over to the new exe, which waits for this one to exit, puts itself in
    place (the old one is kept as `NetSentinel.exe.old` until the next start)
    and starts with the same arguments, monitoring if it was.

  A signature that does not verify, a version older than the running one, or a
  download that is not the signed file installs nothing. Run from source,
  NetSentinel only says a new version is out. The browser dashboard shows the
  new version but cannot install it.
- **Releases are signed** for the updater: `tools/sign_release.py`, run by the
  release workflow with the `NETSENTINEL_SIGNING_KEY` secret. A tag built
  without the secret fails rather than ship a release the updater cannot check.

## v1.9.2 — A third day of real alerts

**2145 unit tests** plus 14 integration checks. A day of 1.9.1 raised 36 alerts,
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

### Captures are rated like live traffic
Replaying the day's captures showed PCAP analysis building its own credential
alert: every credential was a CRITICAL "Plaintext Credential", ESET's hashed
update login included. It now uses the live alert, rated by the finding.

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

A full review of the codebase (see `docs/AUDIT.md`) found one exploitable security bug,
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
