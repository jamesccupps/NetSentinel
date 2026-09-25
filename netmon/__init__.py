"""
netmon — passive site network monitoring.
==========================================
A monitor for one building's network: building automation, access control,
video, kiosks, the flat unsegmented things that run a site and were never
designed to be watched.

It is passive and advisory. It reads a mirror port or a capture file, says what
it sees, and changes nothing. There is no inline blocking, no firewall
automation, no TLS interception.

Everything site-specific lives in a profile (`netmon.profile`), so the rules can
be written once and mean something at a second site. Keep your own profile out of
version control — it is a map of your network.

Layout
------
    profile     the site's VLANs, devices, roles, expected flows, and the
                segments whose payload must never be stored
    bpf         VLAN-aware capture filter construction, verified against tcpdump
    sources     where events come from: live capture, pcap, UniFi flow exports
    rules       what counts as notable, expressed against roles and zones
"""

__version__ = '0.1.0'
