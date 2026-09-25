"""
Event sources.
==============
Where events come from. Each source turns its own vocabulary into the common
`Event`, so the rules never learn which one they are reading.

    unifi_csv   UniFi flow exports — a day of every conversation, no payload
    pcap        a capture file, replayed through the packet parsers
    live        a mirror port
"""
