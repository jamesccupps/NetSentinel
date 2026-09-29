"""
Protocol parsers.
=================
Enough of each protocol to answer the question a rule asks, and no more.

These are not general-purpose dissectors. A rule wants to know "was this a write
command, to which object, from whom" — not to reconstruct the full ASN.1. Parsing
only what is needed keeps the code small enough to audit, and a parser that never
walks the deep structure cannot be made to crash by a malformed packet in it.

Every parser here is bounds-checked and returns None rather than raising. They
run against whatever arrives on a mirror port, which is by definition not under
anyone's control.
"""
