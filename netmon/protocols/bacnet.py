"""
BACnet/IP.
==========
The protocol that runs building automation, and the reason this monitor exists.

BACnet/IP has no authentication of any kind. Anything that can send a UDP packet
to port 47808 on a controller can command it: change a setpoint, stop a fan,
reinitialise the device, rewrite the table that decides which controllers hear
broadcasts. There is no credential to steal because there is no credential. The
only defence is the network, and the only way to know whether that defence is
holding is to watch.

So this parser answers three questions:

    Was this a command or a question?    — the service, and whether it writes
    What did it act on?                  — the object and property
    Who is rearranging the network?      — BBMD and foreign-device operations

What it does not do
-------------------
It does not decode values. A rule asks "did someone write to analog-value-7",
not "what number did they write" — and the value is the part of the packet most
likely to be malformed, most variable between vendors, and least useful to a
rule. Skipping it removes the deepest parsing from the code that runs against
unvalidated input.

It stops at the first thing it cannot read and returns what it has. A packet
that is truncated after the service choice still tells you a write happened.

Layers
------
    BVLC    4 bytes usually, 10 for a forwarded NPDU. Says whether this is a
            plain message, a broadcast, or one of the table operations.
    NPDU    version, control byte, then optional routing addresses whose
            lengths are in the packet. This is where a malformed frame is most
            likely to send a naive parser off the end.
    APDU    type, service choice, then the parameters.

Verified against the service tables in ASHRAE 135. The confirmed and
unconfirmed service namespaces are *different* — service 8 is addListElement
confirmed and Who-Is unconfirmed — which is the single easiest thing to get
wrong here, and would report every device discovery as a list modification.
"""

from __future__ import annotations

__all__ = ['parse', 'BacnetMessage', 'is_bacnet_port', 'WRITE_SERVICES',
           'TOPOLOGY_FUNCTIONS', 'CONFIRMED_SERVICES', 'UNCONFIRMED_SERVICES']

#: The registered port, and the usual range for additional networks.
BACNET_PORTS = frozenset(range(47808, 47824))


def is_bacnet_port(port):
    return port in BACNET_PORTS


# ─── Tables ──────────────────────────────────────────────────────────────────

BVLC_FUNCTIONS = {
    0x00: 'BVLC-Result',
    0x01: 'WriteBroadcastDistributionTable',
    0x02: 'ReadBroadcastDistributionTable',
    0x03: 'ReadBroadcastDistributionTableAck',
    0x04: 'Forwarded-NPDU',
    0x05: 'RegisterForeignDevice',
    0x06: 'ReadForeignDeviceTable',
    0x07: 'ReadForeignDeviceTableAck',
    0x08: 'DeleteForeignDeviceTableEntry',
    0x09: 'DistributeBroadcastToNetwork',
    0x0A: 'Original-Unicast-NPDU',
    0x0B: 'Original-Broadcast-NPDU',
    0x0C: 'Secure-BVLL',
}

#: BVLC operations that change who hears what. Whoever controls the broadcast
#: distribution table controls which controllers receive which messages, which
#: is a quieter and more durable foothold than writing a setpoint.
TOPOLOGY_FUNCTIONS = frozenset({
    'WriteBroadcastDistributionTable', 'ReadBroadcastDistributionTable',
    'ReadBroadcastDistributionTableAck', 'RegisterForeignDevice',
    'ReadForeignDeviceTable', 'ReadForeignDeviceTableAck',
    'DeleteForeignDeviceTableEntry', 'Forwarded-NPDU',
})

APDU_TYPES = {
    0: 'Confirmed-Request', 1: 'Unconfirmed-Request', 2: 'SimpleACK',
    3: 'ComplexACK', 4: 'SegmentACK', 5: 'Error', 6: 'Reject', 7: 'Abort',
}

#: Confirmed service choices (ASHRAE 135 clause 21). A separate namespace from
#: the unconfirmed one below — the same number means different things.
CONFIRMED_SERVICES = {
    0: 'AcknowledgeAlarm', 1: 'ConfirmedCOVNotification',
    2: 'ConfirmedEventNotification', 3: 'GetAlarmSummary',
    4: 'GetEnrollmentSummary', 5: 'SubscribeCOV', 6: 'AtomicReadFile',
    7: 'AtomicWriteFile', 8: 'AddListElement', 9: 'RemoveListElement',
    10: 'CreateObject', 11: 'DeleteObject', 12: 'ReadProperty',
    13: 'ReadPropertyConditional', 14: 'ReadPropertyMultiple',
    15: 'WriteProperty', 16: 'WritePropertyMultiple',
    17: 'DeviceCommunicationControl', 18: 'ConfirmedPrivateTransfer',
    19: 'ConfirmedTextMessage', 20: 'ReinitializeDevice', 21: 'VT-Open',
    22: 'VT-Close', 23: 'VT-Data', 24: 'Authenticate', 25: 'RequestKey',
    26: 'ReadRange', 27: 'LifeSafetyOperation', 28: 'SubscribeCOVProperty',
    29: 'GetEventInformation', 30: 'SubscribeCOVPropertyMultiple',
    31: 'ConfirmedCOVNotificationMultiple', 32: 'ConfirmedAuditNotification',
    33: 'AuditLogQuery',
}

UNCONFIRMED_SERVICES = {
    0: 'I-Am', 1: 'I-Have', 2: 'UnconfirmedCOVNotification',
    3: 'UnconfirmedEventNotification', 4: 'UnconfirmedPrivateTransfer',
    5: 'UnconfirmedTextMessage', 6: 'TimeSynchronization', 7: 'Who-Has',
    8: 'Who-Is', 9: 'UTCTimeSynchronization', 10: 'WriteGroup',
    11: 'UnconfirmedCOVNotificationMultiple', 12: 'UnconfirmedAuditNotification',
    13: 'Who-Am-I', 14: 'You-Are',
}

#: Services that change something. These are what the bacnet_control rule
#: watches; everything else is a question, and questions are not the risk.
#:
#: DeviceCommunicationControl and ReinitializeDevice are here because they are
#: worse than a setpoint change, not milder: the first silences a controller,
#: the second restarts it, and neither needs to know anything about the site.
WRITE_SERVICES = frozenset({
    'WriteProperty', 'WritePropertyMultiple', 'DeviceCommunicationControl',
    'ReinitializeDevice', 'AtomicWriteFile', 'CreateObject', 'DeleteObject',
    'AddListElement', 'RemoveListElement', 'WriteGroup',
    'ConfirmedPrivateTransfer', 'UnconfirmedPrivateTransfer', 'LifeSafetyOperation',
})

OBJECT_TYPES = {
    0: 'analog-input', 1: 'analog-output', 2: 'analog-value',
    3: 'binary-input', 4: 'binary-output', 5: 'binary-value',
    6: 'calendar', 7: 'command', 8: 'device', 9: 'event-enrollment',
    10: 'file', 11: 'group', 12: 'loop', 13: 'multi-state-input',
    14: 'multi-state-output', 15: 'notification-class', 16: 'program',
    17: 'schedule', 18: 'averaging', 19: 'multi-state-value', 20: 'trend-log',
    21: 'life-safety-point', 22: 'life-safety-zone', 23: 'accumulator',
    24: 'pulse-converter', 25: 'event-log', 26: 'global-group',
    27: 'trend-log-multiple', 28: 'load-control', 29: 'structured-view',
    30: 'access-door', 32: 'access-credential', 33: 'access-point',
    34: 'access-rights', 35: 'access-user', 36: 'access-zone',
    37: 'credential-data-input', 39: 'bitstring-value', 40: 'characterstring-value',
    45: 'integer-value', 46: 'large-analog-value', 47: 'octetstring-value',
    48: 'positive-integer-value', 49: 'time-pattern-value', 50: 'time-value',
    56: 'network-port', 57: 'elevator-group', 58: 'escalator', 59: 'lift',
}

#: Only the properties a rule is likely to mention. An unknown number is
#: reported as `property-<n>` rather than dropped — a rule can still match it,
#: and inventing a name would be worse than admitting ignorance.
PROPERTY_IDENTIFIERS = {
    28: 'description', 36: 'event-state', 51: 'high-limit', 59: 'low-limit',
    65: 'notification-class', 75: 'object-identifier', 76: 'object-list',
    77: 'object-name', 79: 'object-type', 81: 'out-of-service',
    85: 'present-value', 87: 'priority-array', 103: 'reliability',
    104: 'relinquish-default', 111: 'status-flags', 112: 'system-status',
    117: 'units', 118: 'update-interval', 120: 'vendor-identifier',
    121: 'vendor-name', 139: 'protocol-revision', 155: 'database-revision',
    371: 'property-list', 846: 'serial-number',
}

REINITIALIZE_STATES = {
    0: 'coldstart', 1: 'warmstart', 2: 'startbackup', 3: 'endbackup',
    4: 'startrestore', 5: 'endrestore', 6: 'abortrestore', 7: 'activate-changes',
}

#: Vendor 7 is Siemens; service 511 is its private transfer, which this site
#: uses for its own automation traffic. Named so it is recognisable in an alert
#: rather than appearing as an unexplained private transfer.
KNOWN_PRIVATE_TRANSFERS = {(7, 511): 'siemens-p2-transfer'}


# ─── Bounded reader ──────────────────────────────────────────────────────────

class _Reader:
    """
    A cursor that refuses to read past the end.

    Every read returns None when there is not enough left, and the caller stops.
    This runs against packets from a mirror port, so "the length field says 40
    but the packet is 12 bytes" is a case to handle, not an anomaly.
    """

    __slots__ = ('data', 'pos')

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos

    def u8(self):
        if self.remaining() < 1:
            return None
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self):
        if self.remaining() < 2:
            return None
        value = int.from_bytes(self.data[self.pos:self.pos + 2], 'big')
        self.pos += 2
        return value

    def u32(self):
        if self.remaining() < 4:
            return None
        value = int.from_bytes(self.data[self.pos:self.pos + 4], 'big')
        self.pos += 4
        return value

    def take(self, count):
        if count < 0 or self.remaining() < count:
            return None
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def peek(self):
        return self.data[self.pos] if self.remaining() else None


# ─── The parsed message ──────────────────────────────────────────────────────

class BacnetMessage:
    """
    What a rule needs to know about one BACnet packet.

    Fields are None when the packet did not carry them or was truncated before
    them. `is_write` and `is_topology` are the two questions rules actually ask.
    """

    #: `vendor_service` rather than `private_service`, which is what the
    #: standard calls it: the outbound redaction gate drops any field whose name
    #: contains "private", for private keys. The BACnet sense of the word is
    #: entirely benign, but narrowing that denylist to fix one field name is how
    #: a hole gets made. Renaming the field costs nothing.
    __slots__ = ('bvlc_function', 'apdu_type', 'service', 'object',
                 'property', 'invoke_id', 'peer', 'network', 'vendor',
                 'vendor_service', 'truncated', 'reinitialize_state',
                 'device_instance', 'enable_disable')

    def __init__(self, **kw):
        for name in self.__slots__:
            setattr(self, name, kw.get(name))
        self.truncated = bool(kw.get('truncated'))

    @property
    def is_write(self):
        return self.service in WRITE_SERVICES

    @property
    def is_topology(self):
        return self.bvlc_function in TOPOLOGY_FUNCTIONS

    @property
    def is_broadcast(self):
        return self.bvlc_function in ('Original-Broadcast-NPDU',
                                      'DistributeBroadcastToNetwork')

    def as_fields(self):
        """The dict an Event carries, with empty entries left out."""
        fields = {
            'service': self.service,
            'bvlc_function': self.bvlc_function,
            'apdu_type': self.apdu_type,
            'object': self.object,
            'property': self.property,
            'peer': self.peer,
            'network': self.network,
            'vendor': self.vendor,
            'vendor_service': self.vendor_service,
            'device_instance': self.device_instance,
            'reinitialize_state': self.reinitialize_state,
            'enable_disable': self.enable_disable,
            'bacnet_write': self.is_write,
            'bacnet_topology': self.is_topology,
            'bacnet_truncated': self.truncated,
        }
        return {k: v for k, v in fields.items() if v not in (None, '')}

    def __repr__(self):
        parts = [self.bvlc_function or '?', self.service or '']
        if self.object:
            parts.append(self.object)
        return f'<BACnet {" ".join(p for p in parts if p)}>'


# ─── Parsing ─────────────────────────────────────────────────────────────────

def parse(payload):
    """
    Parse a BACnet/IP payload. Returns a BacnetMessage, or None if it is not one.

    Never raises. A packet that stops early yields a message with `truncated`
    set and whatever was readable — which is usually enough, since the service
    choice comes before the parameters.
    """
    if not payload or len(payload) < 4:
        return None

    reader = _Reader(payload)
    if reader.u8() != 0x81:                  # BVLL for BACnet/IP
        return None

    function = reader.u8()
    declared = reader.u16()
    if function is None or declared is None:
        return None

    message = BacnetMessage(bvlc_function=BVLC_FUNCTIONS.get(
        function, f'bvlc-0x{function:02x}'))

    # The length field covers the whole BVLC message including its own header.
    # A mismatch is worth noting but not worth discarding the packet over:
    # captures are truncated by snap length far more often than by an attack.
    if declared != len(payload):
        message.truncated = True

    if function == 0x04:                     # Forwarded-NPDU carries the origin
        origin = reader.take(4)
        port = reader.u16()
        if origin is not None:
            message.peer = '.'.join(str(b) for b in origin)
            if port:
                message.peer += f':{port}'
        else:
            message.truncated = True
            return message

    elif function in (0x05,):                # RegisterForeignDevice: a TTL
        ttl = reader.u16()
        if ttl is None:
            message.truncated = True
        return message

    elif function in (0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x00):
        # Table reads and writes carry no NPDU. The function is the finding.
        return message

    if not _parse_npdu(reader, message):
        message.truncated = True
        return message
    _parse_apdu(reader, message)
    return message


def _parse_npdu(reader, message):
    """
    Walk the network layer. Returns False if it ran out of packet.

    The routing addresses are variable-length with the lengths in the packet,
    which is where a parser that trusts its input walks off the end. Every
    length here is checked against what is actually left.
    """
    version = reader.u8()
    control = reader.u8()
    if version is None or control is None:
        return False

    if control & 0x20:                       # destination present
        network = reader.u16()
        length = reader.u8()
        if network is None or length is None:
            return False
        message.network = network
        if length and reader.take(length) is None:
            return False

    if control & 0x08:                       # source present
        source_network = reader.u16()
        length = reader.u8()
        if source_network is None or length is None:
            return False
        if message.network is None:
            message.network = source_network
        if length and reader.take(length) is None:
            return False

    if control & 0x20:                       # hop count follows a destination
        if reader.u8() is None:
            return False

    if control & 0x80:
        # A network-layer message, not an application one. Its type replaces the
        # service; these are router announcements and routing-table changes,
        # which reshape the network as surely as a BBMD write does.
        kind = reader.u8()
        message.service = f'network-message-0x{kind:02x}' if kind is not None \
            else 'network-message'
        return kind is not None

    return True


def _parse_apdu(reader, message):
    """Read the application layer as far as the service parameters."""
    first = reader.u8()
    if first is None:
        message.truncated = True
        return

    apdu_type = first >> 4
    message.apdu_type = APDU_TYPES.get(apdu_type, f'apdu-{apdu_type}')

    if apdu_type == 0:                                  # Confirmed-Request
        if first & 0x08:                                # segmented
            if reader.u8() is None:                     # max segments/APDU
                message.truncated = True
                return
        if reader.u8() is None:                         # max APDU accepted
            message.truncated = True
            return
        message.invoke_id = reader.u8()
        if first & 0x08:                                # sequence + window
            if reader.u8() is None or reader.u8() is None:
                message.truncated = True
                return
        choice = reader.u8()
        if choice is None:
            message.truncated = True
            return
        message.service = CONFIRMED_SERVICES.get(choice, f'confirmed-{choice}')
        _parse_parameters(reader, message)

    elif apdu_type == 1:                                # Unconfirmed-Request
        choice = reader.u8()
        if choice is None:
            message.truncated = True
            return
        message.service = UNCONFIRMED_SERVICES.get(choice, f'unconfirmed-{choice}')
        _parse_parameters(reader, message)

    elif apdu_type in (2, 3):                           # SimpleACK, ComplexACK
        message.invoke_id = reader.u8()
        choice = reader.u8()
        if choice is not None:
            # An acknowledgement names the service it answers, in the confirmed
            # namespace. Useful because a SimpleACK to WriteProperty is proof
            # the write was accepted, not merely attempted.
            message.service = CONFIRMED_SERVICES.get(choice, f'confirmed-{choice}')

    elif apdu_type in (5, 6, 7):                        # Error, Reject, Abort
        message.invoke_id = reader.u8()


def _parse_parameters(reader, message):
    """
    Read the leading context tags, which is where the object and property are.

    Stops at the first value tag. Decoding values means walking constructed
    types of arbitrary depth, which is the part most likely to be malformed and
    the part no rule asks about.
    """
    service = message.service or ''

    if service == 'ReinitializeDevice':
        state = _context_uint(reader, expect_tag=0)
        if state is not None:
            message.reinitialize_state = REINITIALIZE_STATES.get(state, str(state))
        return

    if service == 'DeviceCommunicationControl':
        # Tag 0 is an optional time duration, tag 1 the enable/disable choice.
        first = _context_uint(reader, expect_tag=None)
        second = _context_uint(reader, expect_tag=None)
        value = second if second is not None else first
        message.enable_disable = {0: 'enable', 1: 'disable',
                                  2: 'disable-initiation'}.get(value, value)
        return

    if service in ('ConfirmedPrivateTransfer', 'UnconfirmedPrivateTransfer'):
        vendor = _context_uint(reader, expect_tag=0)
        private = _context_uint(reader, expect_tag=1)
        message.vendor = vendor
        message.vendor_service = private
        known = KNOWN_PRIVATE_TRANSFERS.get((vendor, private))
        if known:
            message.object = known
        return

    if service in ('Who-Is', 'I-Am', 'Who-Has', 'I-Have'):
        return                                # discovery carries no object id

    identifier = _context_object_id(reader)
    if identifier is not None:
        message.object = identifier
    prop = _context_uint(reader, expect_tag=1)
    if prop is not None:
        message.property = PROPERTY_IDENTIFIERS.get(prop, f'property-{prop}')


def _context_object_id(reader):
    """Read a context-tagged BACnetObjectIdentifier, if that is what is next."""
    tag = reader.peek()
    if tag is None:
        return None
    # Context tag 0, length 4: the object identifier in every service that has
    # one. A different tag means this service does not lead with an object.
    if tag != 0x0C:
        return None
    reader.u8()
    raw = reader.u32()
    if raw is None:
        return None
    type_number = raw >> 22
    instance = raw & 0x3FFFFF
    name = OBJECT_TYPES.get(type_number, f'object-type-{type_number}')
    return f'{name}-{instance}'


def _context_uint(reader, expect_tag=None):
    """
    Read a context-tagged unsigned integer of 1-4 bytes.

    Returns None without consuming anything if the next tag is not a context tag
    of the expected number, so a caller can try several shapes in order.
    """
    tag = reader.peek()
    if tag is None:
        return None
    if not tag & 0x08:                       # not context-specific
        return None
    number = tag >> 4
    length = tag & 0x07
    if expect_tag is not None and number != expect_tag:
        return None
    if not 1 <= length <= 4:                 # extended lengths are not integers
        return None

    start = reader.pos
    reader.u8()
    raw = reader.take(length)
    if raw is None:
        reader.pos = start
        return None
    return int.from_bytes(raw, 'big')
