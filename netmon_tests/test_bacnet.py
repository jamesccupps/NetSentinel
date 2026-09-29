"""
BACnet/IP parsing.
==================
Packets are built by the helpers below rather than pasted as hex, so a test
says what it is testing. The builder is deliberately dumb — it writes the bytes
it is told to — which means it can also produce the malformed packets the parser
has to survive.

The parser runs against whatever arrives on a mirror port. Half this file is
about packets that are wrong: truncated by snap length, lying about their own
length, claiming routing addresses that are not there. None of them may raise,
and none may cause a read past the end of the buffer.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.protocols import bacnet  # noqa: E402
from netmon.protocols.bacnet import parse  # noqa: E402


# ─── Builders ────────────────────────────────────────────────────────────────

def bvlc(function, body=b''):
    """Wrap a body in a BVLC header with a correct length field."""
    length = 4 + len(body)
    return bytes([0x81, function]) + length.to_bytes(2, 'big') + body


def npdu(control=0x04, destination=None, source=None, hop_count=255):
    """
    The network layer. `destination`/`source` are (network, address-bytes).

    Control bit 0x20 means a destination follows, 0x08 a source. Both are
    variable-length with the length in the packet, which is the part a careless
    parser walks off the end of.
    """
    out = bytearray([0x01])
    if destination is not None:
        control |= 0x20
    if source is not None:
        control |= 0x08
    out.append(control)
    if destination is not None:
        network, address = destination
        out += network.to_bytes(2, 'big') + bytes([len(address)]) + address
    if source is not None:
        network, address = source
        out += network.to_bytes(2, 'big') + bytes([len(address)]) + address
    if destination is not None:
        out.append(hop_count)
    return bytes(out)


def context_uint(tag, value):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    return bytes([(tag << 4) | 0x08 | len(raw)]) + raw


def object_id(type_number, instance):
    raw = (type_number << 22) | instance
    return bytes([0x0C]) + raw.to_bytes(4, 'big')


def confirmed(service, parameters=b'', invoke_id=1):
    return bytes([0x00, 0x05, invoke_id, service]) + parameters


def unconfirmed(service, parameters=b''):
    return bytes([0x10, service]) + parameters


def write_property(object_type=2, instance=7, prop=85):
    """A WriteProperty to an object — the message the whole rule set is about."""
    return bvlc(0x0A, npdu() + confirmed(
        15, object_id(object_type, instance) + context_uint(1, prop)))


# ─── The service namespaces ──────────────────────────────────────────────────

class TestServiceNamespaces(unittest.TestCase):
    """
    The single easiest thing to get wrong. Confirmed and unconfirmed service
    choices are different tables; treating them as one reports every device
    discovery as a list modification.
    """

    def test_service_eight_means_two_different_things(self):
        self.assertEqual(bacnet.CONFIRMED_SERVICES[8], 'AddListElement')
        self.assertEqual(bacnet.UNCONFIRMED_SERVICES[8], 'Who-Is')

    def test_a_confirmed_request_uses_the_confirmed_table(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(8)))
        self.assertEqual(message.service, 'AddListElement')

    def test_an_unconfirmed_request_uses_the_unconfirmed_table(self):
        message = parse(bvlc(0x0B, npdu() + unconfirmed(8)))
        self.assertEqual(message.service, 'Who-Is')

    def test_who_is_is_not_treated_as_a_write(self):
        """It is the most common message on any BACnet network."""
        self.assertFalse(parse(bvlc(0x0B, npdu() + unconfirmed(8))).is_write)

    def test_add_list_element_is_a_write(self):
        self.assertTrue(parse(bvlc(0x0A, npdu() + confirmed(8))).is_write)

    def test_an_unknown_service_is_named_not_dropped(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(200)))
        self.assertEqual(message.service, 'confirmed-200')
        self.assertFalse(message.is_write)


# ─── Commands ────────────────────────────────────────────────────────────────

class TestCommands(unittest.TestCase):

    def test_write_property(self):
        message = parse(write_property())
        self.assertEqual(message.service, 'WriteProperty')
        self.assertEqual(message.object, 'analog-value-7')
        self.assertEqual(message.property, 'present-value')
        self.assertTrue(message.is_write)

    def test_every_object_type_that_matters_is_named(self):
        for number, name in ((0, 'analog-input'), (4, 'binary-output'),
                             (8, 'device'), (17, 'schedule'), (30, 'access-door'),
                             (59, 'lift')):
            with self.subTest(name=name):
                message = parse(write_property(object_type=number, instance=3))
                self.assertEqual(message.object, f'{name}-3')

    def test_an_unknown_object_type_is_numbered_not_dropped(self):
        message = parse(write_property(object_type=900, instance=1))
        self.assertEqual(message.object, 'object-type-900-1')

    def test_a_large_instance_number_survives_the_bit_split(self):
        """Instance is 22 bits; the type is the top 10."""
        message = parse(write_property(object_type=2, instance=4_194_303))
        self.assertEqual(message.object, 'analog-value-4194303')

    def test_read_property_is_not_a_write(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(12, object_id(2, 7))))
        self.assertEqual(message.service, 'ReadProperty')
        self.assertFalse(message.is_write)

    def test_reinitialize_device_reports_which_kind(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(20, context_uint(0, 0))))
        self.assertEqual(message.service, 'ReinitializeDevice')
        self.assertEqual(message.reinitialize_state, 'coldstart')
        self.assertTrue(message.is_write)

    def test_device_communication_control_reports_enable_or_disable(self):
        """
        Worse than a setpoint change, not milder: it silences a controller, and
        needs to know nothing about the site to do it.
        """
        message = parse(bvlc(0x0A, npdu() + confirmed(17, context_uint(1, 1))))
        self.assertEqual(message.service, 'DeviceCommunicationControl')
        self.assertEqual(message.enable_disable, 'disable')
        self.assertTrue(message.is_write)

    def test_atomic_write_file_is_a_write(self):
        self.assertTrue(parse(bvlc(0x0A, npdu() + confirmed(7))).is_write)

    def test_atomic_read_file_is_not(self):
        self.assertFalse(parse(bvlc(0x0A, npdu() + confirmed(6))).is_write)

    def test_a_private_transfer_reports_its_vendor_and_service(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(
            18, context_uint(0, 7) + context_uint(1, 511))))
        self.assertEqual(message.vendor, 7)
        self.assertEqual(message.vendor_service, 511)

    def test_a_recognised_private_transfer_is_named(self):
        """So it reads as the site's own automation traffic, not a mystery."""
        message = parse(bvlc(0x0A, npdu() + confirmed(
            18, context_uint(0, 7) + context_uint(1, 511))))
        self.assertEqual(message.object, 'siemens-p2-transfer')

    def test_an_unrecognised_private_transfer_is_not_invented(self):
        message = parse(bvlc(0x0A, npdu() + confirmed(
            18, context_uint(0, 99) + context_uint(1, 1))))
        self.assertIsNone(message.object)
        self.assertEqual(message.vendor, 99)


class TestAcknowledgements(unittest.TestCase):

    def test_a_simple_ack_names_the_service_it_answers(self):
        """
        A SimpleACK to WriteProperty is proof the write was accepted, not
        merely attempted — which is the difference between an attack that
        worked and one that did not.
        """
        message = parse(bvlc(0x0A, npdu() + bytes([0x20, 0x01, 15])))
        self.assertEqual(message.apdu_type, 'SimpleACK')
        self.assertEqual(message.service, 'WriteProperty')

    def test_an_error_carries_its_invoke_id(self):
        message = parse(bvlc(0x0A, npdu() + bytes([0x50, 0x07, 0x00, 0x00])))
        self.assertEqual(message.apdu_type, 'Error')
        self.assertEqual(message.invoke_id, 7)


# ─── Topology ────────────────────────────────────────────────────────────────

class TestTopology(unittest.TestCase):
    """
    Whoever controls the broadcast distribution table controls which controllers
    hear which messages — a quieter and more durable foothold than writing a
    setpoint.
    """

    def test_writing_the_broadcast_table(self):
        message = parse(bvlc(0x01, bytes(10)))
        self.assertEqual(message.bvlc_function, 'WriteBroadcastDistributionTable')
        self.assertTrue(message.is_topology)

    def test_registering_as_a_foreign_device(self):
        message = parse(bvlc(0x05, (300).to_bytes(2, 'big')))
        self.assertEqual(message.bvlc_function, 'RegisterForeignDevice')
        self.assertTrue(message.is_topology)

    def test_deleting_a_foreign_device_entry(self):
        self.assertTrue(parse(bvlc(0x08, bytes(6))).is_topology)

    def test_a_forwarded_npdu_reports_where_it_came_from(self):
        """
        The origin address is in the BVLC header, not the IP header. A forwarded
        message naming a peer that does not exist is how a broken or hostile
        BBMD shows up.
        """
        body = bytes([192, 168, 0, 7]) + (47808).to_bytes(2, 'big')
        message = parse(bvlc(0x04, body + npdu() + unconfirmed(8)))
        self.assertEqual(message.peer, '192.168.0.7:47808')
        self.assertEqual(message.service, 'Who-Is')
        self.assertTrue(message.is_topology)

    def test_an_ordinary_message_is_not_topology(self):
        self.assertFalse(parse(write_property()).is_topology)

    def test_a_broadcast_is_recognised(self):
        self.assertTrue(parse(bvlc(0x0B, npdu() + unconfirmed(8))).is_broadcast)
        self.assertFalse(parse(write_property()).is_broadcast)

    def test_a_network_layer_message_is_reported(self):
        """Router announcements reshape the network as surely as a BBMD write."""
        message = parse(bvlc(0x0A, bytes([0x01, 0x80, 0x01])))
        self.assertEqual(message.service, 'network-message-0x01')


# ─── Routing ─────────────────────────────────────────────────────────────────

class TestNpduRouting(unittest.TestCase):

    def test_a_destination_network_is_read(self):
        message = parse(bvlc(0x0A, npdu(destination=(5, b'\x01'))
                             + unconfirmed(8)))
        self.assertEqual(message.network, 5)
        self.assertEqual(message.service, 'Who-Is')

    def test_a_source_network_is_read(self):
        message = parse(bvlc(0x0A, npdu(source=(9, b'\x02\x03'))
                             + unconfirmed(8)))
        self.assertEqual(message.network, 9)

    def test_both_together_still_reach_the_service(self):
        """
        Four variable-length fields before the APDU. Getting any of their
        lengths wrong lands mid-packet and reports a different service.
        """
        message = parse(bvlc(0x0A, npdu(destination=(5, b'\x01\x02\x03'),
                                        source=(9, b'\x04\x05'))
                             + confirmed(15, object_id(2, 7))))
        self.assertEqual(message.service, 'WriteProperty')
        self.assertEqual(message.object, 'analog-value-7')

    def test_a_zero_length_address_is_handled(self):
        """Length 0 means a broadcast on that network, and is legal."""
        message = parse(bvlc(0x0A, npdu(destination=(0xFFFF, b''))
                             + unconfirmed(8)))
        self.assertEqual(message.network, 0xFFFF)
        self.assertEqual(message.service, 'Who-Is')


# ─── Malformed input ─────────────────────────────────────────────────────────

class TestMalformedPackets(unittest.TestCase):
    """
    Everything here arrives on a mirror port from a device nobody controls.
    Nothing may raise, and nothing may read past the end of the buffer.
    """

    def test_empty_and_short(self):
        for payload in (b'', b'\x81', b'\x81\x0a', b'\x81\x0a\x00'):
            with self.subTest(payload=payload):
                self.assertIsNone(parse(payload))

    def test_not_bacnet(self):
        self.assertIsNone(parse(b'GET / HTTP/1.1\r\n\r\n'))
        self.assertIsNone(parse(bytes(64)))

    def test_truncated_at_every_offset_of_a_real_packet(self):
        """Snap length cuts packets at an arbitrary byte. All of them."""
        full = write_property()
        for cut in range(len(full) + 1):
            with self.subTest(cut=cut):
                parse(full[:cut])          # must not raise

    def test_a_truncated_packet_still_reports_what_it_had(self):
        full = write_property()
        # Cut after the service choice but before the object identifier.
        message = parse(full[:12])
        self.assertEqual(message.service, 'WriteProperty')
        self.assertTrue(message.is_write)
        self.assertIsNone(message.object)

    def test_truncation_is_flagged(self):
        message = parse(write_property()[:12])
        self.assertTrue(message.truncated)

    def test_a_length_field_that_lies_is_noted_not_trusted(self):
        """Captures are truncated by snap length far more often than by attack."""
        packet = bytearray(write_property())
        packet[2:4] = (9999).to_bytes(2, 'big')
        message = parse(bytes(packet))
        self.assertTrue(message.truncated)
        self.assertEqual(message.service, 'WriteProperty')

    def test_an_npdu_claiming_an_address_that_is_not_there(self):
        """The length byte says 200; there are two bytes left."""
        packet = bvlc(0x0A, bytes([0x01, 0x20, 0x00, 0x05, 200, 0x01, 0x02]))
        message = parse(packet)
        self.assertTrue(message.truncated)
        self.assertIsNone(message.service)

    def test_a_control_byte_promising_everything_with_nothing_after_it(self):
        message = parse(bvlc(0x0A, bytes([0x01, 0xFF])))
        self.assertTrue(message.truncated)

    def test_random_bytes_after_a_valid_header_never_raise(self):
        import random
        rng = random.Random(20260929)
        for _ in range(500):
            body = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
            parse(bvlc(0x0A, body))
            parse(bvlc(rng.randrange(16), body))

    def test_every_single_byte_mutation_of_a_real_packet_is_survivable(self):
        full = bytearray(write_property())
        for index in range(len(full)):
            for value in (0x00, 0x7F, 0x80, 0xFF):
                mutated = bytearray(full)
                mutated[index] = value
                with self.subTest(index=index, value=value):
                    parse(bytes(mutated))     # must not raise

    def test_a_context_tag_with_an_extended_length_does_not_confuse_it(self):
        """Length 5 in the tag means 'extended', not five bytes."""
        packet = bvlc(0x0A, npdu() + bytes([0x00, 0x05, 0x01, 15, 0x1D, 0xFF]))
        message = parse(packet)
        self.assertEqual(message.service, 'WriteProperty')
        self.assertIsNone(message.property)


# ─── What a rule sees ────────────────────────────────────────────────────────

class TestEventFields(unittest.TestCase):

    def test_the_fields_a_rule_matches_on(self):
        fields = parse(write_property()).as_fields()
        self.assertEqual(fields['service'], 'WriteProperty')
        self.assertEqual(fields['object'], 'analog-value-7')
        self.assertTrue(fields['bacnet_write'])

    def test_empty_fields_are_left_out(self):
        """So `exists` in a rule means what it says."""
        fields = parse(bvlc(0x0B, npdu() + unconfirmed(8))).as_fields()
        self.assertNotIn('object', fields)
        self.assertNotIn('peer', fields)

    def test_the_write_flag_matches_the_service_table(self):
        for number, name in bacnet.CONFIRMED_SERVICES.items():
            with self.subTest(service=name):
                message = parse(bvlc(0x0A, npdu() + confirmed(number)))
                self.assertEqual(message.is_write, name in bacnet.WRITE_SERVICES)

    def test_no_unconfirmed_discovery_service_counts_as_a_write(self):
        """Who-Is, I-Am and Who-Has are most of the traffic on these networks."""
        for name in ('Who-Is', 'I-Am', 'Who-Has', 'I-Have'):
            number = next(k for k, v in bacnet.UNCONFIRMED_SERVICES.items()
                          if v == name)
            with self.subTest(service=name):
                self.assertFalse(
                    parse(bvlc(0x0B, npdu() + unconfirmed(number))).is_write)


if __name__ == '__main__':
    unittest.main(verbosity=2)
