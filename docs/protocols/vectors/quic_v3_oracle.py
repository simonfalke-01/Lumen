#!/usr/bin/env python3
"""Independent deterministic oracle for the Umbra/Lumen QUIC v3 wire contract.

The oracle imports no Lumen or Umbra production code.  It covers the v3
authentication transcripts, the plaintext ULM3 semantic envelope, routing,
and hard bounds.  QUIC supplies confidentiality, integrity, replay protection,
key updates, and path validation; this file intentionally contains no
application AEAD or key schedule.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "quic_v3_vectors.json"
DOMAIN_PAIR_CLIENT = b"lumen/3 pair client\0"
DOMAIN_PAIR_HOST = b"lumen/3 pair host\0"
DOMAIN_AUTH_CLIENT = b"lumen/3 auth client\0"
DOMAIN_AUTH_HOST = b"lumen/3 auth host\0"
ENVELOPE_SIZE = 44
MAX_CONTROL_PAYLOAD = 1_048_576
INITIAL_MAX_SEMANTIC_DATAGRAM = 1_152
MAX_SEMANTIC_PAYLOAD = INITIAL_MAX_SEMANTIC_DATAGRAM - ENVELOPE_SIZE
MAX_VIDEO_FRAME = 67_108_864
MAX_VIDEO_FRAGMENTS = 65_535
VIDEO_FLAGS = 0x3F
INVITATION_HEADER_SIZE = 172
BULK_HEADER_SIZE = 64
CLIENT_INPUT_CAPABILITIES = 0x17F
COMPACT_INPUT_CAPABILITY = 0x200
SERVER_INPUT_CAPABILITIES = CLIENT_INPUT_CAPABILITIES | COMPACT_INPUT_CAPABILITY
INPUT_STATE_HEADER_SIZE = 112
INPUT_EDGE_SIZE = 32
INPUT_TOUCH_SIZE = 32
INPUT_PEN_SIZE = 40
INPUT_CONTROLLER_SIZE = {2: 64, 3: 56}


def _head(major: int, value: int) -> bytes:
    if not (0 <= major <= 7 and 0 <= value < 2**64):
        raise ValueError("CBOR head out of range")
    prefix = major << 5
    if value < 24:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + struct.pack(">I", value)
    return bytes((prefix | 27,)) + struct.pack(">Q", value)


def cbor(value, depth: int = 0) -> bytes:
    """Encode the restricted deterministic-CBOR subset used by control."""
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int) and value >= 0:
        return _head(0, value)
    if isinstance(value, int):
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        if len(value) > 1_048_576:
            raise ValueError("CBOR byte-string limit")
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) > 65_535:
            raise ValueError("CBOR text limit")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        if depth >= 8 or len(value) > 4096:
            raise ValueError("CBOR array limit")
        return _head(4, len(value)) + b"".join(cbor(item, depth + 1) for item in value)
    if isinstance(value, dict):
        if (
            depth >= 8
            or len(value) > 128
            or any(not isinstance(key, int) or key < 0 for key in value)
        ):
            raise ValueError("CBOR map limit")
        items = [
            (cbor(key, depth + 1), cbor(item, depth + 1)) for key, item in value.items()
        ]
        items.sort(key=lambda pair: pair[0])
        return _head(5, len(items)) + b"".join(key + item for key, item in items)
    raise TypeError(type(value))


def decode_head(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """Decode one shortest-form CBOR head."""
    if offset >= len(data):
        raise ValueError("truncated CBOR head")
    initial = data[offset]
    offset += 1
    major, additional = initial >> 5, initial & 31
    if additional < 24:
        return major, additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional not in widths:
        raise ValueError("reserved/indefinite CBOR head")
    width = widths[additional]
    if offset + width > len(data):
        raise ValueError("truncated CBOR argument")
    value = int.from_bytes(data[offset : offset + width], "big")
    minimum = {24: 24, 25: 256, 26: 65_536, 27: 2**32}[additional]
    if value < minimum:
        raise ValueError("non-deterministic CBOR argument")
    return major, value, offset + width


def decode_cbor(data: bytes, offset: int = 0, depth: int = 0):
    """Strictly decode the complete restricted deterministic-CBOR subset."""
    major, value, position = decode_head(data, offset)
    if major == 0:
        return value, position
    if major == 1:
        return -1 - value, position
    if major in (2, 3):
        limit = 1_048_576 if major == 2 else 65_535
        if value > limit:
            raise ValueError("CBOR string limit")
        if position + value > len(data):
            raise ValueError("truncated CBOR string")
        raw = data[position : position + value]
        try:
            decoded = raw if major == 2 else raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("invalid UTF-8") from error
        return decoded, position + value
    if major == 4:
        if depth >= 8 or value > 4096:
            raise ValueError("CBOR array limit")
        result = []
        for _ in range(value):
            item, position = decode_cbor(data, position, depth + 1)
            result.append(item)
        return result, position
    if major == 5:
        if depth >= 8 or value > 128:
            raise ValueError("CBOR map limit")
        result = {}
        previous = None
        for _ in range(value):
            key_start = position
            key, position = decode_cbor(data, position, depth + 1)
            encoded_key = data[key_start:position]
            if not isinstance(key, int) or key < 0:
                raise ValueError("control map key")
            if previous is not None and encoded_key <= previous:
                raise ValueError("duplicate/non-deterministic map key")
            previous = encoded_key
            item, position = decode_cbor(data, position, depth + 1)
            result[key] = item
        return result, position
    if major == 7 and value in (20, 21, 22):
        return {20: False, 21: True, 22: None}[value], position
    raise ValueError("unsupported CBOR type")


EVENT_TYPES = {0x0132, 0x0133, 0x0200}


def validate_control(frame: bytes, direction: str) -> dict:
    """Validate exact ULC3 header, issuer namespace, and deterministic payload."""
    if len(frame) < 24 or frame[:4] != b"ULC3" or frame[4] != 3:
        raise ValueError("control prefix")
    flags = frame[5]
    if flags & ~0x07:
        raise ValueError("control flags")
    message_type, request_id, payload_length = struct.unpack(">HQL", frame[6:20])
    if frame[20:24] != bytes(4):
        raise ValueError("control reserved")
    if payload_length > MAX_CONTROL_PAYLOAD or len(frame) != 24 + payload_length:
        raise ValueError("control length")
    response, error = bool(flags & 1), bool(flags & 2)
    if error and not response:
        raise ValueError("control error without response")
    if request_id == 0:
        if response or error or message_type not in EVENT_TYPES:
            raise ValueError("control event/request id")
    else:
        expected_parity = (
            1
            if (direction == "c2h" and not response)
            or (direction == "h2c" and response)
            else 0
        )
        if request_id & 1 != expected_parity:
            raise ValueError("control issuer parity")
    value, end = decode_cbor(frame, 24)
    if end != len(frame) or not isinstance(value, dict) or cbor(value) != frame[24:]:
        raise ValueError("control deterministic CBOR")
    return value


def control(message_type: int, request_id: int, payload, flags: int = 0) -> bytes:
    encoded = payload if isinstance(payload, bytes) else cbor(payload)
    if len(encoded) > MAX_CONTROL_PAYLOAD:
        raise ValueError("control payload limit")
    return (
        b"ULC3"
        + bytes((3, flags))
        + struct.pack(">HQL", message_type, request_id, len(encoded))
        + bytes(4)
        + encoded
    )


def transcript(domain: bytes, spki_hash: bytes, *frames: bytes) -> bytes:
    """Length-prefix every complete frame so concatenations are unambiguous."""
    if len(spki_hash) != 32:
        raise ValueError("SPKI hash length")
    return (
        domain
        + spki_hash
        + b"".join(struct.pack(">I", len(frame)) + frame for frame in frames)
    )


def envelope(
    session_id: bytes,
    channel: int,
    kind: int,
    flags: int,
    sequence: int,
    object_id: int,
    payload: bytes,
) -> bytes:
    if len(session_id) != 16 or session_id == bytes(16):
        raise ValueError("session id")
    if not (0 <= channel <= 255 and 0 <= kind <= 255 and 0 <= flags <= 255):
        raise ValueError("one-byte semantic field")
    if not (0 <= sequence < 2**64 and 0 <= object_id < 2**64):
        raise ValueError("sequence/object")
    if len(payload) > 0xFFFF:
        raise ValueError("payload length")
    return (
        b"ULM3"
        + bytes((3, channel, kind, flags))
        + struct.pack(">HH", ENVELOPE_SIZE, len(payload))
        + session_id
        + struct.pack(">QQ", sequence, object_id)
        + payload
    )


ROUTES = {
    ("c2h", 1, 1): "input-state",
    ("h2c", 1, 2): "input-ack",
    ("h2c", 1, 3): "input-resync",
    ("h2c", 1, 4): "controller-feedback",
    ("h2c", 2, 1): "video-fragment",
    ("h2c", 2, 2): "video-repair",
    ("c2h", 2, 3): "video-feedback",
    ("h2c", 3, 1): "audio",
    ("c2h", 4, 1): "microphone",
    ("h2c", 5, 1): "transport-telemetry",
}


def validate_input_state(state: bytes, state_format: int) -> None:
    """Validate the shared state-format-2/3 block independently of product code."""
    if (
        state_format not in INPUT_CONTROLLER_SIZE
        or len(state) < INPUT_STATE_HEADER_SIZE
    ):
        raise ValueError("input-state format/header")
    flags, mouse_buttons = struct.unpack(">II", state[:8])
    absolute, relative = bool(flags & 1), bool(flags & 2)
    if flags & ~0x07 or absolute == relative or mouse_buttons & ~0x1F:
        raise ValueError("input-state flags")
    if relative and state[40:48] != bytes(8):
        raise ValueError("input-state relative pointer")
    if absolute and state[8:24] != bytes(16):
        raise ValueError("input-state absolute pointer")
    marker = state[87]
    if marker != (3 if state_format == 3 else 0):
        raise ValueError("input-state marker/format mismatch")
    reserved_start = 88 if state_format == 3 else 87
    if state[reserved_start:INPUT_STATE_HEADER_SIZE] != bytes(
        INPUT_STATE_HEADER_SIZE - reserved_start
    ):
        raise ValueError("input-state header reserved")

    controller_count, touch_count, pen_count = state[84:87]
    if controller_count > 16 or touch_count > 16 or pen_count > 4:
        raise ValueError("input-state record count")
    controller_size = INPUT_CONTROLLER_SIZE[state_format]
    expected = (
        INPUT_STATE_HEADER_SIZE
        + controller_count * controller_size
        + touch_count * INPUT_TOUCH_SIZE
        + pen_count * INPUT_PEN_SIZE
    )
    if len(state) != expected:
        raise ValueError("input-state block length")

    expected_mask = 0
    previous_controller = -1
    for index in range(controller_count):
        offset = INPUT_STATE_HEADER_SIZE + index * controller_size
        semantic = state[offset : offset + 56]
        (
            controller_id,
            controller_type,
            capabilities,
            buttons,
            _left_trigger,
            _right_trigger,
            _left_x,
            _left_y,
            _right_x,
            _right_y,
            _gyro_x,
            _gyro_y,
            _gyro_z,
            _accel_x,
            _accel_y,
            _accel_z,
            battery,
            battery_state,
            reserved,
            supported_buttons,
        ) = struct.unpack(">BBHQHHhhhhiiiiiiHBBI", semantic)
        if (
            controller_id > 15
            or controller_id <= previous_controller
            or not 1 <= controller_type <= 5
            or capabilities & ~0x01FF
            or buttons & ~0x003FFFFF
            or (battery != 0xFFFF and battery > 10_000)
            or battery_state > 5
            or reserved != 0
            or supported_buttons & ~0x003FFFFF
        ):
            raise ValueError("input-state controller")
        if state_format == 2 and state[offset + 56 : offset + 64] != bytes(8):
            raise ValueError("input-state format-2 controller reserved")
        previous_controller = controller_id
        expected_mask |= 1 << controller_id
    if int.from_bytes(state[80:84], "big") != expected_mask:
        raise ValueError("input-state controller mask")

    touch_start = INPUT_STATE_HEADER_SIZE + controller_count * controller_size
    touch_ids = set()
    for index in range(touch_count):
        offset = touch_start + index * INPUT_TOUCH_SIZE
        pointer_id = int.from_bytes(state[offset : offset + 4], "big")
        event_type, contact_flags = state[offset + 4 : offset + 6]
        rotation = int.from_bytes(state[offset + 20 : offset + 22], "big", signed=True)
        if (
            pointer_id in touch_ids
            or event_type not in (1, 2, 3)
            or contact_flags & ~1
            or not -18_000 <= rotation <= 18_000
            or state[offset + 22 : offset + 24] != bytes(2)
            or state[offset + 28 : offset + 32] != bytes(4)
        ):
            raise ValueError("input-state touch")
        touch_ids.add(pointer_id)


def validate_payload(
    route: str, payload: bytes, flags: int, sequence: int, object_id: int
) -> None:
    """Validate the exact phase-one kind-specific binary prefix and bounds."""
    if len(payload) > MAX_SEMANTIC_PAYLOAD:
        raise ValueError("semantic payload limit")
    if route == "input-state":
        if len(payload) < 32:
            raise ValueError("input-state prefix")
        _, _, state_length, edge_count, state_format, edge_format, reserved = (
            struct.unpack(">QQHHHHQ", payload[:32])
        )
        if (
            state_format not in INPUT_CONTROLLER_SIZE
            or edge_format != 2
            or edge_count > 64
            or reserved != 0
        ):
            raise ValueError("input-state fields")
        if (
            state_length < INPUT_STATE_HEADER_SIZE
            or len(payload) != 32 + state_length + INPUT_EDGE_SIZE * edge_count
        ):
            raise ValueError("input-state length")
        validate_input_state(payload[32 : 32 + state_length], state_format)
        newest_edge = struct.unpack(">Q", payload[8:16])[0]
        previous_edge = None
        for index in range(edge_count):
            offset = 32 + state_length + index * INPUT_EDGE_SIZE
            edge_id, _, kind, device, _, _, _, edge_reserved = struct.unpack(
                ">QQBBHiII", payload[offset : offset + INPUT_EDGE_SIZE]
            )
            if (
                edge_id == 0
                or (previous_edge is not None and edge_id != previous_edge + 1)
                or kind not in (1, 2, 3, 4, 5, 6)
                or (kind in (3, 4) and device >= 16)
                or edge_reserved != 0
            ):
                raise ValueError("input-state edge")
            previous_edge = edge_id
        if previous_edge is not None and newest_edge != previous_edge:
            raise ValueError("input-state newest edge")
        if object_id == 0:
            raise ValueError("input state sequence")
    elif route == "input-ack":
        if len(payload) != 48 or struct.unpack(">Q", payload[40:48])[0] != 0:
            raise ValueError("input-ack layout")
    elif route == "input-resync":
        if len(payload) != 16 or payload[8] not in (1, 2, 3) or payload[9:] != bytes(7):
            raise ValueError("input-resync layout")
    elif route == "controller-feedback":
        if len(payload) != 40:
            raise ValueError("controller-feedback length")
        input_generation, controller_generation, controller, command, value_length = (
            struct.unpack(">IIBBH", payload[:12])
        )
        if (
            input_generation == 0
            or object_id != input_generation
            or controller_generation == 0
            or controller >= 16
            or command not in (1, 2, 3, 4, 5)
            or payload[36:] != bytes(4)
        ):
            raise ValueError("controller-feedback generation/route")
        expected_length = {1: 4, 2: 4, 3: 4, 4: 3, 5: 24}[command]
        if value_length != expected_length or payload[12 + value_length : 36] != bytes(
            24 - value_length
        ):
            raise ValueError("controller-feedback value/reserved")
        if command == 3:
            motion_type, reserved, report_rate = struct.unpack(">BBH", payload[12:16])
            if motion_type not in (1, 2) or reserved != 0 or report_rate > 2_000:
                raise ValueError("controller-feedback motion")
        if command == 5 and (payload[12] & ~0x0C or payload[15] != 0):
            raise ValueError("controller-feedback adaptive")
    elif route in ("video-fragment", "video-repair"):
        if len(payload) <= 64:
            raise ValueError("video payload length")
        fields = struct.unpack(">QIIQQIIHHHHHBBBBBBI4s", payload[:64])
        frame_size, offset, index, count = fields[5], fields[6], fields[7], fields[8]
        slice_index, slice_count = fields[9], fields[10]
        fec_group, fec_index, fec_data, fec_parity = fields[11:15]
        config_generation, reserved = fields[18], fields[19]
        if not (
            1 <= frame_size <= MAX_VIDEO_FRAME and 1 <= count <= MAX_VIDEO_FRAGMENTS
        ):
            raise ValueError("video frame bounds")
        if (
            index >= count
            or offset >= frame_size
            or slice_index != 0
            or slice_count != 0
        ):
            raise ValueError("video fragment fields")
        if config_generation == 0 or reserved != bytes(4):
            raise ValueError("video generation/reserved")
        if route == "video-fragment":
            if flags & 0x02:
                raise ValueError("ULM3 video config flag reserved")
            if any((fec_group, fec_index, fec_data, fec_parity)):
                raise ValueError("phase-one FEC fields")
            extent = offset + len(payload) - 64
            if extent > frame_size:
                raise ValueError("video fragment extent")
            is_final = bool(flags & 0x04)
            if is_final != (index == count - 1) or (is_final and extent != frame_size):
                raise ValueError("video final invariant")
        if route == "video-repair" and not (flags & 0x08):
            raise ValueError("video repair flag")
    elif route == "video-feedback":
        if len(payload) < 32:
            raise ValueError("video-feedback prefix")
        _, _, action, range_count, reserved, _, deadline_miss, tail = struct.unpack(
            ">QQBBBBI8s", payload[:32]
        )
        if (
            action not in (1, 2, 3, 4, 5)
            or range_count > 16
            or reserved != 0
            or deadline_miss > 1_000_000
            or (action not in (1, 3) and deadline_miss != 0)
            or tail != bytes(8)
        ):
            raise ValueError("video-feedback fields")
        if len(payload) != 32 + 4 * range_count or (action == 2) != (range_count > 0):
            raise ValueError("video-feedback ranges")
        previous_end = 0
        for index in range(range_count):
            first, count = struct.unpack(
                ">HH", payload[32 + 4 * index : 36 + 4 * index]
            )
            if count == 0 or (index and first < previous_end):
                raise ValueError("video-feedback range order/overlap")
            previous_end = first + count
    elif route in ("audio", "microphone"):
        if len(payload) < 48:
            raise ValueError("audio prefix")
        fields = struct.unpack(">QQIHBBBBBB8sI8s", payload[:48])
        sample_position, generation, frame_samples = fields[1], fields[2], fields[3]
        channels, codec, payload_flags = fields[4], fields[6], fields[7]
        reserved = fields[12]
        if object_id != sample_position or generation == 0:
            raise ValueError("audio generation/object")
        if codec != 1 or channels == 0 or frame_samples not in (120, 240, 480, 960):
            raise ValueError("audio tuple")
        if payload_flags & ~0x07 or reserved != bytes(8):
            raise ValueError("audio flags/reserved")
        if payload_flags & 0x05 and len(payload) != 48:
            raise ValueError("audio empty payload flag")
    elif route == "transport-telemetry":
        if len(payload) != 24:
            raise ValueError("transport-telemetry length")
        generation, smoothed_rtt, minimum_rtt, variation, reserved = struct.unpack(
            ">QIIII", payload
        )
        if (
            generation == 0
            or generation != sequence
            or generation != object_id
            or not 1 <= smoothed_rtt <= 1_000_000
            or not 1 <= minimum_rtt <= smoothed_rtt
            or variation > 1_000_000
            or reserved != 0
        ):
            raise ValueError("transport-telemetry generation/fields")


def validate_envelope(
    record: bytes,
    direction: str,
    expected_session: bytes,
    maximum: int,
) -> tuple:
    if len(record) < ENVELOPE_SIZE:
        raise ValueError("truncated envelope")
    if len(record) > maximum:
        raise ValueError("negotiated datagram limit")
    if record[:4] != b"ULM3" or record[4] != 3:
        raise ValueError("magic/version")
    channel, kind, flags = record[5:8]
    header_length, payload_length = struct.unpack(">HH", record[8:12])
    if header_length != ENVELOPE_SIZE:
        raise ValueError("header length")
    if flags & ~VIDEO_FLAGS:
        raise ValueError("reserved flags")
    session_id = record[12:28]
    if session_id != expected_session or session_id == bytes(16):
        raise ValueError("session routing")
    sequence, object_id = struct.unpack(">QQ", record[28:44])
    if sequence == 0:
        raise ValueError("semantic sequence starts at one")
    if payload_length != len(record) - ENVELOPE_SIZE:
        raise ValueError("payload length")
    route = ROUTES.get((direction, channel, kind))
    if route is None:
        raise ValueError("direction/channel/kind")
    if channel != 2 and flags != 0:
        raise ValueError("flags on non-video channel")
    if (channel, kind) == (2, 3) and flags != 0:
        raise ValueError("flags on feedback")
    if (channel, kind) == (2, 2):
        raise ValueError("phase-one FEC disabled")
    if (channel, kind) == (2, 1) and flags & 0x08:
        raise ValueError("repair flag on data")
    payload = record[ENVELOPE_SIZE:]
    validate_payload(route, payload, flags, sequence, object_id)
    return route, sequence, object_id, payload


def invitation(
    invitation_id: bytes,
    token: bytes,
    host_id: bytes,
    spki_hash: bytes,
    host_public: bytes,
    hostname: bytes,
) -> bytes:
    """Encode deterministic ULI3 invitation bytes."""
    if not (
        len(invitation_id) == 16
        and len(token) == 32
        and len(host_id) == 16
        and len(spki_hash) == 32
        and len(host_public) == 32
        and 1 <= len(hostname) <= 253
    ):
        raise ValueError("invitation field length")
    total = INVITATION_HEADER_SIZE + len(hostname)
    return (
        b"ULI3"
        + bytes((1, 0))
        + struct.pack(">HHHHH", INVITATION_HEADER_SIZE, total, 48_030, 3, 3)
        + invitation_id
        + token
        + host_id
        + spki_hash
        + host_public
        + struct.pack(
            ">QQQHH",
            1_700_000_000,
            1_700_000_300,
            SERVER_INPUT_CAPABILITIES,
            len(hostname),
            0,
        )
        + hostname
    )


def bulk_header(kind: int, request_id: int, object_id: int, payload: bytes) -> bytes:
    """Encode the exact per-object reliable unidirectional stream header."""
    return (
        b"ULB3"
        + bytes((3, kind))
        + bytes(2)
        + struct.pack(">QQQ", request_id, object_id, len(payload))
        + hashlib.sha256(payload).digest()
    )


def validate_invitation(data: bytes, stored_digest: bytes) -> tuple[bytes, bytes]:
    """Validate exact ULI3 framing, normalized hostname, and stored integrity."""
    if len(data) < INVITATION_HEADER_SIZE or data[:4] != b"ULI3" or data[4] != 1:
        raise ValueError("invitation prefix")
    if data[5] & ~1:
        raise ValueError("invitation flags")
    header_length, total, port, minimum, maximum = struct.unpack(">HHHHH", data[6:16])
    hostname_length, reserved = struct.unpack(">HH", data[168:172])
    if header_length != INVITATION_HEADER_SIZE or total != len(data):
        raise ValueError("invitation length")
    if port == 0 or minimum != 3 or maximum != 3 or reserved != 0:
        raise ValueError("invitation fixed fields")
    if (
        not (1 <= hostname_length <= 253)
        or total != INVITATION_HEADER_SIZE + hostname_length
    ):
        raise ValueError("invitation hostname length")
    hostname = data[172:]
    try:
        hostname_text = hostname.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("invitation hostname ASCII") from error
    if (
        hostname_text != hostname_text.lower()
        or hostname_text.endswith(".")
        or "\0" in hostname_text
    ):
        raise ValueError("invitation hostname normalized")
    if hashlib.sha256(data).digest() != stored_digest:
        raise ValueError("complete invitation digest mismatch")
    return data[64:80], data[112:144]


def validate_bulk(header: bytes, payload: bytes, direction: str) -> tuple[int, int]:
    """Validate exact ULB3 registry, bounds, payload length, and digest."""
    if len(header) != BULK_HEADER_SIZE or header[:4] != b"ULB3" or header[4] != 3:
        raise ValueError("bulk prefix/length")
    kind = header[5]
    flags = int.from_bytes(header[6:8], "big")
    request_id, object_id, payload_length = struct.unpack(">QQQ", header[8:32])
    if direction != "h2c" or kind != 1 or flags != 0:
        raise ValueError("bulk registry")
    limit = 16 * 1024 * 1024
    if request_id == 0 or payload_length != len(payload) or payload_length > limit:
        raise ValueError("bulk object bounds")
    if hashlib.sha256(payload).digest() != header[32:64]:
        raise ValueError("bulk SHA-256 mismatch")
    return kind, object_id


def _hex(value: bytes) -> str:
    return value.hex()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact(category: str, value: bytes) -> dict:
    return {"category": category, "hex": _hex(value), "sha256": _digest(value)}


def input_controller(controller_id: int, state_format: int, variant: int = 0) -> bytes:
    """Build one heterogeneous controller record with identical semantic bytes 0...55."""
    if not 0 <= controller_id < 16 or state_format not in INPUT_CONTROLLER_SIZE:
        raise ValueError("input controller arguments")
    controller_type = 1 + (controller_id + variant) % 5
    capabilities = 1 << ((controller_id + variant) % 9)
    buttons = 1 << ((controller_id * 3 + variant) % 22)
    supported_buttons = 1 << ((controller_id * 5 + variant) % 22)
    semantic = struct.pack(
        ">BBHQHHhhhhiiiiiiHBBI",
        controller_id,
        controller_type,
        capabilities,
        buttons,
        0x1000 + controller_id,
        0x2000 + controller_id,
        -1000 - controller_id,
        1000 + controller_id,
        -2000 - controller_id,
        2000 + controller_id,
        0x00010000 + controller_id,
        -0x00010000 - controller_id,
        0x00008000 + controller_id,
        0x00020000 + controller_id,
        -0x00008000 - controller_id,
        0x00004000 + controller_id,
        0xFFFF if controller_id % 2 else 5_000 + controller_id,
        controller_id % 6,
        0,
        supported_buttons,
    )
    if len(semantic) != 56:
        raise AssertionError("controller semantic record size")
    return semantic + (bytes(8) if state_format == 2 else b"")


def input_touch(pointer_id: int, event_type: int = 1) -> bytes:
    """Build one valid 32-byte dirty-touch state record."""
    return struct.pack(
        ">IBBHIIHHHHII",
        pointer_id,
        event_type,
        1,
        0x8000,
        0x40000000,
        0xC0000000,
        10,
        8,
        0,
        0,
        0,
        0,
    )


def input_state_block(
    state_format: int,
    controller_ids: tuple[int, ...],
    touch_ids: tuple[int, ...] = (),
    *,
    initial: bool = True,
    controller_variant: int = 0,
) -> bytes:
    """Build the exact common header plus format-specific controller/touch records."""
    if state_format not in INPUT_CONTROLLER_SIZE:
        raise ValueError("input state format")
    if tuple(sorted(set(controller_ids))) != controller_ids or len(controller_ids) > 16:
        raise ValueError("input controller order/count")
    flags = 2 | (4 if initial else 0)
    controller_mask = sum(1 << controller_id for controller_id in controller_ids)
    state = (
        struct.pack(">IIqqqqII", flags, 0, 0, 0, 0, 0, 0, 0)
        + bytes(32)
        + struct.pack(
            ">IBBBB",
            controller_mask,
            len(controller_ids),
            len(touch_ids),
            0,
            3 if state_format == 3 else 0,
        )
        + bytes(24)
        + b"".join(
            input_controller(controller_id, state_format, controller_variant)
            for controller_id in controller_ids
        )
        + b"".join(input_touch(pointer_id) for pointer_id in touch_ids)
    )
    validate_input_state(state, state_format)
    return state


def input_edge(
    edge_id: int,
    *,
    kind: int = 1,
    device: int = 0,
    code: int = 4,
    value: int = 1,
    auxiliary: int = 0,
) -> bytes:
    """Build one exact edge-format-2 record."""
    return struct.pack(
        ">QQBBHiII",
        edge_id,
        2_000_000 + edge_id,
        kind,
        device,
        code,
        value,
        auxiliary,
        0,
    )


def input_state_payload(
    state_format: int,
    state: bytes,
    edges: tuple[bytes, ...] = (),
    *,
    sample_time: int = 2_000_000,
    last_acknowledged_edge: int = 0,
) -> bytes:
    """Build one input wrapper whose edges are the largest contiguous represented prefix."""
    newest_edge = (
        int.from_bytes(edges[-1][:8], "big") if edges else last_acknowledged_edge
    )
    payload = (
        struct.pack(
            ">QQHHHHQ",
            sample_time,
            newest_edge,
            len(state),
            len(edges),
            state_format,
            2,
            0,
        )
        + state
        + b"".join(edges)
    )
    return payload


def build_fixture() -> dict:
    client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    host_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    client_public = client_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    host_public = host_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_id = hashlib.sha256(client_public).digest()[:16]
    host_id = hashlib.sha256(host_public).digest()[:16]
    spki_hash = bytes(range(0x80, 0xA0))
    session_id = bytes(range(0xC0, 0xD0))
    pair_client_nonce = hashlib.sha256(b"quic-v3-pair-client-nonce").digest()
    pair_host_nonce = hashlib.sha256(b"quic-v3-pair-host-nonce").digest()
    auth_client_nonce = hashlib.sha256(b"quic-v3-auth-client-nonce").digest()
    auth_host_nonce = hashlib.sha256(b"quic-v3-auth-host-nonce").digest()
    if (
        len({pair_client_nonce, pair_host_nonce, auth_client_nonce, auth_host_nonce})
        != 4
    ):
        raise AssertionError("deterministic nonce collision")
    invitation_id = bytes(range(16))
    invitation_token = bytes(range(0xA0, 0xC0))
    pair_attempt_id = hashlib.sha256(b"quic-v3-pair-attempt").digest()[:16]
    connection_attempt_id = hashlib.sha256(b"quic-v3-connection-attempt").digest()[:16]
    start_intent_id = hashlib.sha256(b"quic-v3-start-intent").digest()[:16]
    attach_intent_id = hashlib.sha256(b"quic-v3-attach-intent").digest()[:16]
    trace_id = hashlib.sha256(b"quic-v3-trace").digest()[:16]
    hostname = b"vector.example"
    invitation_bytes = invitation(
        invitation_id, invitation_token, host_id, spki_hash, host_public, hostname
    )
    invitation_hash = hashlib.sha256(invitation_bytes).digest()
    invitation_uri = (
        "umbra://pair/v3#"
        + base64.urlsafe_b64encode(invitation_bytes).rstrip(b"=").decode("ascii")
    ).encode("ascii")

    client_hello = control(
        0x0001,
        1,
        {
            1: 3,
            2: 3,
            3: pair_client_nonce,
            4: CLIENT_INPUT_CAPABILITIES,
            5: [1, 2],
            6: None,
            7: invitation_id,
            8: pair_attempt_id,
        },
    )
    server_hello = control(
        0x0002,
        1,
        {
            1: 3,
            2: pair_host_nonce,
            3: host_id,
            4: host_public,
            5: spki_hash,
            6: SERVER_INPUT_CAPABILITIES,
            7: INITIAL_MAX_SEMANTIC_DATAGRAM,
            8: pair_attempt_id,
        },
        flags=1,
    )
    pair_fields = {
        1: invitation_id,
        2: invitation_token,
        3: invitation_hash,
        4: pair_attempt_id,
        5: client_id,
        6: client_public,
        7: "Umbra QUIC Vector",
        8: 0x17,
    }
    pair_unsigned = control(0x0010, 3, pair_fields)
    pair_message = transcript(
        DOMAIN_PAIR_CLIENT, spki_hash, client_hello, server_hello, pair_unsigned
    )
    pair_signature = client_key.sign(pair_message)
    pair_request = control(0x0010, 3, {**pair_fields, 9: pair_signature})
    pair_response_fields = {
        1: 0,
        2: host_id,
        3: host_public,
        4: client_id,
        5: 0x17,
        6: 3,
        7: pair_attempt_id,
        8: 1,
    }
    pair_response_unsigned = control(0x0011, 3, pair_response_fields, flags=1)
    pair_response_message = transcript(
        DOMAIN_PAIR_HOST,
        spki_hash,
        client_hello,
        server_hello,
        pair_request,
        pair_response_unsigned,
    )
    pair_response_signature = host_key.sign(pair_response_message)
    pair_response = control(
        0x0011, 3, {**pair_response_fields, 9: pair_response_signature}, flags=1
    )
    recovery_client_nonce = hashlib.sha256(
        b"quic-v3-pair-recovery-client-nonce"
    ).digest()
    recovery_host_nonce = hashlib.sha256(b"quic-v3-pair-recovery-host-nonce").digest()
    recovery_client_hello = control(
        0x0001,
        1,
        {
            1: 3,
            2: 3,
            3: recovery_client_nonce,
            4: CLIENT_INPUT_CAPABILITIES,
            5: [1, 2],
            6: None,
            7: invitation_id,
            8: pair_attempt_id,
        },
    )
    recovery_server_hello = control(
        0x0002,
        1,
        {
            1: 3,
            2: recovery_host_nonce,
            3: host_id,
            4: host_public,
            5: spki_hash,
            6: SERVER_INPUT_CAPABILITIES,
            7: INITIAL_MAX_SEMANTIC_DATAGRAM,
            8: pair_attempt_id,
        },
        flags=1,
    )
    recovery_pair_message = transcript(
        DOMAIN_PAIR_CLIENT,
        spki_hash,
        recovery_client_hello,
        recovery_server_hello,
        pair_unsigned,
    )
    recovery_pair_signature = client_key.sign(recovery_pair_message)
    recovery_pair_request = control(
        0x0010, 3, {**pair_fields, 9: recovery_pair_signature}
    )
    recovery_pair_response_message = transcript(
        DOMAIN_PAIR_HOST,
        spki_hash,
        recovery_client_hello,
        recovery_server_hello,
        recovery_pair_request,
        pair_response_unsigned,
    )
    recovery_pair_response_signature = host_key.sign(recovery_pair_response_message)
    recovery_pair_response = control(
        0x0011,
        3,
        {**pair_response_fields, 9: recovery_pair_response_signature},
        flags=1,
    )

    auth_client_hello = control(
        0x0001,
        1,
        {
            1: 3,
            2: 3,
            3: auth_client_nonce,
            4: CLIENT_INPUT_CAPABILITIES,
            5: [1, 2],
            6: client_id,
            7: None,
            8: connection_attempt_id,
        },
    )
    auth_server_hello = control(
        0x0002,
        1,
        {
            1: 3,
            2: auth_host_nonce,
            3: host_id,
            4: host_public,
            5: spki_hash,
            6: SERVER_INPUT_CAPABILITIES,
            7: INITIAL_MAX_SEMANTIC_DATAGRAM,
            8: connection_attempt_id,
        },
        flags=1,
    )
    auth_fields = {1: client_id, 2: connection_attempt_id, 3: True}
    auth_unsigned = control(0x0003, 3, auth_fields)
    auth_message = transcript(
        DOMAIN_AUTH_CLIENT,
        spki_hash,
        auth_client_hello,
        auth_server_hello,
        auth_unsigned,
    )
    auth_signature = client_key.sign(auth_message)
    auth_request = control(0x0003, 3, {**auth_fields, 4: auth_signature})
    auth_response_fields = {
        1: 0,
        2: client_id,
        3: 0x17,
        4: 7,
        5: None,
        6: connection_attempt_id,
    }
    auth_response_unsigned = control(0x0004, 3, auth_response_fields, flags=1)
    auth_response_message = transcript(
        DOMAIN_AUTH_HOST,
        spki_hash,
        auth_client_hello,
        auth_server_hello,
        auth_request,
        auth_response_unsigned,
    )
    auth_response_signature = host_key.sign(auth_response_message)
    auth_response = control(
        0x0004, 3, {**auth_response_fields, 7: auth_response_signature}, flags=1
    )

    codec = {1: 3, 2: 1, 3: 10, 4: 3, 5: 9, 6: 16, 7: 0, 8: 1, 9: 2, 10: 3}
    hdr_offer = {
        1: 2,
        2: 9,
        3: 0,
        4: 1,
        5: 10,
        6: {
            1: True,
            2: 10_000_000,
            3: 1_000,
            4: 400,
        },
        7: [],
    }
    hdr_selected = {
        1: 2,
        2: 9,
        3: 0,
        4: 1,
        5: 10,
        6: {
            1: [34_000, 16_000, 13_250, 34_500, 7_500, 3_000],
            2: [15_635, 16_450],
            3: 10_000_000,
            4: 50,
            5: 1_000,
            6: 400,
        },
        7: [],
    }
    presentation = {1: 3, 2: 2, 3: True, 4: True, 5: 12_000}
    quality_requirements = {1: 3, 2: True, 3: True, 4: True, 5: True, 6: False}
    audio_tuple = {
        1: 1,
        2: 48_000,
        3: 2,
        4: 240,
        5: 1,
        6: 1,
        7: 1,
        8: b"\0\1",
        9: 96_000,
    }
    microphone_tuple = {
        1: 1,
        2: 48_000,
        3: 1,
        4: 960,
        5: 0,
        6: 1,
        7: 0,
        8: b"\0",
        9: 32_000,
    }
    start_request = control(
        0x0100,
        5,
        {
            1: start_intent_id,
            2: 1,
            3: 2,
            4: 1920,
            5: 1080,
            6: 240,
            7: 1,
            8: 80_000,
            9: [codec],
            10: [audio_tuple],
            11: microphone_tuple,
            12: INITIAL_MAX_SEMANTIC_DATAGRAM,
            13: trace_id,
            14: [hdr_offer],
            15: [presentation],
            16: False,
            17: quality_requirements,
            18: True,
        },
    )
    start_response = control(
        0x0101,
        5,
        {
            1: 0,
            2: start_intent_id,
            3: session_id,
            4: 2,
            5: codec,
            6: 1920,
            7: 1080,
            8: 240,
            9: 1,
            10: 80_000,
            11: INITIAL_MAX_SEMANTIC_DATAGRAM,
            12: audio_tuple,
            13: microphone_tuple,
            14: 1,
            15: 1,
            16: 1,
            17: 1,
            18: presentation,
            19: [],
            20: trace_id,
            21: bytes(range(0x20, 0x40)),
            22: 1,
            23: hdr_selected,
        },
        flags=1,
    )
    attach_request = control(
        0x0102,
        7,
        {
            1: session_id,
            2: bytes(range(0x20, 0x40)),
            3: attach_intent_id,
            4: 77,
            5: {1: 1, 2: 1, 3: 1},
        },
    )
    attach_response = control(
        0x0103,
        7,
        {1: 0, 2: session_id, 3: 7, 4: 8, 5: True, 6: {1: 1, 2: 1, 3: 1}},
        flags=1,
    )
    video_config = control(
        0x0140,
        2,
        {
            1: session_id,
            2: 1,
            3: codec,
            4: b"config",
            5: hdr_selected,
            6: 1920,
            7: 1080,
            8: 240,
            9: 1,
        },
    )
    video_config_ack = control(0x0141, 2, {1: 0, 2: session_id, 3: 1, 4: 1}, flags=1)
    audio_config = control(0x0142, 4, {1: session_id, 2: 1, 3: audio_tuple, 4: 48_000})
    audio_config_ack = control(0x0143, 4, {1: 0, 2: session_id, 3: 1}, flags=1)
    microphone_config = control(
        0x0144, 6, {1: session_id, 2: 1, 3: microphone_tuple, 4: 48_000}
    )
    microphone_config_ack = control(0x0145, 6, {1: 0, 2: session_id, 3: 1}, flags=1)
    telemetry = control(
        0x0200,
        0,
        {
            1: 2,
            2: session_id,
            3: trace_id,
            4: 1,
            5: 1,
            6: -12_000,
            7: 2_000,
            8: [{1: 10, 2: 9001, 3: 1_001_250_000, 4: 0, 5: 0}],
        },
    )
    stop_request = control(0x0130, 9, {1: session_id, 2: 0, 3: 1, 4: start_intent_id})
    stop_response = control(
        0x0131, 9, {1: 0, 2: session_id, 3: start_intent_id, 4: False}, flags=1
    )
    session_stopping = control(0x0132, 0, {1: session_id, 2: 1})
    session_ended = control(
        0x0133,
        0,
        {1: session_id, 2: 1, 3: 1_100_000, 4: False, 5: 9001, 6: 42, 7: 77, 8: 12},
    )

    controller_capabilities = 0x0179
    supported_buttons = 0x104000
    controller = struct.pack(
        ">BBHQHHhhhhiiiiiiHBBI",
        0,
        2,
        controller_capabilities,
        0x004000,
        0x2000,
        0x4000,
        -1000,
        1000,
        -2000,
        2000,
        0x00018000,
        -0x00008000,
        0x00004000,
        0x00010000,
        0x00020000,
        -0x00010000,
        7500,
        2,
        0,
        supported_buttons,
    ) + bytes(8)
    controller_touch = struct.pack(
        ">IBBHIIHHHHII",
        0x01000001,
        3,
        1,
        0x8000,
        0x40000000,
        0xC0000000,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    state_block = (
        struct.pack(">IIqqqqII", 6, 0, 0, 0, 0, 0, 0, 0)
        + bytes(32)
        + struct.pack(">IBBB", 1, 1, 1, 0)
        + bytes(25)
        + controller
        + controller_touch
    )
    arrival_edge = struct.pack(
        ">QQBBHiII",
        12,
        1_002_900,
        4,
        0,
        controller_capabilities,
        2,
        supported_buttons,
        0,
    )
    input_payload = (
        struct.pack(">QQHHHHQ", 1_003_000, 12, len(state_block), 1, 2, 2, 0)
        + state_block
        + arrival_edge
    )
    input_state = envelope(session_id, 1, 1, 0, 43, 77, input_payload)

    format2_15_state = input_state_block(2, tuple(range(15)))
    format2_15_payload = input_state_payload(2, format2_15_state)
    if len(format2_15_payload) != 1_104:
        raise AssertionError("format-2 15-controller boundary")
    format2_15 = envelope(session_id, 1, 1, 0, 54, 1, format2_15_payload)

    format3_16_state = input_state_block(3, tuple(range(16)))
    format3_16_payload = input_state_payload(3, format3_16_state)
    if len(format3_16_payload) != 1_040:
        raise AssertionError("format-3 16-controller compact boundary")
    format3_16 = envelope(session_id, 1, 1, 0, 55, 1, format3_16_payload)

    compact_edges = (input_edge(1), input_edge(2))
    format3_16_edges_payload = input_state_payload(3, format3_16_state, compact_edges)
    if len(format3_16_edges_payload) != 1_104:
        raise AssertionError("format-3 controller/edge boundary")
    format3_16_edges = envelope(session_id, 1, 1, 0, 56, 1, format3_16_edges_payload)

    format3_touch_state = input_state_block(
        3, tuple(range(16)), (0x01000001,), initial=False
    )
    format3_touch_payload = input_state_payload(
        3, format3_touch_state, last_acknowledged_edge=2
    )
    if len(format3_touch_payload) != 1_072:
        raise AssertionError("format-3 dirty-touch post-edge boundary")
    format3_touch = envelope(session_id, 1, 1, 0, 57, 2, format3_touch_payload)

    rebound_state = input_state_block(3, (0,), initial=False, controller_variant=1)
    rebound_arrival = input_edge(
        17,
        kind=4,
        device=0,
        code=0x0002,
        value=2,
        auxiliary=0x000002,
    )
    rebound_payload = input_state_payload(
        3, rebound_state, (rebound_arrival,), sample_time=2_100_000
    )
    rebound_state_record = envelope(session_id, 1, 1, 0, 58, 3, rebound_payload)
    rebound_feedback_payload = struct.pack(
        ">IIBBHBBH", 1, 2, 0, 3, 4, 2, 0, 100
    ) + bytes(24)
    rebound_feedback = envelope(session_id, 1, 4, 0, 59, 1, rebound_feedback_payload)

    input_ack_payload = struct.pack(">QQQQQQ", 1_003_200, 77, 12, 0, 9001, 0)
    input_ack = envelope(session_id, 1, 2, 0, 44, 77, input_ack_payload)
    input_resync_payload = struct.pack(">QB7x", 13, 1)
    input_resync = envelope(session_id, 1, 3, 0, 45, 77, input_resync_payload)
    controller_feedback_payload = struct.pack(
        ">IIBBHBBH", 1, 1, 0, 3, 4, 2, 0, 100
    ) + bytes(24)
    controller_feedback = envelope(
        session_id, 1, 4, 0, 46, 1, controller_feedback_payload
    )
    transport_telemetry_payload = struct.pack(">QIIII", 1, 4_000, 3_000, 1_000, 0)
    transport_telemetry = envelope(
        session_id, 5, 1, 0, 1, 1, transport_telemetry_payload
    )

    video_extension = struct.pack(
        ">QIIQQIIHHHHHBBBBBBI4s",
        1_000_000,
        200,
        1_250,
        77,
        12,
        64,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        3,
        9,
        10,
        1,
        bytes(4),
    )
    video = envelope(
        session_id, 2, 1, 0x05, 47, 9001, video_extension + bytes(range(64))
    )
    repair = envelope(
        session_id, 2, 2, 0x08, 48, 9001, video_extension + bytes(range(16))
    )
    feedback_payload = struct.pack(
        ">QQBBBBI8s", 9000, 9000, 2, 1, 0, 0, 0, bytes(8)
    ) + struct.pack(">HH", 0, 1)
    video_feedback = envelope(session_id, 2, 3, 0, 49, 9001, feedback_payload)

    audio_extension = struct.pack(
        ">QQIHBBBBBB8sI8s",
        1_002_000,
        48_096,
        1,
        240,
        2,
        1,
        1,
        0,
        1,
        1,
        b"\0\1" + bytes([255]) * 6,
        96_000,
        bytes(8),
    )
    audio = envelope(session_id, 3, 1, 0, 50, 48_096, audio_extension + b"opus")
    mic_extension = struct.pack(
        ">QQIHBBBBBB8sI8s",
        1_004_000,
        48_192,
        1,
        960,
        1,
        0,
        1,
        0,
        1,
        0,
        b"\0" + bytes([255]) * 7,
        32_000,
        bytes(8),
    )
    microphone = envelope(session_id, 4, 1, 0, 50, 48_192, mic_extension + b"mic")

    asset_payload = b"PNG"
    asset_bulk_header = bulk_header(1, 11, 1, asset_payload)
    invited_host_id, invited_host_public = validate_invitation(
        invitation_bytes, invitation_hash
    )
    if invited_host_id != host_id or invited_host_public != host_public:
        raise AssertionError("invited host identity mismatch")
    if validate_bulk(asset_bulk_header, asset_payload, "h2c") != (1, 1):
        raise AssertionError("bulk positive route mismatch")

    artifacts = {
        "client_hello": _artifact("control", client_hello),
        "invitation_bytes": _artifact("invitation", invitation_bytes),
        "invitation_uri": _artifact("invitation", invitation_uri),
        "server_hello": _artifact("control", server_hello),
        "pair_unsigned": _artifact("control", pair_unsigned),
        "pair_transcript": _artifact("authentication", pair_message),
        "pair_signature": _artifact("authentication", pair_signature),
        "pair_request": _artifact("control", pair_request),
        "pair_response": _artifact("control", pair_response),
        "pair_recovery_client_hello": _artifact("lifecycle", recovery_client_hello),
        "pair_recovery_server_hello": _artifact("lifecycle", recovery_server_hello),
        "pair_recovery_request": _artifact("lifecycle", recovery_pair_request),
        "pair_recovery_response": _artifact("lifecycle", recovery_pair_response),
        "auth_client_hello": _artifact("control", auth_client_hello),
        "auth_server_hello": _artifact("control", auth_server_hello),
        "auth_transcript": _artifact("authentication", auth_message),
        "auth_signature": _artifact("authentication", auth_signature),
        "auth_request": _artifact("control", auth_request),
        "auth_response": _artifact("control", auth_response),
        "start_request": _artifact("lifecycle", start_request),
        "start_response": _artifact("lifecycle", start_response),
        "attach_request": _artifact("lifecycle", attach_request),
        "attach_response": _artifact("lifecycle", attach_response),
        "video_config": _artifact("lifecycle", video_config),
        "video_config_ack": _artifact("lifecycle", video_config_ack),
        "audio_config": _artifact("lifecycle", audio_config),
        "audio_config_ack": _artifact("lifecycle", audio_config_ack),
        "microphone_config": _artifact("lifecycle", microphone_config),
        "microphone_config_ack": _artifact("lifecycle", microphone_config_ack),
        "telemetry_batch": _artifact("telemetry", telemetry),
        "stop_request": _artifact("lifecycle", stop_request),
        "stop_response": _artifact("lifecycle", stop_response),
        "session_stopping": _artifact("lifecycle", session_stopping),
        "session_ended": _artifact("lifecycle", session_ended),
        "route_input_state": _artifact("route", input_state),
        "input_format2_compatibility": _artifact("input-contract", input_state),
        "input_format2_15_controllers_1104": _artifact("input-contract", format2_15),
        "input_format3_16_controllers_1040": _artifact("input-contract", format3_16),
        "input_format3_16_controllers_two_edges_1104": _artifact(
            "input-contract", format3_16_edges
        ),
        "input_format3_touch_after_edge_ack_1072": _artifact(
            "input-contract", format3_touch
        ),
        "input_format3_rebind_generation2": _artifact(
            "input-contract", rebound_state_record
        ),
        "controller_feedback_generation2": _artifact(
            "input-contract", rebound_feedback
        ),
        "route_input_ack": _artifact("route", input_ack),
        "route_input_resync": _artifact("route", input_resync),
        "route_controller_feedback": _artifact("route", controller_feedback),
        "route_video_fragment": _artifact("route", video),
        "route_video_repair_reserved": _artifact("route", repair),
        "route_video_feedback": _artifact("route", video_feedback),
        "route_audio": _artifact("route", audio),
        "route_microphone": _artifact("route", microphone),
        "route_transport_telemetry": _artifact("route", transport_telemetry),
        "bulk_asset_header": _artifact("bulk", asset_bulk_header),
        "bulk_asset_payload": _artifact("bulk", asset_payload),
    }

    control_records = (
        (client_hello, "c2h"),
        (server_hello, "h2c"),
        (pair_request, "c2h"),
        (pair_response, "h2c"),
        (recovery_client_hello, "c2h"),
        (recovery_server_hello, "h2c"),
        (recovery_pair_request, "c2h"),
        (recovery_pair_response, "h2c"),
        (auth_client_hello, "c2h"),
        (auth_server_hello, "h2c"),
        (auth_request, "c2h"),
        (auth_response, "h2c"),
        (start_request, "c2h"),
        (start_response, "h2c"),
        (attach_request, "c2h"),
        (attach_response, "h2c"),
        (video_config, "h2c"),
        (video_config_ack, "c2h"),
        (audio_config, "h2c"),
        (audio_config_ack, "c2h"),
        (microphone_config, "h2c"),
        (microphone_config_ack, "c2h"),
        (telemetry, "h2c"),
        (stop_request, "c2h"),
        (stop_response, "h2c"),
        (session_stopping, "h2c"),
        (session_ended, "h2c"),
    )
    for frame, direction in control_records:
        validate_control(frame, direction)

    hostile = []

    def auth_hostile(
        name: str,
        mutation: str,
        message: bytes,
        signature: bytes,
        public_key,
    ) -> None:
        rejected = False
        try:
            public_key.verify(signature, message)
        except InvalidSignature:
            rejected = True
        if not rejected:
            raise AssertionError(f"hostile authentication case accepted: {name}")
        hostile.append(
            {
                "name": name,
                "class": "authentication",
                "mutation": mutation,
                "candidate_hex": message.hex(),
                "context": {
                    "public_key_hex": public_key.public_bytes(
                        Encoding.Raw, PublicFormat.Raw
                    ).hex(),
                    "signature_hex": signature.hex(),
                    "tls_leaf_spki_sha256": spki_hash.hex(),
                },
                "expected": "reject",
                "reason": "invalid Ed25519 transcript signature",
            }
        )

    tampered_client_hello = bytearray(client_hello)
    tampered_client_hello[-1] ^= 1
    auth_hostile(
        "pair-tampered-complete-client-hello",
        "client hello byte",
        pair_message.replace(client_hello, bytes(tampered_client_hello), 1),
        pair_signature,
        client_key.public_key(),
    )
    mutated_host_nonce = bytearray(pair_host_nonce)
    mutated_host_nonce[7] ^= 1
    tampered_server_hello = server_hello.replace(
        pair_host_nonce, bytes(mutated_host_nonce), 1
    )
    auth_hostile(
        "pair-tampered-fresh-host-nonce-frame",
        "server hello byte",
        pair_message.replace(server_hello, bytes(tampered_server_hello), 1),
        pair_signature,
        client_key.public_key(),
    )
    wrong_spki = bytes(reversed(spki_hash))
    auth_hostile(
        "pair-wrong-tls-leaf-spki",
        "SPKI hash",
        transcript(
            DOMAIN_PAIR_CLIENT, wrong_spki, client_hello, server_hello, pair_unsigned
        ),
        pair_signature,
        client_key.public_key(),
    )
    auth_hostile(
        "pair-reordered-hello-frames",
        "frame order",
        transcript(
            DOMAIN_PAIR_CLIENT, spki_hash, server_hello, client_hello, pair_unsigned
        ),
        pair_signature,
        client_key.public_key(),
    )
    tampered_auth = bytearray(auth_unsigned)
    tampered_auth[-1] ^= 1
    auth_hostile(
        "auth-permission-escalation",
        "unsigned auth request",
        transcript(
            DOMAIN_AUTH_CLIENT,
            spki_hash,
            auth_client_hello,
            auth_server_hello,
            bytes(tampered_auth),
        ),
        auth_signature,
        client_key.public_key(),
    )
    tampered_pair_response_unsigned = bytearray(pair_response_unsigned)
    tampered_pair_response_unsigned[-1] ^= 1
    auth_hostile(
        "pair-host-response-tamper",
        "unsigned host response",
        transcript(
            DOMAIN_PAIR_HOST,
            spki_hash,
            client_hello,
            server_hello,
            pair_request,
            bytes(tampered_pair_response_unsigned),
        ),
        pair_response_signature,
        host_key.public_key(),
    )
    auth_hostile(
        "pair-host-domain-confusion",
        "host response domain",
        transcript(
            DOMAIN_AUTH_HOST,
            spki_hash,
            client_hello,
            server_hello,
            pair_request,
            pair_response_unsigned,
        ),
        pair_response_signature,
        host_key.public_key(),
    )
    auth_hostile(
        "pair-host-response-cross-connection-replay",
        "fresh recovery hello frames",
        recovery_pair_response_message,
        pair_response_signature,
        host_key.public_key(),
    )
    tampered_auth_response_unsigned = bytearray(auth_response_unsigned)
    tampered_auth_response_unsigned[-1] ^= 1
    auth_hostile(
        "auth-host-response-tamper",
        "unsigned auth response",
        transcript(
            DOMAIN_AUTH_HOST,
            spki_hash,
            auth_client_hello,
            auth_server_hello,
            auth_request,
            bytes(tampered_auth_response_unsigned),
        ),
        auth_response_signature,
        host_key.public_key(),
    )
    mutated_host_signature = bytearray(auth_response_signature)
    mutated_host_signature[0] ^= 1
    auth_hostile(
        "auth-host-signature-byte",
        "host signature",
        auth_response_message,
        bytes(mutated_host_signature),
        host_key.public_key(),
    )

    def control_hostile(name: str, candidate: bytes, direction: str) -> None:
        try:
            validate_control(candidate, direction)
        except ValueError as error:
            hostile.append(
                {
                    "name": name,
                    "class": "control-frame",
                    "candidate_hex": candidate.hex(),
                    "context": {"direction": direction},
                    "expected": "reject",
                    "reason": str(error),
                }
            )
        else:
            raise AssertionError(f"hostile control frame accepted: {name}")

    control_hostile(
        "control-reserved-flag",
        client_hello[:5] + bytes((client_hello[5] | 0x80,)) + client_hello[6:],
        "c2h",
    )
    control_hostile(
        "control-nonzero-reserved",
        client_hello[:20] + b"\x01" + client_hello[21:],
        "c2h",
    )
    control_hostile(
        "control-error-without-response",
        pair_request[:5] + b"\x02" + pair_request[6:],
        "c2h",
    )
    control_hostile(
        "control-response-zero-id",
        server_hello[:8] + bytes(8) + server_hello[16:],
        "h2c",
    )
    control_hostile(
        "control-request-zero-id",
        client_hello[:8] + bytes(8) + client_hello[16:],
        "c2h",
    )
    control_hostile(
        "control-wrong-issuer-parity",
        pair_request[:8] + struct.pack(">Q", 4) + pair_request[16:],
        "c2h",
    )
    control_hostile(
        "control-payload-length-mismatch",
        client_hello[:16]
        + struct.pack(">I", int.from_bytes(client_hello[16:20], "big") + 1)
        + client_hello[20:],
        "c2h",
    )
    nondeterministic_payload = bytes.fromhex("a1011817")
    nondeterministic_frame = (
        b"ULC3"
        + bytes((3, 0))
        + struct.pack(">HQI", 0x0500, 13, len(nondeterministic_payload))
        + bytes(4)
        + nondeterministic_payload
    )
    control_hostile("control-nondeterministic-cbor", nondeterministic_frame, "c2h")

    changed_invitation = bytearray(invitation_bytes)
    changed_invitation[-1] ^= 1
    try:
        validate_invitation(bytes(changed_invitation), invitation_hash)
    except ValueError as invitation_error:
        invitation_reason = str(invitation_error)
    else:
        raise AssertionError("hostile invitation accepted")
    hostile.append(
        {
            "name": "invitation-integrity-mutation",
            "class": "invitation",
            "candidate_hex": bytes(changed_invitation).hex(),
            "context": {"stored_invitation_sha256": invitation_hash.hex()},
            "expected": "reject",
            "reason": invitation_reason,
        }
    )
    wrong_host_key = bytes(reversed(host_public))
    if wrong_host_key == host_public:
        raise AssertionError("host-key hostile is not mutated")
    hostile.append(
        {
            "name": "server-hello-host-key-not-invited",
            "class": "invitation",
            "candidate_hex": wrong_host_key.hex(),
            "context": {"invited_host_ed25519": host_public.hex()},
            "expected": "reject",
            "reason": "host Ed25519 key differs from invitation",
        }
    )

    overlapping_feedback_payload = struct.pack(
        ">QQBBBBI8s", 9000, 9000, 2, 2, 0, 0, 500, bytes(8)
    ) + struct.pack(">HHHH", 0, 2, 1, 1)
    overlapping_feedback = envelope(
        session_id, 2, 3, 0, 51, 9001, overlapping_feedback_payload
    )
    input_format_one = input_state[:64] + struct.pack(">HH", 1, 1) + input_state[68:]
    format3_marker_two = bytearray(format3_16)
    format3_marker_two[ENVELOPE_SIZE + 32 + 87] = 0
    format2_marker_three = bytearray(format2_15)
    format2_marker_three[ENVELOPE_SIZE + 32 + 87] = 3
    input_edge_format_three = (
        input_state[: ENVELOPE_SIZE + 22]
        + struct.pack(">H", 3)
        + input_state[ENVELOPE_SIZE + 24 :]
    )
    format2_15_edge_payload = input_state_payload(2, format2_15_state, (input_edge(1),))
    format2_15_edge = envelope(session_id, 1, 1, 0, 60, 2, format2_15_edge_payload)
    format3_payload_1109 = envelope(
        session_id,
        1,
        1,
        0,
        61,
        2,
        format3_16_edges_payload + bytes(5),
    )
    format3_noncontiguous_edges = envelope(
        session_id,
        1,
        1,
        0,
        62,
        2,
        input_state_payload(3, format3_16_state, (input_edge(1), input_edge(3))),
    )
    format3_touch_before_edges = envelope(
        session_id,
        1,
        1,
        0,
        63,
        2,
        input_state_payload(3, format3_touch_state, compact_edges),
    )
    media_hostiles = {
        "truncated-envelope": (
            video[:43],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "wrong-magic": (
            b"BAD3" + video[4:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "wrong-version": (
            video[:4] + b"\x02" + video[5:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "wrong-header-length": (
            video[:8] + struct.pack(">H", 45) + video[10:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "wrong-session": (
            video,
            "h2c",
            bytes(range(16)),
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "payload-length-mismatch": (
            video[:10] + struct.pack(">H", len(video) - 43) + video[12:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "reserved-flags": (
            video[:7] + b"\x80" + video[8:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-in-wrong-direction": (
            video,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "audio-flags-forbidden": (
            audio[:7] + b"\x01" + audio[8:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "record-over-negotiated-limit": (video, "h2c", session_id, len(video) - 1),
        "semantic-sequence-zero": (
            video[:28] + bytes(8) + video[36:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "phase-one-video-repair": (
            repair,
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-config-flag-reserved": (
            video[:7] + bytes((video[7] | 0x02,)) + video[8:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-final-flag-missing": (
            video[:7] + bytes((video[7] & ~0x04,)) + video[8:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-feedback-overlap": (
            overlapping_feedback,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-feedback-deadline-over-bound": (
            video_feedback[:64] + struct.pack(">I", 1_000_001) + video_feedback[68:],
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "video-feedback-deadline-on-loss": (
            video_feedback[:64] + struct.pack(">I", 1) + video_feedback[68:],
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format-one-rejected": (
            input_format_one,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format3-wrapper-marker2": (
            bytes(format3_marker_two),
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format2-wrapper-marker3": (
            bytes(format2_marker_three),
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-edge-format3-rejected": (
            input_edge_format_three,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format2-15-plus-edge-1136": (
            format2_15_edge,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format3-payload-1109": (
            format3_payload_1109,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format3-noncontiguous-edge-prefix": (
            format3_noncontiguous_edges,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "input-format3-touch-before-edge-budget": (
            format3_touch_before_edges,
            "c2h",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "controller-feedback-stale-input-generation": (
            controller_feedback[:36] + struct.pack(">Q", 2) + controller_feedback[44:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "controller-feedback-reserved-tail": (
            controller_feedback[:60] + b"\x01" + controller_feedback[61:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "controller-feedback-command-length": (
            controller_feedback[:53] + b"\x05" + controller_feedback[54:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "transport-telemetry-generation-mismatch": (
            transport_telemetry[:36] + struct.pack(">Q", 2) + transport_telemetry[44:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "transport-telemetry-minimum-over-smoothed": (
            transport_telemetry[:56]
            + struct.pack(">I", 5_000)
            + transport_telemetry[60:],
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
        "transport-telemetry-reserved": (
            transport_telemetry[:-1] + b"\x01",
            "h2c",
            session_id,
            INITIAL_MAX_SEMANTIC_DATAGRAM,
        ),
    }
    for name, arguments in media_hostiles.items():
        try:
            validate_envelope(*arguments)
        except ValueError as error:
            record, direction, expected, maximum = arguments
            hostile.append(
                {
                    "name": name,
                    "class": "semantic-envelope",
                    "candidate_hex": record.hex(),
                    "context": {
                        "direction": direction,
                        "expected_session": expected.hex(),
                        "maximum": maximum,
                    },
                    "expected": "reject",
                    "reason": str(error),
                }
            )
        else:
            raise AssertionError(f"hostile media case accepted: {name}")

    for record, direction, route in (
        (input_state, "c2h", "input-state"),
        (input_ack, "h2c", "input-ack"),
        (input_resync, "h2c", "input-resync"),
        (controller_feedback, "h2c", "controller-feedback"),
        (video, "h2c", "video-fragment"),
        (video_feedback, "c2h", "video-feedback"),
        (audio, "h2c", "audio"),
        (microphone, "c2h", "microphone"),
        (transport_telemetry, "h2c", "transport-telemetry"),
    ):
        if (
            validate_envelope(
                record,
                direction,
                session_id,
                INITIAL_MAX_SEMANTIC_DATAGRAM,
            )[0]
            != route
        ):
            raise AssertionError(f"positive route mismatch: {route}")

    for record in (
        format2_15,
        format3_16,
        format3_16_edges,
        format3_touch,
        rebound_state_record,
    ):
        if (
            validate_envelope(record, "c2h", session_id, INITIAL_MAX_SEMANTIC_DATAGRAM)[
                0
            ]
            != "input-state"
        ):
            raise AssertionError("positive compact input vector mismatch")
    if (
        validate_envelope(
            rebound_feedback, "h2c", session_id, INITIAL_MAX_SEMANTIC_DATAGRAM
        )[0]
        != "controller-feedback"
    ):
        raise AssertionError("positive rebound feedback vector mismatch")

    client_key.public_key().verify(pair_signature, pair_message)
    host_key.public_key().verify(pair_response_signature, pair_response_message)
    client_key.public_key().verify(recovery_pair_signature, recovery_pair_message)
    host_key.public_key().verify(
        recovery_pair_response_signature, recovery_pair_response_message
    )
    client_key.public_key().verify(auth_signature, auth_message)
    host_key.public_key().verify(auth_response_signature, auth_response_message)

    routing = [
        {
            "direction": direction,
            "channel": channel,
            "kind": kind,
            "semantic": semantic,
            "registered": True,
            "phase_one_allowed": semantic != "video-repair",
        }
        for (direction, channel, kind), semantic in sorted(ROUTES.items())
    ]
    routing += [
        {
            "direction": "c2h",
            "channel": 3,
            "kind": 1,
            "semantic": None,
            "registered": False,
            "phase_one_allowed": False,
        },
        {
            "direction": "h2c",
            "channel": 4,
            "kind": 1,
            "semantic": None,
            "registered": False,
            "phase_one_allowed": False,
        },
        {
            "direction": "h2c",
            "channel": 2,
            "kind": 3,
            "semantic": None,
            "registered": False,
            "phase_one_allowed": False,
        },
        {
            "direction": "c2h",
            "channel": 1,
            "kind": 2,
            "semantic": None,
            "registered": False,
            "phase_one_allowed": False,
        },
    ]
    for entry in routing:
        if (
            not entry["registered"]
            and (entry["direction"], entry["channel"], entry["kind"]) in ROUTES
        ):
            raise AssertionError("negative route unexpectedly registered")

    invalid_bulk = bytearray(asset_bulk_header)
    invalid_bulk[-1] ^= 1
    try:
        validate_bulk(bytes(invalid_bulk), asset_payload, "h2c")
    except ValueError as bulk_error:
        bulk_reason = str(bulk_error)
    else:
        raise AssertionError("hostile bulk header accepted")
    hostile.append(
        {
            "name": "bulk-payload-digest-mismatch",
            "class": "bulk-stream",
            "candidate_hex": bytes(invalid_bulk).hex(),
            "context": {"payload_hex": asset_payload.hex(), "direction": "h2c"},
            "expected": "reject",
            "reason": bulk_reason,
        }
    )

    return {
        "schema": "umbra-lumen-quic-v3-vectors/1",
        "alpn": "lumen/3",
        "quic_0rtt": False,
        "application_aead": False,
        "envelope_size": ENVELOPE_SIZE,
        "bulk_header_size": BULK_HEADER_SIZE,
        "phase_one_fec": False,
        "constants": {
            "initial_max_semantic_datagram": INITIAL_MAX_SEMANTIC_DATAGRAM,
            "max_semantic_payload": MAX_SEMANTIC_PAYLOAD,
            "max_control_payload": MAX_CONTROL_PAYLOAD,
            "max_video_frame": MAX_VIDEO_FRAME,
            "max_video_fragments": MAX_VIDEO_FRAGMENTS,
            "client_input_capabilities": CLIENT_INPUT_CAPABILITIES,
            "compact_input_capability": COMPACT_INPUT_CAPABILITY,
            "server_input_capabilities": SERVER_INPUT_CAPABILITIES,
        },
        "input_contract": {
            "state_header_bytes": INPUT_STATE_HEADER_SIZE,
            "edge_format": 2,
            "edge_bytes": INPUT_EDGE_SIZE,
            "touch_bytes": INPUT_TOUCH_SIZE,
            "formats": {
                "2": {"marker_byte_87": 0, "controller_bytes": 64},
                "3": {"marker_byte_87": 3, "controller_bytes": 56},
            },
            "budget_order": [
                "all-active-controllers",
                "largest-contiguous-edge-prefix",
                "dirty-touch-updates",
            ],
            "negotiation": {
                "client_hello_capabilities": CLIENT_INPUT_CAPABILITIES,
                "old_server_capabilities": CLIENT_INPUT_CAPABILITIES,
                "new_server_capabilities": SERVER_INPUT_CAPABILITIES,
                "selected_format_without_0x200": 2,
                "selected_format_with_0x200": 3,
            },
            "cases": [
                {
                    "id": "format2-byte-compatible",
                    "artifact": "input_format2_compatibility",
                    "format": 2,
                    "expected": "accept",
                },
                {
                    "id": "format2-15-controller-boundary",
                    "artifact": "input_format2_15_controllers_1104",
                    "format": 2,
                    "controllers": 15,
                    "edges": 0,
                    "payload_bytes": 1_104,
                    "expected": "accept",
                },
                {
                    "id": "old-host-15-controller-pending-edge",
                    "format": 2,
                    "controllers": 15,
                    "edges": 1,
                    "would_be_payload_bytes": 1_136,
                    "emitted": False,
                    "state_sequence_advanced": False,
                    "outcome": "nonterminal-degradation",
                },
                {
                    "id": "format3-16-controller-compact",
                    "artifact": "input_format3_16_controllers_1040",
                    "format": 3,
                    "controllers": 16,
                    "edges": 0,
                    "payload_bytes": 1_040,
                    "expected": "accept",
                },
                {
                    "id": "format3-16-controller-two-edge-boundary",
                    "artifact": "input_format3_16_controllers_two_edges_1104",
                    "format": 3,
                    "controllers": 16,
                    "edges": 2,
                    "touches": 0,
                    "payload_bytes": 1_104,
                    "expected": "accept",
                },
                {
                    "id": "format3-touch-after-edge-ack",
                    "artifact": "input_format3_touch_after_edge_ack_1072",
                    "format": 3,
                    "controllers": 16,
                    "edges": 0,
                    "touches": 1,
                    "payload_bytes": 1_072,
                    "expected": "accept",
                },
                {
                    "id": "payload-1109",
                    "payload_bytes": 1_109,
                    "expected": "reject",
                },
            ],
            "generation_rebind": {
                "controller_id": 0,
                "first_generation": 1,
                "rebound_generation": 2,
                "stale_feedback_generation": 1,
                "accepted_feedback_generation": 2,
                "state_artifact": "input_format3_rebind_generation2",
                "feedback_artifact": "controller_feedback_generation2",
            },
        },
        "identities": {
            "client_public": _hex(client_public),
            "client_id": _hex(client_id),
            "host_public": _hex(host_public),
            "host_id": _hex(host_id),
            "tls_leaf_spki_sha256": _hex(spki_hash),
            "session_id": _hex(session_id),
        },
        "artifacts": artifacts,
        "routing": routing,
        "hostile": hostile,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the checked-in deterministic fixture",
    )
    parser.add_argument(
        "--dump", action="store_true", help="print the generated fixture"
    )
    args = parser.parse_args()
    generated = build_fixture()
    encoded = json.dumps(generated, indent=2, sort_keys=True) + "\n"
    if args.write:
        FIXTURE.write_text(encoded, encoding="utf-8")
    if args.dump:
        print(encoded, end="")
    if not FIXTURE.exists():
        raise SystemExit(f"missing fixture: {FIXTURE}")
    checked_in = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if checked_in != generated:
        raise SystemExit(
            "FAIL quic v3 fixture drift; inspect --dump and update intentionally with --write"
        )
    print(
        f"PASS {len(generated['artifacts'])} artifacts, "
        f"{len(generated['hostile'])} hostile cases, {len(generated['routing'])} routing cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
