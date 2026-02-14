# Helper utilities for Akita Zmodem logic that do not depend on Reticulum
import crcmod

# Akita Zmodem constants (subset required for helpers)
AKITA_APP_NAME = "akita_zmodem"
AKITA_ZPAD = b'*'
AKITA_ZDLE = b'\x18'
AKITA_ZDLEE = b'\x58'
AKITA_ZHEX = b'h'
AKITA_ZBIN = b'B'
AKITA_ZBIN32_MARKER = b'C'

# Zmodem Frame Types (subset)
AKITA_ZRQINIT = 0
AKITA_ZRINIT = 1
AKITA_ZACK = 3
AKITA_ZFILE = 4
AKITA_ZSKIP = 5
AKITA_ZNAK = 6
AKITA_ZABORT = 7
AKITA_ZFIN = 8
AKITA_ZRPOS = 9
AKITA_ZDATA = 10
AKITA_ZEOF = 11
AKITA_ZFERR = 12
AKITA_ZCAN = 16
AKITA_NO_TYPE = 255

# ZDLE sequences
AKITA_ZCRCE = b'h'
AKITA_ZCRCG = b'i'
AKITA_ZCRCQ = b'j'
AKITA_ZCRCW = b'k'

# Flags
AKITA_CANFC32 = 0x20

# Length constants
ZMODEM_HEADER_LENGTH_BIN = 10
ZMODEM_SUBPACKET_DATA_PREFIX_LEN = 2
ZMODEM_SUBPACKET_DATA_SUFFIX_LEN = 4
CRC32_LEN = 4

# CRC functions
crc16_func = crcmod.predefined.mkCrcFun('crc-ccitt-false')
crc32_func = crcmod.predefined.mkCrcFun('crc-32')


def zmodem_escape(data_bytes, esc_ctl=True, esc_8=False):
    """ZDLE-escapes data following Zmodem conventions.

    - Always escapes ZDLE (0x18) -> ZDLE ZDLEE.
    - If esc_ctl is True (default) escapes control characters (< 0x20 and 0x7F)
      by encoding them as ZDLE + (byte ^ 0x40).
    - If esc_8 is True also escapes high-bit bytes (>= 0x80) using the same
      XOR-0x40 transformation (not used by default).
    """
    escaped = bytearray()
    for b in data_bytes:
        if b == AKITA_ZDLE[0]:
            escaped.extend(AKITA_ZDLE)
            escaped.extend(AKITA_ZDLEE)
            continue
        if esc_ctl and (b < 0x20 or b == 0x7f):
            escaped.extend(AKITA_ZDLE)
            escaped.append(b ^ 0x40)
            continue
        if esc_8 and b >= 0x80:
            escaped.extend(AKITA_ZDLE)
            escaped.append((b ^ 0x40) & 0xff)
            continue
        escaped.append(b)
    return bytes(escaped)


def zmodem_unescape(escaped_data_bytes, esc_8=False):
    """Reverse ZDLE escaping produced by zmodem_escape.

    - ZDLE ZDLEE -> literal ZDLE
    - ZDLE <ch> where <ch> != ZDLEE -> original_byte = <ch> ^ 0x40
    """
    data = bytearray()
    i = 0
    while i < len(escaped_data_bytes):
        b = escaped_data_bytes[i]
        if b == AKITA_ZDLE[0]:
            i += 1
            if i >= len(escaped_data_bytes):
                # trailing ZDLE
                break
            nb = escaped_data_bytes[i]
            if nb == AKITA_ZDLEE[0]:
                data.append(AKITA_ZDLE[0])
            else:
                orig = nb ^ 0x40
                data.append(orig & 0xff)
        else:
            data.append(b)
        i += 1
    return bytes(data)


def build_zmodem_header(frame_type, data_val=0):
    """Build simplified Zmodem binary header with CRC16 (type + data_val little-endian).
    Header: ZPAD + ZDLE + ZBIN + type(1) + data_val(4) + crc16(2)
    """
    frame = AKITA_ZPAD + AKITA_ZDLE + AKITA_ZBIN
    header_content = bytes([frame_type]) + data_val.to_bytes(4, 'little', signed=False)
    frame += header_content
    crc = crc16_func(header_content)
    frame += crc.to_bytes(2, 'little')
    return bytes(frame)


def parse_zmodem_header(raw_packet):
    """Parse simplified Zmodem binary header. Returns (type, data_val, header_len_consumed)
    Returns (AKITA_NO_TYPE, 0, 0) on failure to parse or CRC mismatch.
    """
    if not raw_packet:
        return AKITA_NO_TYPE, 0, 0
    min_len_no_zpad = ZMODEM_HEADER_LENGTH_BIN - 1
    header_start_idx = 0
    if raw_packet[0] == AKITA_ZPAD[0]:
        if len(raw_packet) < ZMODEM_HEADER_LENGTH_BIN:
            return AKITA_NO_TYPE, 0, 0
        header_start_idx = 1
    elif len(raw_packet) < min_len_no_zpad:
        return AKITA_NO_TYPE, 0, 0
    if raw_packet[header_start_idx] != AKITA_ZDLE[0] or raw_packet[header_start_idx+1] != AKITA_ZBIN[0]:
        return AKITA_NO_TYPE, 0, 0
    content_start_idx = header_start_idx + 2
    if len(raw_packet) < content_start_idx + 5 + 2:
        return AKITA_NO_TYPE, 0, 0
    header_content = raw_packet[content_start_idx : content_start_idx + 5]
    crc_bytes = raw_packet[content_start_idx + 5 : content_start_idx + 7]
    if len(header_content) != 5 or len(crc_bytes) != 2:
        return AKITA_NO_TYPE, 0, 0
    received_crc = int.from_bytes(crc_bytes, 'little')
    calculated_crc = crc16_func(header_content)
    if received_crc != calculated_crc:
        return AKITA_NO_TYPE, 0, 0
    frame_type = header_content[0]
    data_val = int.from_bytes(header_content[1:5], 'little', signed=False)
    parsed_header_length = content_start_idx + 7
    return frame_type, data_val, parsed_header_length
