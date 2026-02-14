import os
import random
from akita_zmodem_helpers import zmodem_escape, zmodem_unescape, build_zmodem_header, parse_zmodem_header, crc16_func, crc32_func, AKITA_ZDLE, AKITA_ZDLEE


def test_escape_unescape_roundtrip():
    samples = [b"hello world", b"\x18literalZDLE\x00\x01\x02", bytes(range(0,32)), bytes(range(0,256))[:128]]
    for s in samples:
        esc = zmodem_escape(s)
        unesc = zmodem_unescape(esc)
        assert unesc == s, f"Roundtrip mismatch for {s!r}: got {unesc!r}"


def test_build_and_parse_header_random():
    for _ in range(50):
        t = random.randint(0, 255)
        val = random.getrandbits(32)
        hdr = build_zmodem_header(t, val)
        ptype, pval, plen = parse_zmodem_header(hdr)
        assert ptype == t
        assert pval == val
        assert plen == len(hdr)


def test_header_crc_mismatch():
    t = 10
    v = 12345
    hdr = bytearray(build_zmodem_header(t, v))
    # Corrupt one byte in header content
    hdr[-1] ^= 0xff
    ptype, pval, plen = parse_zmodem_header(bytes(hdr))
    assert ptype == 255 and pval == 0 and plen == 0
