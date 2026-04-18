import threading

import akita_zmodem_rns as azr


class DummyLink:
    def __init__(self):
        self.status = azr.RNS.Link.ACTIVE
        self.teardown_calls = 0

    def teardown(self):
        self.teardown_calls += 1
        self.status = azr.RNS.Link.CLOSED


class DummyStdin:
    def __init__(self, interactive):
        self._interactive = interactive

    def isatty(self):
        return self._interactive


def build_zfile_packet(filename, size=16, mtime=0, mode=0o644):
    file_info = f"{filename}\0{size} {oct(mtime)} {oct(mode)}\0".encode("utf-8")
    return (
        azr.build_zmodem_header(azr.AKITA_ZFILE, 0)
        + azr.AKITA_ZDLE
        + azr.AKITA_ZBIN
        + azr.zmodem_escape(file_info)
        + azr.AKITA_ZDLE
        + azr.AKITA_ZCRCW
        + azr.crc16_func(file_info).to_bytes(2, "little")
    )


def test_sender_resends_same_chunk_after_znak(monkeypatch, tmp_path):
    payload = b"retry-this-chunk"
    send_file = tmp_path / "payload.bin"
    send_file.write_bytes(payload)

    sent_packets = []
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRINIT, azr.AKITA_CANFC32),
        azr.build_zmodem_header(azr.AKITA_ZRPOS, 0),
        azr.build_zmodem_header(azr.AKITA_ZNAK),
        azr.build_zmodem_header(azr.AKITA_ZACK, len(payload)),
        azr.build_zmodem_header(azr.AKITA_ZRINIT),
        azr.build_zmodem_header(azr.AKITA_ZFIN),
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "file_to_send_path", str(send_file))
    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "sender_last_acked_offset", 0)
    monkeypatch.setattr(azr, "current_file_offset", 0)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS.Link, "MDU", 256, raising=False)
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_sender_protocol()

    zdata_packets = [
        packet for packet in sent_packets
        if azr.parse_zmodem_header(packet)[0] == azr.AKITA_ZDATA
    ]

    assert len(zdata_packets) == 2
    assert zdata_packets[0] == zdata_packets[1]


def test_resolve_receive_conflict_overwrite_policy(monkeypatch):
    monkeypatch.setattr(azr, "receive_conflict_policy", "overwrite")
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    assert azr.resolve_receive_conflict("file.bin") == "overwrite"


def test_resolve_receive_conflict_skips_without_interactive_stdin(monkeypatch):
    monkeypatch.setattr(azr, "receive_conflict_policy", "prompt")
    monkeypatch.setattr(azr.sys, "stdin", DummyStdin(False))
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    assert azr.resolve_receive_conflict("file.bin") == "skip"


def test_sender_ignores_future_ack_offsets(monkeypatch, tmp_path):
    payload = b"future-ack-check"
    send_file = tmp_path / "payload.bin"
    send_file.write_bytes(payload)

    sent_packets = []
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRINIT, azr.AKITA_CANFC32),
        azr.build_zmodem_header(azr.AKITA_ZRPOS, 0),
        azr.build_zmodem_header(azr.AKITA_ZACK, len(payload) + 5),
        azr.build_zmodem_header(azr.AKITA_ZACK, len(payload)),
        azr.build_zmodem_header(azr.AKITA_ZRINIT),
        azr.build_zmodem_header(azr.AKITA_ZFIN),
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "file_to_send_path", str(send_file))
    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "sender_last_acked_offset", 0)
    monkeypatch.setattr(azr, "current_file_offset", 0)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS.Link, "MDU", 256, raising=False)
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_sender_protocol()

    zdata_packets = [
        packet for packet in sent_packets
        if azr.parse_zmodem_header(packet)[0] == azr.AKITA_ZDATA
    ]

    assert len(zdata_packets) == 1
    assert azr.sender_last_acked_offset == len(payload)


def test_receiver_rejects_empty_filename(monkeypatch, tmp_path):
    sent_packets = []
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRQINIT),
        build_zfile_packet(""),
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "receive_directory", str(tmp_path))
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_receiver_protocol()

    sent_types = [azr.parse_zmodem_header(packet)[0] for packet in sent_packets]
    assert sent_types[-1] == azr.AKITA_ZFERR


def test_receiver_skips_existing_file_when_policy_is_skip(monkeypatch, tmp_path):
    existing_file = tmp_path / "file.bin"
    existing_file.write_bytes(b"already-here")

    sent_packets = []
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRQINIT),
        build_zfile_packet("file.bin"),
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "receive_directory", str(tmp_path))
    monkeypatch.setattr(azr, "receive_conflict_policy", "skip")
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_receiver_protocol()

    sent_types = [azr.parse_zmodem_header(packet)[0] for packet in sent_packets]
    assert sent_types[-1] == azr.AKITA_ZSKIP
    assert existing_file.read_bytes() == b"already-here"


def test_receiver_waits_for_zEOF_before_final_handshake(monkeypatch, tmp_path):
    sent_packets = []
    data_payload = b"abc123"
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRQINIT),
        build_zfile_packet("file.bin", size=len(data_payload)),
        azr.build_zmodem_header(azr.AKITA_ZDATA, 0) + data_payload + azr.crc32_func(data_payload).to_bytes(4, "little"),
        azr.build_zmodem_header(azr.AKITA_ZEOF, len(data_payload)),
        azr.build_zmodem_header(azr.AKITA_ZFIN),
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "receive_directory", str(tmp_path))
    monkeypatch.setattr(azr, "receive_conflict_policy", "overwrite")
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_receiver_protocol()

    sent_types = [azr.parse_zmodem_header(packet)[0] for packet in sent_packets]
    assert azr.AKITA_ZACK in sent_types
    assert azr.AKITA_ZRINIT in sent_types
    assert sent_types[-1] == azr.AKITA_ZFIN


def test_receiver_aborts_after_repeated_resync_failures(monkeypatch, tmp_path):
    sent_packets = []
    peer_packets = iter([
        azr.build_zmodem_header(azr.AKITA_ZRQINIT),
        build_zfile_packet("file.bin"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ])

    def fake_link_send(link, data):
        sent_packets.append(data)
        return True

    monkeypatch.setattr(azr, "target_link", DummyLink())
    monkeypatch.setattr(azr, "receive_directory", str(tmp_path))
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "session_use_crc32", False)
    monkeypatch.setattr(azr, "link_send", fake_link_send)
    monkeypatch.setattr(azr, "link_receive", lambda timeout=0: next(peer_packets, None))
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.run_zmodem_receiver_protocol()

    sent_types = [azr.parse_zmodem_header(packet)[0] for packet in sent_packets]
    assert sent_types[-1] == azr.AKITA_ZABORT
    assert azr.cancel_transfer_flag.is_set()


def test_receiver_listener_loop_resets_after_transfer(monkeypatch):
    link = DummyLink()

    monkeypatch.setattr(azr, "target_link", link)
    monkeypatch.setattr(azr, "transfer_active", True)
    monkeypatch.setattr(azr, "transfer_event", threading.Event())
    monkeypatch.setattr(azr, "cancel_transfer_flag", threading.Event())
    monkeypatch.setattr(azr, "shutdown_requested", threading.Event())
    monkeypatch.setattr(azr.RNS, "log", lambda *args, **kwargs: None)

    azr.transfer_event.set()
    azr.cancel_transfer_flag.set()

    def fake_sleep(_seconds):
        azr.shutdown_requested.set()

    monkeypatch.setattr(azr.time, "sleep", fake_sleep)

    azr.run_receiver_listener_loop()

    assert link.teardown_calls == 1
    assert azr.target_link is None
    assert azr.transfer_active is False
    assert not azr.transfer_event.is_set()
    assert not azr.cancel_transfer_flag.is_set()