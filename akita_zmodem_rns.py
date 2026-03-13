# akita_zmodem_rns.py
# GPLv3 Licensed
#
# Akita Zmodem for Reticulum: A file transfer utility using a Zmodem-like
# protocol over the Reticulum Network Stack.

import crcmod
import time
import os
import sys
import json
import argparse
import threading
import queue
import stat
import RNS


# Akita Zmodem constants
AKITA_APP_NAME = "akita_zmodem"
AKITA_ZPAD = b'*'        # Padding character begins frames
AKITA_ZDLE = b'\x18'     # Ctrl-X Zmodem DLE (Data Link Escape)
AKITA_ZDLEE = b'\x58'    # ZDLE encoded (ZDLE ^ 0x40)
AKITA_ZHEX = b'h'        # HEX frame indicator (not actively used in this version)
AKITA_ZBIN = b'B'        # Binary frame indicator for Zmodem headers
AKITA_ZBIN32_MARKER = b'C'  # Noted but not used; session flag controls CRC32

# Zmodem Frame Types
AKITA_ZRQINIT = 0        # Request receive init
AKITA_ZRINIT = 1         # Receive init
AKITA_ZSINIT = 2         # Send init sequence (optional, not used)
AKITA_ZACK = 3           # ACK
AKITA_ZFILE = 4          # File name from sender
AKITA_ZSKIP = 5          # To sender: skip this file
AKITA_ZNAK = 6           # Last packet was NAKed / Negative ACK
AKITA_ZABORT = 7         # Abort batch transfers
AKITA_ZFIN = 8           # Finish session
AKITA_ZRPOS = 9          # Resume data transmission at this position
AKITA_ZDATA = 10         # Data packet(s) follow
AKITA_ZEOF = 11          # End Of File
AKITA_ZFERR = 12         # Fatal Read or Write error Detected
AKITA_ZCRC = 13          # Request for file CRC and response (not used)
AKITA_ZCHALLENGE = 14    # Receiver's Challenge (not used)
AKITA_ZCOMPL = 15        # Request is complete (not used)
AKITA_ZCAN = 16          # Other end canned session with CAN*5
AKITA_ZFREECNT = 17      # Request for free bytes on disk (not used)
AKITA_ZCOMMAND = 18      # Command from sending program (not used, security)
AKITA_ZSTDERR = 19       # Output to standard error (not used)
AKITA_NO_TYPE = 255      # Placeholder for invalid type

# ZDLE sequences for data subpackets (primarily for ZFILE info subpacket)
AKITA_ZCRCE = b'h'       # CRC next, frame ends, header packet follows
AKITA_ZCRCG = b'i'       # CRC next, frame continues nonstop
AKITA_ZCRCQ = b'j'       # CRC next, frame continues, ZACK expected
AKITA_ZCRCW = b'k'       # CRC next, ZACK expected, end of frame

# Bit masks for ZRINIT flags byte ZF0
AKITA_CANFDX = 0x01
AKITA_CANOVIO = 0x02
AKITA_CANBRK = 0x04
AKITA_CANCRY = 0x08
AKITA_CANLZW = 0x10
AKITA_CANFC32 = 0x20     # Receiver can use 32-bit CRC for ZDATA payloads
AKITA_ESCCTL = 0x40
AKITA_ESC8 = 0x80

# Length constants
ZMODEM_HEADER_LENGTH_BIN = 10     # ZPAD + ZDLE + ZBIN + type(1) + data_val(4) + crc16(2)
ZMODEM_SUBPACKET_DATA_PREFIX_LEN = 2  # ZDLE + ZBIN for ZFILE info subpacket
ZMODEM_SUBPACKET_DATA_SUFFIX_LEN = 4  # ZDLE + ZCRCW + crc16(2)
CRC32_LEN = 4

# CRC functions
crc16_func = crcmod.predefined.mkCrcFun('crc-ccitt-false')
crc32_func = crcmod.predefined.mkCrcFun('crc-32')

# Global context variables
reticulum_instance = None
identity = None
destination_hash_hex = None  # For sender: target receiver's hash
target_link = None           # Active RNS Link for transfer
transfer_event = threading.Event()  # Signals completion/cancellation of a transfer attempt
receive_file_path = None     # Full path for the file being received
file_to_send_path = None     # Full path for the file being sent
is_sender_mode = False       # True if sender, False if receiver
current_file_size = 0
current_file_offset = 0      # Tracks file pointer offset for sending
receive_directory = "~/akita_received_files/"
sender_last_acked_offset = 0
receiver_last_written_offset = 0
transfer_active = False
cancel_transfer_flag = threading.Event()
session_use_crc32 = False

# Thread-safe queue for incoming packets on the active link
packet_queue = queue.Queue()


# --- ZMODEM Protocol Helper Functions ---

def zmodem_escape(data_bytes, esc_ctl=True, esc_8=False):
    """ZDLE-escapes data following Zmodem conventions."""
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
    """Reverse ZDLE escaping produced by zmodem_escape."""
    data = bytearray()
    i = 0
    while i < len(escaped_data_bytes):
        b = escaped_data_bytes[i]
        if b == AKITA_ZDLE[0]:
            i += 1
            if i >= len(escaped_data_bytes):
                RNS.log("ZMODEM: Trailing ZDLE in unescape, data may be truncated.", RNS.LOG_WARNING)
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
    """Builds a simplified Zmodem binary header with CRC16."""
    frame = AKITA_ZPAD + AKITA_ZDLE + AKITA_ZBIN
    header_content = bytes([frame_type]) + data_val.to_bytes(4, 'little', signed=False)
    frame += header_content
    crc = crc16_func(header_content)
    frame += crc.to_bytes(2, 'little')
    return bytes(frame)


def parse_zmodem_header(raw_packet):
    """Parses a simplified Zmodem binary header. Returns (type, data_val, header_len_consumed)."""
    if not raw_packet:
        return AKITA_NO_TYPE, 0, 0

    min_len_no_zpad = ZMODEM_HEADER_LENGTH_BIN - 1
    header_start_idx = 0
    if raw_packet[0] == AKITA_ZPAD[0]:
        if len(raw_packet) < ZMODEM_HEADER_LENGTH_BIN:
            RNS.log(f"ZMODEM HDR: Packet too short ({len(raw_packet)}B) with ZPAD.", RNS.LOG_DEBUG)
            return AKITA_NO_TYPE, 0, 0
        header_start_idx = 1
    elif len(raw_packet) < min_len_no_zpad:
        RNS.log(f"ZMODEM HDR: Packet too short ({len(raw_packet)}B) without ZPAD.", RNS.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0

    if raw_packet[header_start_idx] != AKITA_ZDLE[0] or \
       raw_packet[header_start_idx + 1] != AKITA_ZBIN[0]:
        RNS.log("ZMODEM HDR: Invalid ZDLE/ZBIN marker.", RNS.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0

    content_start_idx = header_start_idx + 2
    if len(raw_packet) < content_start_idx + 5 + 2:
        RNS.log("ZMODEM HDR: Packet too short for content and CRC.", RNS.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0

    header_content = raw_packet[content_start_idx: content_start_idx + 5]
    crc_bytes = raw_packet[content_start_idx + 5: content_start_idx + 7]

    if len(header_content) != 5 or len(crc_bytes) != 2:
        RNS.log("ZMODEM HDR: Truncated content or CRC part.", RNS.LOG_ERROR)
        return AKITA_NO_TYPE, 0, 0

    received_crc = int.from_bytes(crc_bytes, 'little')
    calculated_crc = crc16_func(header_content)

    if received_crc != calculated_crc:
        RNS.log(f"ZMODEM HDR: Header CRC16 mismatch. Got {received_crc:04x}, calc {calculated_crc:04x}", RNS.LOG_WARNING)
        return AKITA_NO_TYPE, 0, 0

    frame_type = header_content[0]
    data_val = int.from_bytes(header_content[1:5], 'little', signed=False)
    parsed_header_length = content_start_idx + 7
    return frame_type, data_val, parsed_header_length


# --- Link communication helpers ---
# RNS Links are asynchronous: data is sent via RNS.Packet and received via
# a packet callback. These helpers provide a synchronous-like interface used
# by the protocol threads.

def link_send(link, data):
    """Send data over an RNS Link by creating and sending a Packet."""
    if link and link.status == RNS.Link.ACTIVE:
        packet = RNS.Packet(link, data)
        result = packet.send()
        if result is False:
            RNS.log("link_send: Packet.send() returned False (link closed or no interface)", RNS.LOG_ERROR)
            return False
        return True
    return False


def link_receive(timeout=10):
    """Block until a packet arrives on the active link or timeout expires."""
    try:
        return packet_queue.get(timeout=timeout)
    except queue.Empty:
        return None


def link_packet_callback(message, packet):
    """Callback registered on the link to enqueue received packets."""
    packet_queue.put(message)


# --- Checkpointing Functions ---

def save_checkpoint(filename, offset, size, mtime=0, mode=0):
    """Saves transfer checkpoint information."""
    base_fn = os.path.basename(filename)
    checkpoint_file = os.path.join(receive_directory, f"{base_fn}.checkpoint")
    checkpoint_data = {"filename": base_fn, "offset": offset, "size": size, "mtime": mtime, "mode": mode}
    try:
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f)
        RNS.log(f"Checkpoint saved: {base_fn} @{offset}, sz {size}, mt {mtime}, md {oct(mode)}", RNS.LOG_DEBUG)
    except Exception as e:
        RNS.log(f"Error saving checkpoint {checkpoint_file}: {e}", RNS.LOG_ERROR)


def load_checkpoint(filename_basename):
    """Loads checkpoint information for a given basename."""
    checkpoint_file = os.path.join(receive_directory, f"{filename_basename}.checkpoint")
    try:
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, "r") as f:
                cp = json.load(f)
                cp.setdefault('mtime', 0)
                cp.setdefault('mode', 0)
                RNS.log(f"Checkpoint loaded for {filename_basename}: Offset {cp['offset']}, Size {cp['size']}", RNS.LOG_INFO)
                return cp
    except Exception as e:
        RNS.log(f"Error loading checkpoint {checkpoint_file}: {e}", RNS.LOG_ERROR)
    return None


def delete_checkpoint(filename_basename):
    """Deletes checkpoint file for a given basename."""
    checkpoint_file = os.path.join(receive_directory, f"{filename_basename}.checkpoint")
    try:
        if os.path.exists(checkpoint_file):
            os.remove(checkpoint_file)
            RNS.log(f"Checkpoint deleted: {filename_basename}", RNS.LOG_INFO)
    except Exception as e:
        RNS.log(f"Error deleting checkpoint {checkpoint_file}: {e}", RNS.LOG_ERROR)


def _link_repr(link):
    """Return a short string identifying a link for log messages."""
    if link and hasattr(link, 'link_id') and link.link_id:
        return RNS.prettyhexrep(link.link_id)
    return "<unknown>"


# --- Reticulum Link Callbacks ---

def client_link_established(link):
    global target_link, transfer_event, is_sender_mode, transfer_active, session_use_crc32
    RNS.log(f"Link established to server {_link_repr(link)}", RNS.LOG_INFO)
    target_link = link
    transfer_active = True
    session_use_crc32 = False
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            break
    link.set_packet_callback(link_packet_callback)
    if is_sender_mode:
        sender_thread = threading.Thread(target=run_zmodem_sender_protocol, name="ZAPS")
        sender_thread.daemon = True
        sender_thread.start()
    else:
        RNS.log("Client link established but not in sender mode. Tearing down.", RNS.LOG_ERROR)
        link.teardown()


def client_link_closed(link):
    global target_link, transfer_event, transfer_active
    if link == target_link or target_link is None:
        RNS.log(f"Link to server {_link_repr(link)} closed.", RNS.LOG_INFO)
        target_link = None
        transfer_active = False
        cancel_transfer_flag.set()
        transfer_event.set()


def server_link_established(link):
    global target_link, transfer_event, is_sender_mode, transfer_active, session_use_crc32
    if target_link is not None and target_link.status != RNS.Link.CLOSED:
        RNS.log(f"Server busy, rejecting new link from {_link_repr(link)}.", RNS.LOG_WARNING)
        link.teardown()
        return

    RNS.log(f"Link established from client {_link_repr(link)}", RNS.LOG_INFO)
    target_link = link
    transfer_active = True
    session_use_crc32 = False
    cancel_transfer_flag.clear()
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            break
    link.set_packet_callback(link_packet_callback)
    link.set_link_closed_callback(server_link_closed)
    if not is_sender_mode:
        receiver_thread = threading.Thread(target=run_zmodem_receiver_protocol, name="ZAPR")
        receiver_thread.daemon = True
        receiver_thread.start()
    else:
        RNS.log("Server link established but instance is in sender mode. Tearing down.", RNS.LOG_ERROR)
        link.teardown()


def server_link_closed(link):
    global target_link, transfer_event, transfer_active
    if link == target_link or target_link is None:
        RNS.log(f"Link from client {_link_repr(link)} closed.", RNS.LOG_INFO)
        target_link = None
        transfer_active = False
        cancel_transfer_flag.set()
        transfer_event.set()


# --- ZMODEM SENDER PROTOCOL Thread ---

def run_zmodem_sender_protocol():
    global file_to_send_path, target_link, current_file_size, current_file_offset
    global sender_last_acked_offset, cancel_transfer_flag, transfer_event, session_use_crc32

    RNS.log("Zmodem Sender Protocol Started", RNS.LOG_VERBOSE)

    file_mtime = 0
    file_mode = 0
    filename_base = ""

    try:
        filename_base = os.path.basename(file_to_send_path)
        file_stat = os.stat(file_to_send_path)
        current_file_size = file_stat.st_size
        file_mtime = int(file_stat.st_mtime)
        file_mode = stat.S_IMODE(file_stat.st_mode)
    except FileNotFoundError:
        RNS.log(f"Sender: File not found: {file_to_send_path}", RNS.LOG_ERROR)
        return
    except Exception as e:
        RNS.log(f"Sender: Error stating file {file_to_send_path}: {e}", RNS.LOG_ERROR)
        return

    current_file_offset = 0
    sender_last_acked_offset = 0

    try:
        RNS.log("Sender: Sending ZRQINIT", RNS.LOG_DEBUG)
        if not link_send(target_link, build_zmodem_header(AKITA_ZRQINIT)):
            return

        packet = link_receive(timeout=30)
        if cancel_transfer_flag.is_set() or not packet:
            RNS.log("Sender: No ZRINIT received or transfer cancelled.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        ptype, pdata_val, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRINIT:
            RNS.log(f"Sender: Expected ZRINIT, got type {ptype}. Aborting.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        RNS.log(f"Sender: Received ZRINIT (flags: {pdata_val:08x})", RNS.LOG_DEBUG)
        zf0_flags = pdata_val & 0xFF
        if zf0_flags & AKITA_CANFC32:
            session_use_crc32 = True
            RNS.log("Sender: Receiver supports CRC32 for ZDATA payloads.", RNS.LOG_INFO)
        else:
            RNS.log("Sender: Receiver does not advertise CRC32 support.", RNS.LOG_INFO)

        zfile_main_header = build_zmodem_header(AKITA_ZFILE, 0)

        clean_filename = filename_base.replace('\0', '_')
        file_info_str = f"{clean_filename}\0{current_file_size} {oct(file_mtime)} {oct(file_mode)}\0"
        file_info_bytes_unescaped = file_info_str.encode('utf-8')
        escaped_file_info_bytes = zmodem_escape(file_info_bytes_unescaped)

        zfile_data_subpacket = (AKITA_ZDLE + AKITA_ZBIN +
                                escaped_file_info_bytes +
                                AKITA_ZDLE + AKITA_ZCRCW +
                                crc16_func(file_info_bytes_unescaped).to_bytes(2, 'little'))

        RNS.log(f"Sender: Sending ZFILE for '{clean_filename}', Size {current_file_size}", RNS.LOG_DEBUG)
        if not link_send(target_link, zfile_main_header + zfile_data_subpacket):
            return

        packet = link_receive(timeout=30)
        if cancel_transfer_flag.is_set() or not packet:
            RNS.log("Sender: No ZRPOS after ZFILE or transfer cancelled.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        ptype, pdata_offset, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRPOS:
            RNS.log(f"Sender: Expected ZRPOS, got type {ptype}. Aborting.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        sender_last_acked_offset = pdata_offset
        current_file_offset = sender_last_acked_offset
        RNS.log(f"Sender: Received ZRPOS. Starting from offset {current_file_offset}", RNS.LOG_INFO)

        with open(file_to_send_path, 'rb') as f:
            f.seek(current_file_offset)
            send_retries = 0
            max_send_retries = 10

            while current_file_offset < current_file_size:
                if cancel_transfer_flag.is_set() or not target_link or target_link.status == RNS.Link.CLOSED:
                    RNS.log("Sender: Transfer cancelled or link lost during ZDATA loop.", RNS.LOG_INFO)
                    link_send(target_link, build_zmodem_header(AKITA_ZCAN))
                    break

                chunk_size = RNS.Link.MDU - ZMODEM_HEADER_LENGTH_BIN - 30
                if session_use_crc32:
                    chunk_size -= CRC32_LEN
                if chunk_size <= 64:
                    chunk_size = 64

                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    RNS.log("Sender: Read empty chunk unexpectedly.", RNS.LOG_WARNING)
                    break

                zdata_header = build_zmodem_header(AKITA_ZDATA, current_file_offset)
                payload_to_send = chunk_data

                if session_use_crc32:
                    chunk_crc32_val = crc32_func(chunk_data)
                    payload_to_send += chunk_crc32_val.to_bytes(CRC32_LEN, 'little')

                if not link_send(target_link, zdata_header + payload_to_send):
                    break

                ack_received_for_current_chunk = False
                ack_retries = 0
                max_ack_retries = 3
                while not ack_received_for_current_chunk and ack_retries < max_ack_retries:
                    if cancel_transfer_flag.is_set() or not target_link or target_link.status == RNS.Link.CLOSED:
                        break

                    ack_packet = link_receive(timeout=15)
                    if ack_packet:
                        ack_type, ack_offset_val, _ = parse_zmodem_header(ack_packet)
                        expected_ack_offset = current_file_offset + len(chunk_data)
                        if ack_type == AKITA_ZACK:
                            if ack_offset_val >= expected_ack_offset or \
                               (ack_offset_val == current_file_size and expected_ack_offset == current_file_size):
                                sender_last_acked_offset = ack_offset_val
                                current_file_offset += len(chunk_data)
                                ack_received_for_current_chunk = True
                                send_retries = 0
                                break
                            else:
                                RNS.log(f"Sender: Stale ZACK for offset {ack_offset_val}", RNS.LOG_DEBUG)
                        elif ack_type == AKITA_ZRPOS:
                            RNS.log(f"Sender: Received ZRPOS {ack_offset_val}. Resyncing.", RNS.LOG_INFO)
                            current_file_offset = ack_offset_val
                            f.seek(current_file_offset)
                            sender_last_acked_offset = ack_offset_val
                            ack_received_for_current_chunk = True
                            break
                        elif ack_type == AKITA_ZNAK:
                            RNS.log("Sender: Received ZNAK. Will resend chunk.", RNS.LOG_WARNING)
                            ack_received_for_current_chunk = True
                            break
                        elif ack_type == AKITA_ZCAN:
                            RNS.log("Sender: Received ZCAN from receiver. Aborting.", RNS.LOG_INFO)
                            cancel_transfer_flag.set()
                            break
                        else:
                            RNS.log(f"Sender: Unexpected type {ack_type} while waiting for ZACK.", RNS.LOG_WARNING)
                    else:
                        RNS.log(f"Sender: Timeout waiting for ZACK. Retry {ack_retries + 1}/{max_ack_retries}", RNS.LOG_WARNING)
                        ack_retries += 1

                if not ack_received_for_current_chunk and not cancel_transfer_flag.is_set():
                    send_retries += 1
                    RNS.log(f"Sender: Failed to get ACK. Retry {send_retries}/{max_send_retries}", RNS.LOG_ERROR)
                    if send_retries >= max_send_retries:
                        RNS.log("Sender: Max retries exceeded. Aborting.", RNS.LOG_ERROR)
                        link_send(target_link, build_zmodem_header(AKITA_ZABORT))
                        cancel_transfer_flag.set()
                        break

            if cancel_transfer_flag.is_set():
                RNS.log("Sender: Transfer cancelled during or after ZDATA phase.", RNS.LOG_INFO)
            elif current_file_offset >= current_file_size:
                RNS.log(f"Sender: Sending ZEOF for offset {current_file_size}", RNS.LOG_DEBUG)
                if not link_send(target_link, build_zmodem_header(AKITA_ZEOF, current_file_size)):
                    return

                packet = link_receive(timeout=15)
                if packet:
                    ptype, _, _ = parse_zmodem_header(packet)
                    RNS.log(f"Sender: Received type {ptype} after ZEOF.", RNS.LOG_DEBUG)
                else:
                    RNS.log("Sender: No response after ZEOF.", RNS.LOG_DEBUG)

                RNS.log("Sender: Sending ZFIN", RNS.LOG_DEBUG)
                link_send(target_link, build_zmodem_header(AKITA_ZFIN))

                packet = link_receive(timeout=5)
                if packet:
                    ptype, _, _ = parse_zmodem_header(packet)
                    if ptype == AKITA_ZFIN:
                        RNS.log("Sender: Received final ZFIN. Transfer complete.", RNS.LOG_INFO)
                    else:
                        RNS.log(f"Sender: Received type {ptype} instead of ZFIN.", RNS.LOG_DEBUG)
                else:
                    RNS.log("Sender: No final ZFIN. Assuming complete.", RNS.LOG_DEBUG)

                print(f"\nFile '{filename_base}' sent successfully.")
            else:
                RNS.log(f"Sender: Data loop exited prematurely. {current_file_offset}/{current_file_size}", RNS.LOG_ERROR)
                link_send(target_link, build_zmodem_header(AKITA_ZABORT))

    except Exception as e_outer:
        RNS.log(f"Sender: Unhandled exception: {e_outer}", RNS.LOG_CRITICAL)
        import traceback
        RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
        try:
            link_send(target_link, build_zmodem_header(AKITA_ZABORT))
        except Exception:
            pass
    finally:
        if target_link and target_link.status != RNS.Link.CLOSED:
            target_link.teardown()
        target_link = None
        transfer_event.set()
        RNS.log("Sender: Protocol Finished.", RNS.LOG_VERBOSE)


# --- ZMODEM RECEIVER PROTOCOL Thread ---

def run_zmodem_receiver_protocol():
    global target_link, receive_file_path, current_file_size, current_file_offset
    global receive_directory, receiver_last_written_offset, cancel_transfer_flag
    global transfer_event, session_use_crc32

    RNS.log("Zmodem Receiver Protocol Started", RNS.LOG_VERBOSE)

    file_handle = None
    received_filename_base = None
    expected_file_mtime = 0
    expected_file_mode = 0
    resumed_transfer = False
    receiver_last_written_offset = 0

    try:
        packet = link_receive(timeout=600)
        if cancel_transfer_flag.is_set() or not packet:
            RNS.log("Receiver: No ZRQINIT received or transfer cancelled.", RNS.LOG_WARNING)
            return

        ptype, _, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRQINIT:
            RNS.log(f"Receiver: Expected ZRQINIT, got type {ptype}.", RNS.LOG_WARNING)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return
        RNS.log("Receiver: Received ZRQINIT", RNS.LOG_DEBUG)

        zrinit_flags = AKITA_CANFC32
        session_use_crc32 = True
        RNS.log(f"Receiver: Sending ZRINIT (flags: {zrinit_flags:08x})", RNS.LOG_INFO)
        if not link_send(target_link, build_zmodem_header(AKITA_ZRINIT, zrinit_flags)):
            return

        zfile_packet = link_receive(timeout=30)
        if cancel_transfer_flag.is_set() or not zfile_packet:
            RNS.log("Receiver: No ZFILE received or transfer cancelled.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        ptype, _, zfile_main_header_len = parse_zmodem_header(zfile_packet)
        if ptype != AKITA_ZFILE:
            RNS.log(f"Receiver: Expected ZFILE, got type {ptype}.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        subpacket_start = zfile_main_header_len
        if not (len(zfile_packet) > subpacket_start + ZMODEM_SUBPACKET_DATA_PREFIX_LEN and
                zfile_packet[subpacket_start: subpacket_start + ZMODEM_SUBPACKET_DATA_PREFIX_LEN] == (AKITA_ZDLE + AKITA_ZBIN)):
            RNS.log("Receiver: ZFILE missing ZDLE+ZBIN subpacket prefix.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        data_payload_start = subpacket_start + ZMODEM_SUBPACKET_DATA_PREFIX_LEN

        trailer_start_idx = -1
        search_end_limit = len(zfile_packet) - (ZMODEM_SUBPACKET_DATA_SUFFIX_LEN - 1)
        for i in range(data_payload_start, search_end_limit):
            if zfile_packet[i: i + 2] == (AKITA_ZDLE + AKITA_ZCRCW):
                trailer_start_idx = i
                break

        if trailer_start_idx == -1:
            RNS.log("Receiver: ZFILE ZDLE+ZCRCW trailer not found.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        escaped_file_info_bytes = zfile_packet[data_payload_start: trailer_start_idx]

        subpacket_crc_start = trailer_start_idx + 2
        subpacket_crc_bytes = zfile_packet[subpacket_crc_start: subpacket_crc_start + 2]

        if len(subpacket_crc_bytes) != 2:
            RNS.log("Receiver: ZFILE subpacket CRC truncated.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZCAN))
            return

        received_subpacket_crc16 = int.from_bytes(subpacket_crc_bytes, 'little')
        file_info_bytes_unescaped = zmodem_unescape(escaped_file_info_bytes)
        calculated_subpacket_crc16 = crc16_func(file_info_bytes_unescaped)

        if received_subpacket_crc16 != calculated_subpacket_crc16:
            RNS.log("Receiver: ZFILE subpacket CRC16 mismatch.", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZNAK))
            return

        try:
            file_info_str = file_info_bytes_unescaped.decode('utf-8')
            parts = file_info_str.strip('\0').split('\0')
            received_filename_base = os.path.basename(parts[0])

            if len(parts) > 1 and parts[1].strip():
                attrs_str = parts[1].split(' ')
                if len(attrs_str) >= 3:
                    current_file_size = int(attrs_str[0])
                    expected_file_mtime = int(attrs_str[1], 8)
                    expected_file_mode = int(attrs_str[2], 8)
                else:
                    raise ValueError("ZFILE attributes incomplete")
            else:
                raise ValueError("ZFILE info missing attributes")

            RNS.log(f"Receiver: ZFILE '{received_filename_base}', Size {current_file_size}", RNS.LOG_INFO)

        except Exception as e:
            RNS.log(f"Receiver: Error parsing ZFILE info: {e}", RNS.LOG_ERROR)
            link_send(target_link, build_zmodem_header(AKITA_ZFERR))
            return

        receive_file_path = os.path.join(receive_directory, received_filename_base)
        os.makedirs(os.path.dirname(receive_file_path), exist_ok=True)

        checkpoint = load_checkpoint(received_filename_base)
        current_file_offset = 0

        if checkpoint and checkpoint['filename'] == received_filename_base and checkpoint['size'] == current_file_size:
            if checkpoint.get('mtime', 0) == expected_file_mtime and checkpoint.get('mode', 0) == expected_file_mode:
                if os.path.exists(receive_file_path) and os.path.getsize(receive_file_path) == checkpoint['offset']:
                    RNS.log(f"Receiver: Valid checkpoint. Resuming from offset {checkpoint['offset']}", RNS.LOG_INFO)
                    current_file_offset = checkpoint['offset']
                    receiver_last_written_offset = current_file_offset
                    resumed_transfer = True
                else:
                    RNS.log("Receiver: Checkpoint/file size mismatch. Starting from scratch.", RNS.LOG_WARNING)
                    delete_checkpoint(received_filename_base)
            else:
                RNS.log("Receiver: Checkpoint metadata mismatch. Starting from scratch.", RNS.LOG_WARNING)
                delete_checkpoint(received_filename_base)
        elif os.path.exists(receive_file_path) and not resumed_transfer:
            print(f"File '{received_filename_base}' already exists in '{receive_directory}'.")
            overwrite_choice = input("Overwrite? (y/N): ").strip().lower()
            if overwrite_choice != 'y':
                RNS.log("Receiver: User chose not to overwrite. Sending ZSKIP.", RNS.LOG_INFO)
                link_send(target_link, build_zmodem_header(AKITA_ZSKIP))
                return
            RNS.log("Receiver: User chose to overwrite.", RNS.LOG_INFO)
            try:
                if os.path.exists(receive_file_path):
                    os.remove(receive_file_path)
                delete_checkpoint(received_filename_base)
            except Exception as e_del:
                RNS.log(f"Receiver: Could not remove existing file: {e_del}", RNS.LOG_ERROR)
                link_send(target_link, build_zmodem_header(AKITA_ZFERR))
                return

        if not resumed_transfer:
            current_file_offset = 0
            receiver_last_written_offset = 0

        RNS.log(f"Receiver: Sending ZRPOS with offset {current_file_offset}", RNS.LOG_DEBUG)
        if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, current_file_offset)):
            return

        file_open_mode = 'r+b' if resumed_transfer and current_file_offset > 0 else 'wb'
        if not os.path.exists(receive_file_path) and file_open_mode == 'r+b':
            RNS.log("Receiver: Resumed file missing, switching to 'wb'.", RNS.LOG_WARNING)
            file_open_mode = 'wb'
            current_file_offset = 0
            receiver_last_written_offset = 0

        try:
            file_handle = open(receive_file_path, file_open_mode)
            if current_file_offset > 0 and file_open_mode == 'r+b':
                file_handle.seek(current_file_offset)
                if file_handle.tell() != current_file_offset:
                    RNS.log("Receiver: Seek failed. Falling back to overwrite.", RNS.LOG_ERROR)
                    file_handle.close()
                    file_handle = open(receive_file_path, 'wb')
                    current_file_offset = 0
                    receiver_last_written_offset = 0
        except Exception as e_open:
            RNS.log(f"Receiver: Error opening file: {e_open}", RNS.LOG_CRITICAL)
            link_send(target_link, build_zmodem_header(AKITA_ZFERR))
            return

        while receiver_last_written_offset < current_file_size:
            if cancel_transfer_flag.is_set() or not target_link or target_link.status == RNS.Link.CLOSED:
                RNS.log("Receiver: Transfer cancelled or link lost.", RNS.LOG_INFO)
                break

            data_packet = link_receive(timeout=20)
            if not data_packet:
                RNS.log("Receiver: Timeout waiting for ZDATA. Requesting ZRPOS.", RNS.LOG_WARNING)
                if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                    break
                continue

            ptype, pdata_offset, data_header_len = parse_zmodem_header(data_packet)

            if ptype == AKITA_ZDATA:
                chunk_with_potential_crc = data_packet[data_header_len:]
                actual_chunk_data = None

                if session_use_crc32:
                    if len(chunk_with_potential_crc) < CRC32_LEN:
                        RNS.log("Receiver: ZDATA payload too short for CRC32.", RNS.LOG_ERROR)
                        if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                            break
                        continue

                    actual_chunk_data = chunk_with_potential_crc[:-CRC32_LEN]
                    received_crc = int.from_bytes(chunk_with_potential_crc[-CRC32_LEN:], 'little')
                    calculated_crc = crc32_func(actual_chunk_data)

                    if received_crc != calculated_crc:
                        RNS.log(f"Receiver: ZDATA CRC32 mismatch at offset {pdata_offset}", RNS.LOG_ERROR)
                        if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                            break
                        continue
                else:
                    actual_chunk_data = chunk_with_potential_crc

                if pdata_offset == receiver_last_written_offset:
                    file_handle.write(actual_chunk_data)
                    file_handle.flush()
                    receiver_last_written_offset += len(actual_chunk_data)
                    save_checkpoint(received_filename_base, receiver_last_written_offset, current_file_size, expected_file_mtime, expected_file_mode)

                    if not link_send(target_link, build_zmodem_header(AKITA_ZACK, receiver_last_written_offset)):
                        break

                    progress = (receiver_last_written_offset / current_file_size) * 100 if current_file_size > 0 else 100.0
                    sys.stdout.write(f"\rReceiving '{received_filename_base}': {receiver_last_written_offset}/{current_file_size} bytes ({progress:.2f}%)  ")
                    sys.stdout.flush()

                elif pdata_offset < receiver_last_written_offset:
                    RNS.log(f"Receiver: Duplicate ZDATA at offset {pdata_offset}", RNS.LOG_DEBUG)
                    if not link_send(target_link, build_zmodem_header(AKITA_ZACK, receiver_last_written_offset)):
                        break
                else:
                    RNS.log(f"Receiver: Gap in ZDATA. Expected {receiver_last_written_offset}, got {pdata_offset}", RNS.LOG_WARNING)
                    if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                        break

            elif ptype == AKITA_ZEOF:
                eof_offset = pdata_offset
                RNS.log(f"Receiver: ZEOF (reported {eof_offset}). Written: {receiver_last_written_offset}", RNS.LOG_DEBUG)
                if receiver_last_written_offset == current_file_size and eof_offset == current_file_size:
                    RNS.log("Receiver: Transfer complete.", RNS.LOG_INFO)
                    link_send(target_link, build_zmodem_header(AKITA_ZRINIT))
                    break
                RNS.log("Receiver: ZEOF mismatch. Requesting ZRPOS.", RNS.LOG_ERROR)
                if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                    break

            elif ptype == AKITA_ZCAN or ptype == AKITA_ZABORT:
                RNS.log("Receiver: ZCAN/ZABORT from sender.", RNS.LOG_INFO)
                cancel_transfer_flag.set()
                break
            else:
                RNS.log(f"Receiver: Unexpected type {ptype}. Requesting ZRPOS.", RNS.LOG_WARNING)
                if not link_send(target_link, build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)):
                    break

        if file_handle:
            file_handle.close()
            file_handle = None

        if cancel_transfer_flag.is_set() and received_filename_base:
            RNS.log(f"Receiver: Transfer for '{received_filename_base}' cancelled. Checkpoint preserved.", RNS.LOG_INFO)
            return

        if receiver_last_written_offset == current_file_size and received_filename_base:
            try:
                if expected_file_mtime > 0:
                    os.utime(receive_file_path, (expected_file_mtime, expected_file_mtime))
                if expected_file_mode > 0:
                    os.chmod(receive_file_path, expected_file_mode)
                RNS.log(f"Receiver: Set mtime/mode for '{received_filename_base}'", RNS.LOG_INFO)
            except Exception as e_attr:
                RNS.log(f"Receiver: Error setting file attributes: {e_attr}", RNS.LOG_WARNING)

            if not target_link or target_link.status == RNS.Link.CLOSED:
                delete_checkpoint(received_filename_base)
                print(f"\nFile '{received_filename_base}' received to '{os.path.abspath(receive_file_path)}'.")
                return

            packet = link_receive(timeout=10)
            if packet:
                ptype, _, _ = parse_zmodem_header(packet)
                if ptype == AKITA_ZFIN:
                    RNS.log("Receiver: Received ZFIN. Sending final ZFIN.", RNS.LOG_DEBUG)
                    link_send(target_link, build_zmodem_header(AKITA_ZFIN))
                else:
                    RNS.log(f"Receiver: Expected ZFIN, got type {ptype}. Assuming finished.", RNS.LOG_WARNING)
            else:
                RNS.log("Receiver: Timeout waiting for ZFIN. Assuming finished.", RNS.LOG_WARNING)

            delete_checkpoint(received_filename_base)
            print(f"\nFile '{received_filename_base}' received successfully to '{os.path.abspath(receive_file_path)}'.")
        elif received_filename_base:
            print(f"\nTransfer for '{received_filename_base}' incomplete. {receiver_last_written_offset}/{current_file_size} bytes.")
            RNS.log(f"Receiver: Incomplete. {receiver_last_written_offset}/{current_file_size}", RNS.LOG_ERROR)
        else:
            RNS.log("Receiver: Transfer ended incompletely, filename unknown.", RNS.LOG_ERROR)

    except KeyboardInterrupt:
        RNS.log("Receiver: Keyboard interrupt.", RNS.LOG_INFO)
        cancel_transfer_flag.set()
        link_send(target_link, build_zmodem_header(AKITA_ZCAN))
    except Exception as e_outer:
        RNS.log(f"Receiver: Unhandled exception: {e_outer}", RNS.LOG_CRITICAL)
        import traceback
        RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
        try:
            link_send(target_link, build_zmodem_header(AKITA_ZFERR))
        except Exception:
            pass
    finally:
        if file_handle:
            file_handle.close()
        if target_link and target_link.status != RNS.Link.CLOSED:
            target_link.teardown()
        target_link = None
        transfer_event.set()
        RNS.log("Receiver: Protocol Finished.", RNS.LOG_VERBOSE)


# --- Main Application Logic ---

def main():
    global reticulum_instance, identity, destination_hash_hex, file_to_send_path
    global is_sender_mode, receive_directory, transfer_event, cancel_transfer_flag, target_link, transfer_active

    parser = argparse.ArgumentParser(
        description="Akita Zmodem for Reticulum: File transfer over RNS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("mode", choices=['send', 'receive'], help="Mode of operation: 'send' or 'receive'.")
    parser.add_argument("-i", "--identity", metavar="PATH",
                        help="Path to Reticulum identity file.\nIf not specified, uses/creates '~/.akita_zmodem_id.key'.")
    parser.add_argument("-d", "--destination", metavar="HASH",
                        help="Receiver's Reticulum destination hash.\nRequired for 'send' mode.")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="Path to the file to send.\nRequired for 'send' mode.")
    parser.add_argument("--recvdir", metavar="PATH", default="~/akita_received_files/",
                        help="Directory to save received files.\n(Default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity level:\n  -v INFO, -vv DEBUG, -vvv EXTREME.\n  Default: NOTICE.")

    args = parser.parse_args()

    if args.verbose == 1:
        RNS.loglevel = RNS.LOG_INFO
    elif args.verbose == 2:
        RNS.loglevel = RNS.LOG_DEBUG
    elif args.verbose >= 3:
        RNS.loglevel = RNS.LOG_EXTREME
    else:
        RNS.loglevel = RNS.LOG_NOTICE

    receive_directory = os.path.expanduser(args.recvdir)
    try:
        os.makedirs(receive_directory, exist_ok=True)
        RNS.log(f"Receive directory set to: {os.path.abspath(receive_directory)}", RNS.LOG_DEBUG)
    except Exception as e:
        print(f"Error: Could not create receive directory '{receive_directory}': {e}")
        sys.exit(1)

    if args.identity:
        identity_path = os.path.expanduser(args.identity)
    else:
        identity_path = os.path.expanduser("~/.akita_zmodem_id.key")

    if not os.path.exists(identity_path):
        RNS.log(f"Identity file '{identity_path}' not found. Creating new one.", RNS.LOG_NOTICE)
        identity = RNS.Identity()
        try:
            identity.to_file(identity_path)
            RNS.log(f"New identity created and saved to '{identity_path}'", RNS.LOG_INFO)
        except Exception as e:
            print(f"Error: Could not save new identity to '{identity_path}': {e}")
            sys.exit(1)
    else:
        try:
            identity = RNS.Identity.from_file(identity_path)
            if identity is None:
                raise ValueError("Identity.from_file returned None")
            RNS.log(f"Identity loaded from '{identity_path}'.", RNS.LOG_INFO)
        except Exception as e:
            print(f"Error: Could not load identity from '{identity_path}'.")
            print(f"Ensure it's a valid Reticulum identity file. Error: {e}")
            sys.exit(1)

    reticulum_instance = RNS.Reticulum(loglevel=RNS.loglevel)
    RNS.log(f"Reticulum Identity: {RNS.prettyhexrep(identity.hash)} ({identity_path})", RNS.LOG_NOTICE)

    if args.mode == 'send':
        is_sender_mode = True
        if not args.destination or not args.file:
            parser.error("Sender mode requires both --destination HASH and --file PATH arguments.")

        destination_hash_hex = args.destination
        file_to_send_path = os.path.expanduser(args.file)

        if not os.path.exists(file_to_send_path):
            print(f"Error: File to send not found: '{file_to_send_path}'")
            sys.exit(1)
        if not os.path.isfile(file_to_send_path):
            print(f"Error: Path is not a file: '{file_to_send_path}'")
            sys.exit(1)

        try:
            dest_hash_bytes = bytes.fromhex(destination_hash_hex)
            expected_len = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
            if len(dest_hash_bytes) != expected_len:
                raise ValueError(f"Expected {expected_len} bytes ({expected_len * 2} hex chars), got {len(dest_hash_bytes)} bytes")
        except Exception as e:
            print(f"Error: Invalid destination hash '{destination_hash_hex}': {e}")
            sys.exit(1)

        RNS.log(f"Sender mode. Target: {destination_hash_hex}, File: '{file_to_send_path}'", RNS.LOG_INFO)

        if not RNS.Transport.has_path(dest_hash_bytes):
            RNS.log(f"Path to {destination_hash_hex} not known. Requesting...", RNS.LOG_INFO)
            RNS.Transport.request_path(dest_hash_bytes)
            print(f"Requesting path to {destination_hash_hex}...")
            path_timeout = 30
            path_wait_start = time.time()
            while not RNS.Transport.has_path(dest_hash_bytes):
                time.sleep(0.1)
                if time.time() - path_wait_start > path_timeout:
                    break

            if not RNS.Transport.has_path(dest_hash_bytes):
                print(f"Error: Could not find path to {destination_hash_hex}. Is the receiver running?")
                RNS.Reticulum.exit_handler()
                sys.exit(1)

        remote_identity = RNS.Identity.recall(dest_hash_bytes)
        if remote_identity is None:
            print(f"Error: Could not recall identity for {destination_hash_hex}. The receiver may need to re-announce.")
            RNS.Reticulum.exit_handler()
            sys.exit(1)

        remote_destination = RNS.Destination(
            remote_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            AKITA_APP_NAME,
            "transfer_server"
        )

        RNS.Link(remote_destination, established_callback=client_link_established, closed_callback=client_link_closed)

        print(f"Connecting to {destination_hash_hex} to send '{os.path.basename(file_to_send_path)}'...")
        transfer_event.wait()

    elif args.mode == 'receive':
        is_sender_mode = False
        RNS.log("Receiver mode. Setting up listener...", RNS.LOG_INFO)

        server_destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            AKITA_APP_NAME,
            "transfer_server"
        )
        server_destination.set_link_established_callback(server_link_established)

        server_destination.announce()
        announce_hash_hex = RNS.prettyhexrep(server_destination.hash)

        print("Receiver started and listening for connections.")
        print(f"  Reticulum Full Node Address: {RNS.prettyhexrep(identity.hash)}")
        print(f"  Service Announce Hash:     {announce_hash_hex} (for aspect: {AKITA_APP_NAME}/transfer_server)")
        print(f"  Received files will be saved in: {os.path.abspath(receive_directory)}")
        print("Press Ctrl+C to stop listening.")

        try:
            while not cancel_transfer_flag.is_set():
                if transfer_event.is_set():
                    RNS.log("Receiver: Transfer attempt finished. Resetting.", RNS.LOG_INFO)
                    if target_link and target_link.status != RNS.Link.CLOSED:
                        RNS.log("Receiver: Forcing teardown of previous link.", RNS.LOG_DEBUG)
                        target_link.teardown()
                    target_link = None
                    transfer_active = False
                    transfer_event.clear()
                    RNS.log("Receiver ready for new connection.", RNS.LOG_INFO)
                time.sleep(0.2)
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Shutting down...")
            cancel_transfer_flag.set()
            if target_link and target_link.status != RNS.Link.CLOSED:
                target_link.teardown()

    RNS.log("Stopping Reticulum...", RNS.LOG_INFO)
    RNS.Reticulum.exit_handler()
    time.sleep(0.5)
    print("Akita Zmodem has stopped.")


if __name__ == "__main__":
    reticulum_instance = None
    try:
        main()
    except Exception as e_main:
        print(f"Fatal error in Akita Zmodem: {e_main}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            RNS.Reticulum.exit_handler()
        except Exception:
            pass
