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
import stat # For file mode constants and conversion
import Reticulum as R


# Akita Zmodem constants
AKITA_APP_NAME = "akita_zmodem"
AKITA_ZPAD = b'*'        # Padding character begins frames
AKITA_ZDLE = b'\x18'     # Ctrl-X Zmodem DLE (Data Link Escape)
AKITA_ZDLEE = b'\x58'    # ZDLE encoded (ZDLE ^ 0x40)
AKITA_ZHEX = b'h'        # HEX frame indicator (not actively used for Zmodem headers in this version)
AKITA_ZBIN = b'B'        # Binary frame indicator for Zmodem headers
AKITA_ZBIN32_MARKER = b'C' # Zmodem traditional marker for data subpackets with 32-bit CRC
                         # This constant is noted, but our current implementation uses a session flag
                         # to append CRC32 to ZDATA payload rather than changing ZDATA header's ZBIN marker.

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
AKITA_ZCRCW = b'k'       # CRC next, ZACK expected, end of frame (used for ZFILE info)

# Bit masks for ZRINIT flags byte ZF0 (LSB of the 4-byte data_val in ZRINIT header)
AKITA_CANFDX = 0x01      # Rx can send and receive true FDX
AKITA_CANOVIO = 0x02     # Rx can receive data during disk I/O
AKITA_CANBRK = 0x04      # Rx can send a break signal
AKITA_CANCRY = 0x08      # Receiver can decrypt
AKITA_CANLZW = 0x10      # Receiver can uncompress
AKITA_CANFC32 = 0x20     # Receiver can use 32-bit Frame Check for ZDATA payloads
AKITA_ESCCTL = 0x40      # Receiver expects ctl chars to be escaped
AKITA_ESC8 = 0x80        # Receiver expects 8th bit to be escaped

# Length constants
ZMODEM_HEADER_LENGTH_BIN = 10     # ZPAD + ZDLE + ZBIN + type(1) + data_val(4) + crc16(2)
ZMODEM_SUBPACKET_DATA_PREFIX_LEN = 2 # ZDLE + ZBIN for ZFILE info subpacket
ZMODEM_SUBPACKET_DATA_SUFFIX_LEN = 4 # ZDLE + ZCRCW + crc16(2) for ZFILE info subpacket (total bytes)
CRC32_LEN = 4                    # Length of CRC32 checksum in bytes

# CRC functions
crc16_func = crcmod.predefined.mkCrcFun('crc-ccitt-false') # For Zmodem headers and ZFILE info subpacket
crc32_func = crcmod.predefined.mkCrcFun('crc-32')         # For ZDATA payloads if negotiated

# Global context variables
reticulum_instance = None
identity = None
destination_hash_hex = None # For sender: target receiver's hash
target_link = None          # Active RNS Link for transfer
transfer_event = threading.Event() # Signals completion/cancellation of a transfer attempt
receive_file_path = None    # Full path for the file being received
file_to_send_path = None    # Full path for the file being sent
is_sender_mode = False      # True if current instance is sender, False if receiver
current_file_size = 0       # Total size of the file being transferred
current_file_offset = 0     # Tracks the file pointer offset for sending (where to read next)
receive_directory = "~/akita_received_files/" # Default, overridden by CLI
sender_last_acked_offset = 0 # Tracks the latest byte offset ACKed by receiver (sender's view)
receiver_last_written_offset = 0 # Tracks bytes successfully written by receiver (receiver's view)
transfer_active = False     # True if a transfer protocol is currently running
cancel_transfer_flag = threading.Event() # Signals protocols to cancel gracefully
session_use_crc32 = False   # True if CRC32 for ZDATA payloads is negotiated for the current session

# --- ZMODEM Protocol Helper Functions ---

def zmodem_escape(data_bytes, esc_ctl=True, esc_8=False):
    """ZDLE-escapes data following Zmodem conventions.

    - Always escapes ZDLE (0x18) -> ZDLE ZDLEE.
    - If esc_ctl is True (default) escapes control characters (< 0x20 and 0x7F)
      by encoding them as ZDLE + (byte ^ 0x40).
    - If esc_8 is True also escapes high-bit bytes (>= 0x80) using the same
      XOR-0x40 transformation (not used by default).

    This mirrors the common Zmodem behaviour and fixes edge-cases where
    control characters or literal ZDLE bytes would corrupt subpacket parsing.
    """
    escaped = bytearray()
    for b in data_bytes:
        # Always escape ZDLE by mapping to ZDLE ZDLEE
        if b == AKITA_ZDLE[0]:
            escaped.extend(AKITA_ZDLE)
            escaped.extend(AKITA_ZDLEE)
            continue

        # Escape control characters (C0) when requested
        if esc_ctl and (b < 0x20 or b == 0x7f):
            escaped.extend(AKITA_ZDLE)
            escaped.append(b ^ 0x40)
            continue

        # Optionally escape 8th-bit characters (ESC8)
        if esc_8 and b >= 0x80:
            escaped.extend(AKITA_ZDLE)
            escaped.append((b ^ 0x40) & 0xff)
            continue

        # Default: append unchanged
        escaped.append(b)

    return bytes(escaped) 

def zmodem_unescape(escaped_data_bytes, esc_8=False):
    """Reverse ZDLE escaping produced by zmodem_escape.

    - ZDLE ZDLEE -> literal ZDLE
    - ZDLE <ch> where <ch> != ZDLEE -> original_byte = <ch> ^ 0x40

    esc_8 mirrors the corresponding option in zmodem_escape (kept for symmetry).
    """
    data = bytearray()
    i = 0
    while i < len(escaped_data_bytes):
        b = escaped_data_bytes[i]
        if b == AKITA_ZDLE[0]:
            i += 1
            if i >= len(escaped_data_bytes):
                R.log("ZMODEM: Trailing ZDLE in unescape, data may be truncated.", R.LOG_WARNING)
                break
            nb = escaped_data_bytes[i]
            if nb == AKITA_ZDLEE[0]:
                data.append(AKITA_ZDLE[0])
            else:
                # Reverse the XOR-0x40 mapping used for escaped bytes
                orig = nb ^ 0x40
                data.append(orig & 0xff)
        else:
            data.append(b)
        i += 1
    return bytes(data) 

def build_zmodem_header(frame_type, data_val=0):
    """Builds a simplified Zmodem binary header with CRC16."""
    # Header structure: ZPAD ZDLE ZBIN frame_type(1) data_val(4) crc16(2)
    # data_val is typically ZF0-ZF3 (flags) or ZP0-ZP3 (position)
    frame = AKITA_ZPAD + AKITA_ZDLE + AKITA_ZBIN
    header_content = bytes([frame_type]) + data_val.to_bytes(4, 'little', signed=False)
    frame += header_content
    crc = crc16_func(header_content) # CRC16 is on type + data_val
    frame += crc.to_bytes(2, 'little')
    return bytes(frame)

def parse_zmodem_header(raw_packet):
    """Parses a simplified Zmodem binary header. Returns (type, data_val, header_len_consumed)."""
    if not raw_packet: return AKITA_NO_TYPE, 0, 0

    # Minimum length depends on whether ZPAD is present
    min_len_no_zpad = ZMODEM_HEADER_LENGTH_BIN - 1
    
    header_start_idx = 0
    if raw_packet[0] == AKITA_ZPAD[0]:
        if len(raw_packet) < ZMODEM_HEADER_LENGTH_BIN:
            R.log(f"ZMODEM HDR: Packet too short ({len(raw_packet)}B) even with ZPAD.", R.LOG_DEBUG)
            return AKITA_NO_TYPE, 0, 0
        header_start_idx = 1
    elif len(raw_packet) < min_len_no_zpad:
        R.log(f"ZMODEM HDR: Packet too short ({len(raw_packet)}B) without ZPAD.", R.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0

    # Check for ZDLE ZBIN sequence
    if raw_packet[header_start_idx] != AKITA_ZDLE[0] or \
       raw_packet[header_start_idx+1] != AKITA_ZBIN[0]: # We only support our simplified ZBIN headers
        R.log(f"ZMODEM HDR: Invalid ZDLE/ZBIN marker: {raw_packet[header_start_idx:header_start_idx+2].hex()}", R.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0
    
    # Position after ZPAD (if any) + ZDLE + ZBIN
    content_start_idx = header_start_idx + 2 
    
    # Ensure packet is long enough for header_content (5 bytes) + crc (2 bytes)
    if len(raw_packet) < content_start_idx + 5 + 2:
        R.log(f"ZMODEM HDR: Packet too short for content and CRC. Len: {len(raw_packet)}, Need: {content_start_idx+7}", R.LOG_DEBUG)
        return AKITA_NO_TYPE, 0, 0

    header_content = raw_packet[content_start_idx : content_start_idx + 5] # type(1) + data_val(4)
    crc_bytes = raw_packet[content_start_idx + 5 : content_start_idx + 7]

    # This check should be redundant due to the length check above, but good for sanity
    if len(header_content) != 5 or len(crc_bytes) != 2:
        R.log(f"ZMODEM HDR: Internal logic error - Truncated content or CRC part.", R.LOG_ERROR)
        return AKITA_NO_TYPE, 0, 0

    received_crc = int.from_bytes(crc_bytes, 'little')
    calculated_crc = crc16_func(header_content)

    if received_crc != calculated_crc:
        R.log(f"ZMODEM HDR: Header CRC16 mismatch. Got {received_crc:04x}, calc {calculated_crc:04x}", R.LOG_WARNING)
        return AKITA_NO_TYPE, 0, 0

    frame_type = header_content[0]
    data_val = int.from_bytes(header_content[1:5], 'little', signed=False)
    
    parsed_header_length = content_start_idx + 7 # Total bytes consumed from start of raw_packet
    
    return frame_type, data_val, parsed_header_length

# --- Checkpointing Functions ---
def save_checkpoint(filename, offset, size, mtime=0, mode=0):
    """Saves transfer checkpoint information."""
    # Ensure filename in checkpoint is just the basename
    base_fn = os.path.basename(filename)
    checkpoint_file = os.path.join(receive_directory, f"{base_fn}.checkpoint")
    checkpoint_data = {"filename": base_fn, "offset": offset, "size": size, "mtime": mtime, "mode": mode}
    try:
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f)
        R.log(f"Checkpoint saved: {base_fn} @{offset}, sz {size}, mt {mtime}, md {oct(mode)}", R.LOG_DEBUG)
    except Exception as e:
        R.log(f"Error saving checkpoint {checkpoint_file}: {e}", R.LOG_ERROR)

def load_checkpoint(filename_basename):
    """Loads checkpoint information for a given basename."""
    checkpoint_file = os.path.join(receive_directory, f"{filename_basename}.checkpoint")
    try:
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, "r") as f:
                cp = json.load(f)
                # Add mtime/mode with defaults if not present from older checkpoints
                cp.setdefault('mtime', 0)
                cp.setdefault('mode', 0)
                R.log(f"Checkpoint loaded for {filename_basename}: Offset {cp['offset']}, Size {cp['size']}", R.LOG_INFO)
                return cp
    except Exception as e:
        R.log(f"Error loading checkpoint {checkpoint_file}: {e}", R.LOG_ERROR)
    return None

def delete_checkpoint(filename_basename):
    """Deletes checkpoint file for a given basename."""
    checkpoint_file = os.path.join(receive_directory, f"{filename_basename}.checkpoint")
    try:
        if os.path.exists(checkpoint_file):
            os.remove(checkpoint_file)
            R.log(f"Checkpoint deleted: {filename_basename}", R.LOG_INFO)
    except Exception as e:
        R.log(f"Error deleting checkpoint {checkpoint_file}: {e}", R.LOG_ERROR)

# --- Reticulum Link Callbacks ---
def client_link_established(link):
    global target_link, transfer_event, is_sender_mode, transfer_active, session_use_crc32
    R.log(f"Link established to server {R.prettyhexrep(link.destination_hash)}", R.LOG_INFO)
    target_link = link
    transfer_active = True
    session_use_crc32 = False # Reset for new session
    if is_sender_mode:
        sender_thread = threading.Thread(target=run_zmodem_sender_protocol, name="ZAPS") # Zmodem Akita Protocol Sender
        sender_thread.daemon = True
        sender_thread.start()
    else: # Should not happen for client if logic is correct
        R.log("Client link established but not in sender mode? Tearing down.", R.LOG_ERROR)
        link.teardown()

def client_link_closed(link):
    global target_link, transfer_event, transfer_active
    if link == target_link or target_link is None: # Also handle if target_link was already cleared
        R.log(f"Link to server {R.prettyhexrep(link.destination_hash)} closed.", R.LOG_INFO)
        target_link = None
        transfer_active = False
        cancel_transfer_flag.set() # Signal protocol thread to stop
        transfer_event.set()       # Signal main thread

def server_link_established(link):
    global target_link, transfer_event, is_sender_mode, transfer_active, session_use_crc32
    if target_link is not None and target_link.status != R.Link.CLOSED:
        R.log(f"Server busy with {R.prettyhexrep(target_link.destination_hash)}, rejecting new link from {R.prettyhexrep(link.destination_hash)}.", R.LOG_WARNING)
        link.teardown()
        return

    R.log(f"Link established from client {R.prettyhexrep(link.destination_hash)}", R.LOG_INFO)
    target_link = link
    transfer_active = True
    session_use_crc32 = False # Reset for new session
    cancel_transfer_flag.clear() # Clear flag for a new transfer
    if not is_sender_mode: # Current instance is a receiver
        receiver_thread = threading.Thread(target=run_zmodem_receiver_protocol, name="ZAPR") # Zmodem Akita Protocol Receiver
        receiver_thread.daemon = True
        receiver_thread.start()
    else: # Should not happen for server if logic is correct
        R.log("Server link established but instance is in sender mode? Tearing down.", R.LOG_ERROR)
        link.teardown()

def server_link_closed(link):
    global target_link, transfer_event, transfer_active
    if link == target_link or target_link is None:
        R.log(f"Link from client {R.prettyhexrep(link.destination_hash)} closed.", R.LOG_INFO)
        target_link = None
        transfer_active = False
        cancel_transfer_flag.set()
        transfer_event.set()

# --- ZMODEM SENDER PROTOCOL Thread ---
def run_zmodem_sender_protocol():
    global file_to_send_path, target_link, current_file_size, current_file_offset
    global sender_last_acked_offset, cancel_transfer_flag, transfer_event, session_use_crc32

    R.log("Zmodem Sender Protocol Started", R.LOG_VERBOSE)
    # session_use_crc32 is reset by client_link_established

    file_mtime = 0
    file_mode = 0
    filename_base = ""

    try:
        filename_base = os.path.basename(file_to_send_path)
        file_stat = os.stat(file_to_send_path)
        current_file_size = file_stat.st_size
        file_mtime = int(file_stat.st_mtime)
        file_mode = stat.S_IMODE(file_stat.st_mode) # Get transferable mode bits (permissions)
    except FileNotFoundError:
        R.log(f"Sender: File not found: {file_to_send_path}", R.LOG_ERROR)
        # Link teardown and event set will be handled in finally
        return # Exit protocol thread
    except Exception as e:
        R.log(f"Sender: Error stating file {file_to_send_path}: {e}", R.LOG_ERROR)
        return

    current_file_offset = 0
    sender_last_acked_offset = 0

    try:
        # 1. Send ZRQINIT
        R.log("Sender: Sending ZRQINIT", R.LOG_DEBUG)
        if not target_link or target_link.status == R.Link.CLOSED: return
        target_link.send(build_zmodem_header(AKITA_ZRQINIT))

        # 2. Wait for ZRINIT
        packet = target_link.receive(timeout=10)
        if cancel_transfer_flag.is_set() or not packet:
            R.log("Sender: No ZRINIT received or transfer cancelled.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        
        ptype, pdata_val, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRINIT:
            R.log(f"Sender: Expected ZRINIT, got type {ptype}. Tearing down.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        
        R.log(f"Sender: Received ZRINIT (raw flags value: {pdata_val}, hex: {pdata_val:08x})", R.LOG_DEBUG)
        zf0_flags = pdata_val & 0xFF # ZF0 is the LSB of the 4-byte data_val
        if zf0_flags & AKITA_CANFC32:
            session_use_crc32 = True
            R.log("Sender: Receiver supports CRC32 for ZDATA payloads. Will use if sending data.", R.LOG_INFO)
        else:
            R.log("Sender: Receiver does not advertise CRC32 support for ZDATA payloads.", R.LOG_INFO)

        # 3. Send ZFILE (Header + ZDLE-escaped Info Subpacket)
        zfile_main_header = build_zmodem_header(AKITA_ZFILE, 0) # data_val for ZFILE header is not critical here
        
        clean_filename = filename_base.replace('\0', '_') # Basic sanitization for nulls
        file_info_str = f"{clean_filename}\0{current_file_size} {oct(file_mtime)} {oct(file_mode)}\0"
        file_info_bytes_unescaped = file_info_str.encode('utf-8')
        escaped_file_info_bytes = zmodem_escape(file_info_bytes_unescaped)
        
        zfile_data_subpacket = (AKITA_ZDLE + AKITA_ZBIN +
                                escaped_file_info_bytes +
                                AKITA_ZDLE + AKITA_ZCRCW +
                                crc16_func(file_info_bytes_unescaped).to_bytes(2, 'little'))

        R.log(f"Sender: Sending ZFILE for '{clean_filename}', Size {current_file_size}, MTime {oct(file_mtime)}, Mode {oct(file_mode)}", R.LOG_DEBUG)
        if not target_link or target_link.status == R.Link.CLOSED: return
        target_link.send(zfile_main_header + zfile_data_subpacket)

        # 4. Wait for ZRPOS (Resume Position / ACK for ZFILE)
        packet = target_link.receive(timeout=15)
        if cancel_transfer_flag.is_set() or not packet:
            R.log("Sender: No ZRPOS after ZFILE or transfer cancelled.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return

        ptype, pdata_offset, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRPOS:
            R.log(f"Sender: Expected ZRPOS, got type {ptype} (val {pdata_offset}). Tearing down.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        
        sender_last_acked_offset = pdata_offset
        current_file_offset = sender_last_acked_offset 
        R.log(f"Sender: Received ZRPOS. Starting/resuming data transfer from offset {current_file_offset}", R.LOG_INFO)

        # 5. Send ZDATA packets
        with open(file_to_send_path, 'rb') as f:
            f.seek(current_file_offset)
            send_retries = 0
            max_send_retries = 10 

            while current_file_offset < current_file_size:
                if cancel_transfer_flag.is_set() or not target_link or target_link.status == R.Link.CLOSED:
                    R.log("Sender: Transfer cancelled or link lost during ZDATA loop.", R.LOG_INFO)
                    if target_link and target_link.status != R.Link.CLOSED and current_file_offset < current_file_size : target_link.send(build_zmodem_header(AKITA_ZCAN))
                    break # Exit ZDATA loop

                chunk_size = R.Link.MDU - ZMODEM_HEADER_LENGTH_BIN - 30 # Approx RNS overhead
                if session_use_crc32:
                    chunk_size -= CRC32_LEN
                if chunk_size <= 64: chunk_size = 64 # Minimum practical chunk size

                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    R.log("Sender: Read empty chunk, but not at EOF. File may have changed size or seek error.", R.LOG_WARNING)
                    break # Exit ZDATA loop

                zdata_header = build_zmodem_header(AKITA_ZDATA, current_file_offset)
                payload_to_send = chunk_data
                
                if session_use_crc32:
                    chunk_crc32_val = crc32_func(chunk_data)
                    payload_to_send += chunk_crc32_val.to_bytes(CRC32_LEN, 'little')
                    # R.log(f"Sender: Sending ZDATA @{current_file_offset}, len {len(chunk_data)}, CRC32 {chunk_crc32_val:08x}", R.LOG_EXTREME)
                # else:
                    # R.log(f"Sender: Sending ZDATA @{current_file_offset}, len {len(chunk_data)} (no CRC32)", R.LOG_EXTREME)


                if not target_link or target_link.status == R.Link.CLOSED: break
                target_link.send(zdata_header + payload_to_send)
                
                # ACK Wait loop
                ack_received_for_current_chunk = False
                ack_retries = 0
                max_ack_retries = 3
                while not ack_received_for_current_chunk and ack_retries < max_ack_retries:
                    if cancel_transfer_flag.is_set() or not target_link or target_link.status == R.Link.CLOSED: break
                    
                    ack_packet = target_link.receive(timeout=10) 
                    if ack_packet:
                        ack_type, ack_offset_val, _ = parse_zmodem_header(ack_packet)
                        expected_ack_offset = current_file_offset + len(chunk_data)
                        if ack_type == AKITA_ZACK:
                            if ack_offset_val >= expected_ack_offset or \
                               (ack_offset_val == current_file_size and expected_ack_offset == current_file_size):
                                sender_last_acked_offset = ack_offset_val
                                current_file_offset += len(chunk_data)
                                ack_received_for_current_chunk = True
                                send_retries = 0 # Reset general send retries on successful ACK
                                break 
                            else:
                                R.log(f"Sender: Stale ZACK for offset {ack_offset_val}, expected >= {expected_ack_offset}", R.LOG_DEBUG)
                        elif ack_type == AKITA_ZRPOS: 
                             R.log(f"Sender: Received ZRPOS with offset {ack_offset_val}. Resyncing file pointer.", R.LOG_INFO)
                             current_file_offset = ack_offset_val
                             f.seek(current_file_offset)
                             sender_last_acked_offset = ack_offset_val
                             ack_received_for_current_chunk = True # Break inner loop to resend from new offset
                             break
                        elif ack_type == AKITA_ZNAK: 
                            R.log(f"Sender: Received ZNAK (val {ack_offset_val}). Will resend chunk for offset {current_file_offset}.", R.LOG_WARNING)
                            ack_received_for_current_chunk = True # Break inner loop to resend current chunk
                            break
                        elif ack_type == AKITA_ZCAN:
                            R.log("Sender: Received ZCAN from receiver. Aborting.", R.LOG_INFO)
                            cancel_transfer_flag.set()
                            break
                        else:
                             R.log(f"Sender: Unexpected packet type {ack_type} (val {ack_offset_val}) while waiting for ZACK/ZRPOS.", R.LOG_WARNING)
                             # Loop to wait for ACK again
                    else: # Timeout waiting for ZACK
                        R.log(f"Sender: Timeout waiting for ZACK for chunk at {current_file_offset}. ACK Retry {ack_retries+1}/{max_ack_retries}", R.LOG_WARNING)
                        ack_retries += 1
                
                if not ack_received_for_current_chunk and not cancel_transfer_flag.is_set(): # Failed to get ACK after sub-retries
                    send_retries += 1
                    R.log(f"Sender: Failed to get ACK for chunk at {current_file_offset}. Overall Send Retry {send_retries}/{max_send_retries}", R.LOG_ERROR)
                    if send_retries >= max_send_retries:
                        R.log("Sender: Max overall send retries exceeded. Aborting transfer.", R.LOG_ERROR)
                        if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZABORT))
                        cancel_transfer_flag.set() # Signal cancellation
                        break # Exit ZDATA loop
                    # Will resend the same chunk due to current_file_offset not advancing

            # End of ZDATA while loop

            if cancel_transfer_flag.is_set():
                 R.log("Sender: Transfer cancelled during or after ZDATA phase.", R.LOG_INFO)
            elif current_file_offset >= current_file_size : # Successfully sent all data
                # 6. Send ZEOF
                R.log(f"Sender: Sending ZEOF for offset {current_file_size}", R.LOG_DEBUG)
                if not target_link or target_link.status == R.Link.CLOSED: return
                target_link.send(build_zmodem_header(AKITA_ZEOF, current_file_size))

                # 7. Wait for ZRINIT (or ZACK from receiver acknowledging ZEOF)
                packet = target_link.receive(timeout=10)
                if not (cancel_transfer_flag.is_set() or not packet):
                    ptype, pdata_val, _ = parse_zmodem_header(packet)
                    R.log(f"Sender: Received type {ptype} (val {pdata_val}) after ZEOF.", R.LOG_DEBUG)
                elif not packet:
                     R.log("Sender: No response after ZEOF.", R.LOG_DEBUG)


                # 8. Send ZFIN
                R.log("Sender: Sending ZFIN", R.LOG_DEBUG)
                if not target_link or target_link.status == R.Link.CLOSED: return
                target_link.send(build_zmodem_header(AKITA_ZFIN))
                
                # Optionally wait for receiver's ZFIN
                packet = target_link.receive(timeout=5) 
                if packet:
                    ptype, _, _ = parse_zmodem_header(packet)
                    if ptype == AKITA_ZFIN: R.log("Sender: Received final ZFIN from receiver. Transfer complete.", R.LOG_INFO)
                    else: R.log(f"Sender: Received type {ptype} instead of final ZFIN from receiver.", R.LOG_DEBUG)
                else: R.log("Sender: No final ZFIN from receiver. Assuming complete.", R.LOG_DEBUG)
                
                print(f"\nFile '{filename_base}' sent successfully.")
            else: # Loop exited but not EOF and not cancelled - implies an unhandled error or file size issue
                R.log(f"Sender: Data loop exited prematurely. Sent Offset {current_file_offset}/{current_file_size}. This may indicate an issue.", R.LOG_ERROR)
                if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZABORT))


    except Exception as e_outer:
        R.log(f"Sender: Unhandled exception during transfer: {e_outer}", R.LOG_CRITICAL)
        import traceback
        R.log(traceback.format_exc(), R.LOG_ERROR)
        if target_link and target_link.status != R.Link.CLOSED:
            try: target_link.send(build_zmodem_header(AKITA_ZABORT))
            except Exception as e_abort: R.log(f"Sender: Error sending ABORT on exception: {e_abort}",R.LOG_ERROR)
    finally:
        if target_link and target_link.status != R.Link.CLOSED:
            target_link.teardown()
        target_link = None # Important to clear the global link reference
        transfer_event.set() # Signal main thread that this attempt is over
        R.log("Sender: Protocol Finished.", R.LOG_VERBOSE)

# --- ZMODEM RECEIVER PROTOCOL Thread ---
def run_zmodem_receiver_protocol():
    global target_link, receive_file_path, current_file_size, current_file_offset
    global receive_directory, receiver_last_written_offset, cancel_transfer_flag, transfer_event, session_use_crc32
    
    R.log("Zmodem Receiver Protocol Started", R.LOG_VERBOSE)
    # session_use_crc32 is reset by server_link_established

    file_handle = None
    received_filename_base = None # Basename of the file being received
    expected_file_mtime = 0
    expected_file_mode = 0
    resumed_transfer = False
    receiver_last_written_offset = 0

    try:
        # 1. Wait for ZRQINIT
        packet = target_link.receive(timeout=600) # Long timeout for initial contact
        if cancel_transfer_flag.is_set() or not packet:
            R.log("Receiver: No ZRQINIT received or transfer cancelled.", R.LOG_WARNING)
            return # Exit protocol thread

        ptype, _, _ = parse_zmodem_header(packet)
        if ptype != AKITA_ZRQINIT:
            R.log(f"Receiver: Expected ZRQINIT, got type {ptype}. Tearing down.", R.LOG_WARNING)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        R.log("Receiver: Received ZRQINIT", R.LOG_DEBUG)

        # 2. Send ZRINIT, advertising CANFC32 capability
        zrinit_flags = AKITA_CANFC32 # Receiver is capable of CRC32 for ZDATA payloads
        session_use_crc32 = True      # Assume we will use it if sender also does (sender confirms by its ZDATA format)
        R.log(f"Receiver: Sending ZRINIT (flags: {zrinit_flags:08x}, indicating CANFC32)", R.LOG_INFO)
        if not target_link or target_link.status == R.Link.CLOSED: return
        target_link.send(build_zmodem_header(AKITA_ZRINIT, zrinit_flags))

        # 3. Wait for ZFILE frame (Header + ZDLE-escaped Info Subpacket)
        zfile_packet = target_link.receive(timeout=30)
        if cancel_transfer_flag.is_set() or not zfile_packet:
            R.log("Receiver: No ZFILE packet received or transfer cancelled.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return

        ptype, _, zfile_main_header_len = parse_zmodem_header(zfile_packet)
        if ptype != AKITA_ZFILE:
            R.log(f"Receiver: Expected ZFILE, got type {ptype}. Packet dump: {zfile_packet.hex()[:100]}", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        
        # Parse the ZFILE data subpacket part (filename, size, mtime, mode)
        subpacket_start_in_main_packet = zfile_main_header_len
        if not (len(zfile_packet) > subpacket_start_in_main_packet + ZMODEM_SUBPACKET_DATA_PREFIX_LEN and \
                zfile_packet[subpacket_start_in_main_packet : subpacket_start_in_main_packet + ZMODEM_SUBPACKET_DATA_PREFIX_LEN] == (AKITA_ZDLE + AKITA_ZBIN)):
            R.log(f"Receiver: ZFILE missing or incorrect ZDLE+ZBIN for data subpacket. Got: {zfile_packet[subpacket_start_in_main_packet : subpacket_start_in_main_packet + ZMODEM_SUBPACKET_DATA_PREFIX_LEN].hex()}", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
        
        data_payload_start = subpacket_start_in_main_packet + ZMODEM_SUBPACKET_DATA_PREFIX_LEN

        # Find end of escaped data: looking for ZDLE ZCRCW
        trailer_start_idx = -1
        # Search for ZDLE ZCRCW trailer from data_payload_start up to where a trailer could fit
        # ZDLE ZCRCW is 2 bytes, CRC16 is 2 bytes. Min length of escaped data is 0.
        search_end_limit = len(zfile_packet) - (ZMODEM_SUBPACKET_DATA_SUFFIX_LEN - 1) # ensure room for ZDLE+ZCRCW + 2-byte CRC
        for i in range(data_payload_start, search_end_limit): 
            if zfile_packet[i : i + 2] == (AKITA_ZDLE + AKITA_ZCRCW): # ZDLE + 'k'
                trailer_start_idx = i
                break
        
        if trailer_start_idx == -1:
            R.log(f"Receiver: ZFILE data subpacket ZDLE+ZCRCW trailer not found in packet of len {len(zfile_packet)}.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return

        escaped_file_info_bytes = zfile_packet[data_payload_start : trailer_start_idx]
        
        # CRC for subpacket is after ZDLE+ZCRCW
        subpacket_crc_bytes_start = trailer_start_idx + 2 # Past ZDLE + ZCRCW character
        subpacket_crc_bytes = zfile_packet[subpacket_crc_bytes_start : subpacket_crc_bytes_start + 2]

        if len(subpacket_crc_bytes) != 2:
            R.log(f"Receiver: ZFILE data subpacket CRC is truncated. Found {len(subpacket_crc_bytes)} bytes.", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZCAN))
            return
            
        received_subpacket_crc16 = int.from_bytes(subpacket_crc_bytes, 'little')
        
        file_info_bytes_unescaped = zmodem_unescape(escaped_file_info_bytes)
        calculated_subpacket_crc16 = crc16_func(file_info_bytes_unescaped)

        if received_subpacket_crc16 != calculated_subpacket_crc16:
            R.log(f"Receiver: ZFILE data subpacket CRC16 mismatch! Got {received_subpacket_crc16:04x}, calc {calculated_subpacket_crc16:04x}. Unescaped data: '{file_info_bytes_unescaped.decode('utf-8', 'replace')}'", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZNAK)) # NAK general error
            return

        # Parse the unescaped "filename\0size mtime mode\0" string
        try:
            file_info_str = file_info_bytes_unescaped.decode('utf-8')
            parts = file_info_str.strip('\0').split('\0')
            received_filename_base = os.path.basename(parts[0]) # Sanitize: always use basename
            
            if len(parts) > 1 and parts[1].strip(): # Ensure attributes part is not empty
                attrs_str = parts[1].split(' ')
                if len(attrs_str) >= 3:
                    current_file_size = int(attrs_str[0])
                    expected_file_mtime = int(attrs_str[1], 8) # mtime is octal string
                    expected_file_mode = int(attrs_str[2], 8)  # mode is octal string
                else:
                    raise ValueError("ZFILE attributes string part is incomplete.")
            else: 
                raise ValueError("ZFILE info string missing attributes part or filename.")

            R.log(f"Receiver: Parsed ZFILE for '{received_filename_base}', Size {current_file_size}, MTime {oct(expected_file_mtime)}, Mode {oct(expected_file_mode)}", R.LOG_INFO)

        except Exception as e:
            R.log(f"Receiver: Error parsing ZFILE info string '{file_info_bytes_unescaped.decode('utf-8','replace')}': {e}", R.LOG_ERROR)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZFERR)) # Fatal error parsing info
            return
            
        # Overwrite protection / Resume logic
        receive_file_path = os.path.join(receive_directory, received_filename_base)
        os.makedirs(os.path.dirname(receive_file_path), exist_ok=True) # Ensure directory exists

        checkpoint = load_checkpoint(received_filename_base)
        current_file_offset = 0 # This is the offset we want the sender to start from

        if checkpoint and checkpoint['filename'] == received_filename_base and checkpoint['size'] == current_file_size:
            if checkpoint.get('mtime',0) == expected_file_mtime and checkpoint.get('mode',0) == expected_file_mode:
                if os.path.exists(receive_file_path) and os.path.getsize(receive_file_path) == checkpoint['offset']:
                    R.log(f"Receiver: Valid checkpoint found. Requesting resume for '{received_filename_base}' from offset {checkpoint['offset']}.", R.LOG_INFO)
                    current_file_offset = checkpoint['offset']
                    receiver_last_written_offset = current_file_offset
                    resumed_transfer = True
                else: 
                    R.log(f"Receiver: Checkpoint offset {checkpoint['offset']} mismatch with disk file size {os.path.getsize(receive_file_path) if os.path.exists(receive_file_path) else 'N/A'} or file missing. Starting from scratch.", R.LOG_WARNING)
                    delete_checkpoint(received_filename_base)
            else: 
                 R.log(f"Receiver: Checkpoint metadata (mtime {checkpoint.get('mtime',0)} vs {expected_file_mtime} /mode {checkpoint.get('mode',0)} vs {expected_file_mode}) mismatch with new offer. Starting from scratch.", R.LOG_WARNING)
                 delete_checkpoint(received_filename_base)
        elif os.path.exists(receive_file_path) and not resumed_transfer:
            print(f"File '{received_filename_base}' already exists in '{receive_directory}'.")
            overwrite_choice = input("Overwrite? (y/N): ").strip().lower()
            if overwrite_choice != 'y':
                R.log("Receiver: User chose not to overwrite. Sending ZSKIP.", R.LOG_INFO)
                if not target_link or target_link.status == R.Link.CLOSED: return
                target_link.send(build_zmodem_header(AKITA_ZSKIP))
                return 
            else:
                R.log("Receiver: User chose to overwrite. Deleting existing file and checkpoint.", R.LOG_INFO)
                try:
                    if os.path.exists(receive_file_path): os.remove(receive_file_path)
                    delete_checkpoint(received_filename_base) 
                except Exception as e_del:
                    R.log(f"Receiver: Could not remove existing file '{receive_file_path}' for overwrite: {e_del}",R.LOG_ERROR)
                    if not target_link or target_link.status == R.Link.CLOSED: return
                    target_link.send(build_zmodem_header(AKITA_ZFERR)) # File system error
                    return
        
        if not resumed_transfer: # If starting from scratch (no resume or overwrite chosen)
            current_file_offset = 0
            receiver_last_written_offset = 0

        # 4. Send ZRPOS with the offset we want to start/resume from
        R.log(f"Receiver: Sending ZRPOS with offset {current_file_offset}", R.LOG_DEBUG)
        if not target_link or target_link.status == R.Link.CLOSED: return
        target_link.send(build_zmodem_header(AKITA_ZRPOS, current_file_offset))

        # 5. Receive ZDATA packets
        file_open_mode = 'r+b' if resumed_transfer and current_file_offset > 0 else 'wb'
        if not os.path.exists(receive_file_path) and file_open_mode == 'r+b': # File might have been deleted since checkpoint
            R.log(f"Receiver: Resumed file path '{receive_file_path}' does not exist, switching to 'wb'. Resetting offset.", R.LOG_WARNING)
            file_open_mode = 'wb'
            current_file_offset = 0 
            receiver_last_written_offset = 0
        
        try:
            file_handle = open(receive_file_path, file_open_mode)
            if current_file_offset > 0 and file_open_mode == 'r+b': # If resuming, seek to correct position
                file_handle.seek(current_file_offset)
                if file_handle.tell() != current_file_offset: # Verify seek
                    R.log(f"Receiver: Seek to offset {current_file_offset} failed (current pos: {file_handle.tell()}). Falling back to overwrite.", R.LOG_ERROR)
                    file_handle.close()
                    file_handle = open(receive_file_path, 'wb') # Fallback to overwrite from start
                    current_file_offset = 0
                    receiver_last_written_offset = 0
        except Exception as e_open:
            R.log(f"Receiver: Critical error opening file '{receive_file_path}' in mode '{file_open_mode}': {e_open}", R.LOG_CRITICAL)
            if target_link and target_link.status != R.Link.CLOSED: target_link.send(build_zmodem_header(AKITA_ZFERR))
            return


        while receiver_last_written_offset < current_file_size:
            if cancel_transfer_flag.is_set() or not target_link or target_link.status == R.Link.CLOSED:
                R.log("Receiver: Transfer cancelled or link lost during ZDATA reception.", R.LOG_INFO)
                break
            
            data_packet = target_link.receive(timeout=20) 
            if not data_packet:
                R.log("Receiver: Timeout waiting for ZDATA. Requesting ZRPOS for current offset.", R.LOG_WARNING)
                if not target_link or target_link.status == R.Link.CLOSED: break
                target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset))
                continue

            ptype, pdata_offset, data_header_len = parse_zmodem_header(data_packet)
            
            if ptype == AKITA_ZDATA:
                chunk_with_potential_crc = data_packet[data_header_len:]
                actual_chunk_data = None
                
                if session_use_crc32: # Check if CRC32 is expected for this session
                    if len(chunk_with_potential_crc) < CRC32_LEN:
                        R.log(f"Receiver: ZDATA packet payload too short for CRC32. Offset {pdata_offset}, Len: {len(chunk_with_potential_crc)}", R.LOG_ERROR)
                        if not target_link or target_link.status == R.Link.CLOSED: break
                        target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)) 
                        continue # Get this packet again
                    
                    actual_chunk_data = chunk_with_potential_crc[:-CRC32_LEN]
                    received_payload_crc32 = int.from_bytes(chunk_with_potential_crc[-CRC32_LEN:], 'little')
                    calculated_payload_crc32 = crc32_func(actual_chunk_data)

                    if received_payload_crc32 != calculated_payload_crc32:
                        R.log(f"Receiver: ZDATA payload CRC32 mismatch! Offset {pdata_offset}. Got {received_payload_crc32:08x}, calc {calculated_payload_crc32:08x}", R.LOG_ERROR)
                        if not target_link or target_link.status == R.Link.CLOSED: break
                        target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset)) 
                        continue # Request retransmission from last known good offset
                    # else: CRC32 for payload is OK
                    # R.log(f"Receiver: ZDATA payload CRC32 OK for offset {pdata_offset}", R.LOG_EXTREME)
                else: # No CRC32 expected for ZDATA payload in this session
                    actual_chunk_data = chunk_with_potential_crc

                # Process the (now validated if CRC32) actual_chunk_data
                if pdata_offset == receiver_last_written_offset: # Correct offset
                    file_handle.write(actual_chunk_data)
                    file_handle.flush() # Ensure data is written for checkpointing
                    receiver_last_written_offset += len(actual_chunk_data)
                    save_checkpoint(received_filename_base, receiver_last_written_offset, current_file_size, expected_file_mtime, expected_file_mode)
                    
                    if not target_link or target_link.status == R.Link.CLOSED: break
                    target_link.send(build_zmodem_header(AKITA_ZACK, receiver_last_written_offset)) # ACK with *new* total bytes received
                    
                    progress = (receiver_last_written_offset / current_file_size) * 100 if current_file_size > 0 else 100.0
                    sys.stdout.write(f"\rReceiving '{received_filename_base}': {receiver_last_written_offset}/{current_file_size} bytes ({progress:.2f}%)  ")
                    sys.stdout.flush()

                elif pdata_offset < receiver_last_written_offset: 
                    R.log(f"Receiver: Duplicate ZDATA for offset {pdata_offset} (already have up to {receiver_last_written_offset}). Acknowledging current progress.", R.LOG_DEBUG)
                    if not target_link or target_link.status == R.Link.CLOSED: break
                    target_link.send(build_zmodem_header(AKITA_ZACK, receiver_last_written_offset))
                else: # Gap detected (pdata_offset > receiver_last_written_offset)
                    R.log(f"Receiver: Gap in ZDATA. Expected offset {receiver_last_written_offset}, got {pdata_offset}. Requesting ZRPOS.", R.LOG_WARNING)
                    if not target_link or target_link.status == R.Link.CLOSED: break
                    target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset))
            
            elif ptype == AKITA_ZEOF:
                eof_reported_offset = pdata_offset # ZEOF header's data_val should be total file size
                R.log(f"Receiver: Received ZEOF (reports offset/size {eof_reported_offset}). Current written: {receiver_last_written_offset}, Expected total: {current_file_size}", R.LOG_DEBUG)
                if receiver_last_written_offset == current_file_size and eof_reported_offset == current_file_size:
                    R.log("Receiver: File data transfer complete and matches ZEOF.", R.LOG_INFO)
                    if not target_link or target_link.status == R.Link.CLOSED: break
                    target_link.send(build_zmodem_header(AKITA_ZRINIT)) # Acknowledge ZEOF with ZRINIT
                    break # Exit ZDATA loop successfully
                else:
                    R.log(f"Receiver: ZEOF size/offset mismatch! Expected total {current_file_size}, actually wrote {receiver_last_written_offset}, ZEOF reports {eof_reported_offset}. Requesting ZRPOS.", R.LOG_ERROR)
                    if not target_link or target_link.status == R.Link.CLOSED: break
                    target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset))

            elif ptype == AKITA_ZCAN or ptype == AKITA_ZABORT:
                R.log("Receiver: Received ZCAN/ZABORT from sender. Transfer cancelled by sender.", R.LOG_INFO)
                cancel_transfer_flag.set() # Set flag to ensure graceful exit
                break
            else: # Unexpected packet type during data transfer
                R.log(f"Receiver: Expected ZDATA or ZEOF, got type {ptype} (val {pdata_offset}). Requesting ZRPOS.", R.LOG_WARNING)
                if not target_link or target_link.status == R.Link.CLOSED: break
                target_link.send(build_zmodem_header(AKITA_ZRPOS, receiver_last_written_offset))
        
        # End of ZDATA while loop

        if file_handle: # Ensure file is closed
            file_handle.close()
            file_handle = None

        if cancel_transfer_flag.is_set() and received_filename_base:
            R.log(f"Receiver: Transfer for '{received_filename_base}' was cancelled during data phase. Checkpoint (if any) is preserved.", R.LOG_INFO)
            # No further action, main loop will reset
            return 

        # Check if transfer was successful and complete
        if receiver_last_written_offset == current_file_size and received_filename_base:
            # Set file mtime and mode
            try:
                if expected_file_mtime > 0: # Ensure mtime was parsed
                    os.utime(receive_file_path, (expected_file_mtime, expected_file_mtime)) # (atime, mtime)
                if expected_file_mode > 0: # Ensure mode was parsed
                    os.chmod(receive_file_path, expected_file_mode)
                R.log(f"Receiver: Successfully set mtime {oct(expected_file_mtime)} and mode {oct(expected_file_mode)} for '{received_filename_base}'", R.LOG_INFO)
            except Exception as e_attr:
                R.log(f"Receiver: Error setting file attributes for '{received_filename_base}': {e_attr}", R.LOG_WARNING)

            # 7. Wait for ZFIN from sender
            if not target_link or target_link.status == R.Link.CLOSED: return # Link might have dropped
            packet = target_link.receive(timeout=10)
            if packet:
                ptype, _, _ = parse_zmodem_header(packet)
                if ptype == AKITA_ZFIN:
                    R.log("Receiver: Received ZFIN from sender. Sending final ZFIN.", R.LOG_DEBUG)
                    if not target_link or target_link.status == R.Link.CLOSED: return
                    target_link.send(build_zmodem_header(AKITA_ZFIN)) # Respond with our ZFIN
                    delete_checkpoint(received_filename_base) # Successful, delete checkpoint
                    print(f"\nFile '{received_filename_base}' received successfully to '{os.path.abspath(receive_file_path)}'.")
                else: # Unexpected packet instead of ZFIN
                    R.log(f"Receiver: Expected ZFIN from sender, got type {ptype}. Assuming transfer still finished.", R.LOG_WARNING)
                    delete_checkpoint(received_filename_base) # File is complete, so delete checkpoint
                    print(f"\nFile '{received_filename_base}' received (unexpected packet post ZEOF) to '{os.path.abspath(receive_file_path)}'.")
            else: # Timeout waiting for ZFIN from sender
                R.log("Receiver: Timeout waiting for ZFIN from sender. Assuming transfer finished as file data is complete.", R.LOG_WARNING)
                delete_checkpoint(received_filename_base)
                print(f"\nFile '{received_filename_base}' received (no ZFIN from sender) to '{os.path.abspath(receive_file_path)}'.")
        elif received_filename_base: # File incomplete but we know its name
            print(f"\nFile transfer for '{received_filename_base}' appears incomplete. Received {receiver_last_written_offset}/{current_file_size} bytes.")
            R.log(f"Receiver: File transfer for '{received_filename_base}' incomplete. Got {receiver_last_written_offset}/{current_file_size}", R.LOG_ERROR)
        else: # Incomplete and filename never determined (should not happen if ZFILE was processed)
            R.log(f"Receiver: File transfer ended incompletely, and filename was not determined.", R.LOG_ERROR)

    except KeyboardInterrupt:
        R.log("Receiver: Keyboard interrupt during protocol.", R.LOG_INFO)
        cancel_transfer_flag.set() # Signal main loop and potentially sender
        if target_link and target_link.status != R.Link.CLOSED:
            target_link.send(build_zmodem_header(AKITA_ZCAN)) # Try to notify sender
    except Exception as e_outer_recv:
        R.log(f"Receiver: Unhandled exception during transfer: {e_outer_recv}", R.LOG_CRITICAL)
        import traceback
        R.log(traceback.format_exc(), R.LOG_ERROR)
        if target_link and target_link.status != R.Link.CLOSED:
            try: target_link.send(build_zmodem_header(AKITA_ZFERR)) # Fatal error
            except Exception as e_ferr: R.log(f"Receiver: Error sending ZFERR on exception: {e_ferr}", R.LOG_ERROR)
    finally:
        if file_handle: # Ensure file is closed on any exit path
            file_handle.close()
        if target_link and target_link.status != R.Link.CLOSED:
            target_link.teardown() # Close the link
        target_link = None # Clear global link reference
        transfer_event.set() # Signal main thread that this attempt is over
        R.log("Receiver: Protocol Finished.", R.LOG_VERBOSE)

# --- Main Application Logic ---
def main():
    global reticulum_instance, identity, destination_hash_hex, file_to_send_path
    global is_sender_mode, receive_directory, transfer_event, cancel_transfer_flag, target_link

    parser = argparse.ArgumentParser(
        description="Akita Zmodem for Reticulum: File transfer over RNS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("mode", choices=['send', 'receive'], help="Mode of operation: 'send' or 'receive'.")
    parser.add_argument("-i", "--identity", metavar="PATH",
                        help="Path to Reticulum identity file.\nIf not specified, uses/creates '~/.akili_zmodem_id.key'.")
    parser.add_argument("-d", "--destination", metavar="HASH",
                        help="Receiver's Reticulum destination hash (Announce or Full Node hash).\nRequired for 'send' mode.")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="Path to the file to send.\nRequired for 'send' mode.")
    parser.add_argument("--recvdir", metavar="PATH", default="~/akita_received_files/",
                        help="Directory to save received files.\n(Default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity level for logging:\n  -v for INFO, -vv for DEBUG, -vvv for EXTREME.\n  Default is NOTICE.")

    args = parser.parse_args()

    # Setup logging level based on verbosity
    if args.verbose == 1: R.loglevel = R.LOG_INFO
    elif args.verbose == 2: R.loglevel = R.LOG_DEBUG
    elif args.verbose >= 3: R.loglevel = R.LOG_EXTREME
    else: R.loglevel = R.LOG_NOTICE # Default
        
    receive_directory = os.path.expanduser(args.recvdir)
    try:
        os.makedirs(receive_directory, exist_ok=True)
        R.log(f"Receive directory set to: {os.path.abspath(receive_directory)}", R.LOG_DEBUG)
    except Exception as e:
        print(f"Error: Could not create receive directory '{receive_directory}': {e}")
        sys.exit(1)

    # Initialize Reticulum Identity
    identity_path_to_use = None
    if args.identity:
        identity_path_to_use = os.path.expanduser(args.identity)
    else:
        # Akita Zmodem ID Location Initializer (default path)
        identity_path_to_use = os.path.expanduser("~/.akili_zmodem_id.key") 

    if not os.path.exists(identity_path_to_use):
        R.log(f"Identity file '{identity_path_to_use}' not found. Creating new one.", R.LOG_NOTICE)
        identity = R.Identity()
        try:
            identity.to_file(identity_path_to_use)
            R.log(f"New identity created and saved to '{identity_path_to_use}'", R.LOG_INFO)
        except Exception as e:
            print(f"Error: Could not save new identity to '{identity_path_to_use}': {e}")
            sys.exit(1)
    else:
        try:
            identity = R.Identity.from_file(identity_path_to_use)
            if identity is None: # Should not happen if from_file doesn't raise exception
                 raise ValueError("Identity.from_file returned None")
            R.log(f"Identity loaded from '{identity_path_to_use}'.", R.LOG_INFO)
        except Exception as e:
            print(f"Error: Could not load identity from '{identity_path_to_use}'.")
            print(f"Ensure it's a valid Reticulum identity file. Error details: {e}")
            sys.exit(1)
    
    # Start Reticulum
    reticulum_instance = R.Reticulum(identity=identity, loglevel=R.loglevel)
    R.log(f"Reticulum Identity: {R.prettyhexrep(identity.get_hash())} ({identity_path_to_use})", R.LOG_NOTICE)
    R.log(f"Reticulum effective log level: {R.loglevel}", R.LOG_DEBUG) # Confirm RNS log level

    # Mode-specific logic
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
            print(f"Error: Path specified for sending is not a file: '{file_to_send_path}'")
            sys.exit(1)
        
        # Validate destination hash format/length
        try:
            dest_bytes = R.hexrep_to_bytes(destination_hash_hex)
            # Check against full node hash, truncated node hash, or destination (announce) hash
            if not (len(dest_bytes) == R.Identity.HASHLENGTH//8 or \
                    len(dest_bytes) == R.Identity.TRUNCATED_HASHLENGTH//8 or \
                    len(dest_bytes) == R.Destination.DESTINATION_HASH_LENGTH//8):
                 raise ValueError(f"Invalid destination hash length: {len(dest_bytes)*8} bits. Expected {R.Destination.DESTINATION_HASH_LENGTH}, {R.Identity.TRUNCATED_HASHLENGTH}, or {R.Identity.HASHLENGTH} bits.")
        except Exception as e:
            print(f"Error: Invalid destination hash '{destination_hash_hex}': {e}")
            sys.exit(1)

        R.log(f"Sender mode active. Target: {destination_hash_hex}, File: '{file_to_send_path}'", R.LOG_INFO)
        
        # Create an OUT destination for the client side of the link
        # Aspects for client OUT destinations are locally significant only.
        temp_client_dst = R.Destination(
            identity,
            R.Destination.OUT,
            R.Destination.SINGLE, # Important for OUT destinations to get callbacks correctly
            AKITA_APP_NAME,
            "transfer_client" 
        )

        target_rns_destination_obj = R.Destination.hash_from_bytes_or_string(destination_hash_hex)
        
        R.log(f"Attempting to create link to {R.prettyhexrep(target_rns_destination_obj)} using our OUT destination aspect {temp_client_dst.aspect_packed()}", R.LOG_DEBUG)
        
        # Create and configure the link
        link = R.Link(destination_hash_or_instance=target_rns_destination_obj, destination=temp_client_dst)
        link.set_link_established_callback(client_link_established)
        link.set_link_closed_callback(client_link_closed)
        
        print(f"Attempting to connect to {destination_hash_hex} to send '{os.path.basename(file_to_send_path)}'...")
        transfer_event.wait() # Block main thread until sender protocol thread signals completion or error

    elif args.mode == 'receive':
        is_sender_mode = False
        R.log("Receiver mode active. Setting up listener...", R.LOG_INFO)

        # Create an IN destination for the server to listen on
        server_destination = R.Destination(
            identity,
            R.Destination.IN,
            R.Destination.SINGLE, # Only one client Link at a time for this app aspect
            AKITA_APP_NAME,
            "transfer_server" # Specific aspect for this Zmodem server
        )
        server_destination.set_link_established_callback(server_link_established)
        # Note: server_destination.set_link_closed_callback is not typically used;
        # link_closed is handled by the Link object itself via client_link_closed/server_link_closed.

        server_destination.announce() # Make the destination discoverable
        announce_hash_hex = R.prettyhexrep(server_destination.hash) # This is the service-specific hash
        
        print(f"Receiver started and listening for connections.")
        print(f"  Reticulum Full Node Address: {R.prettyhexrep(identity.get_hash())}")
        print(f"  Service Announce Hash:     {announce_hash_hex} (for aspect: {AKITA_APP_NAME}/transfer_server)")
        print(f"  Received files will be saved in: {os.path.abspath(receive_directory)}")
        print("Press Ctrl+C to stop listening.")
        
        try:
            while not cancel_transfer_flag.is_set(): # Main listening loop for receiver
                if transfer_event.is_set(): # A transfer attempt (link session) has completed or failed
                    R.log("Receiver: Transfer attempt finished. Resetting to listen for new connection.", R.LOG_INFO)
                    # Ensure target_link is cleared if the link_closed callback didn't manage to
                    if target_link and target_link.status != R.Link.CLOSED :
                        R.log("Receiver: Forcing teardown of previous link.", R.LOG_DEBUG)
                        target_link.teardown()
                    target_link = None 
                    transfer_active = False # Ensure this is reset
                    # cancel_transfer_flag is managed by link callbacks for specific transfers
                    transfer_event.clear() # Ready for next event
                    R.log("Receiver ready for new connection.", R.LOG_INFO)
                time.sleep(0.2) # Keep main thread alive, poll cancel_transfer_flag
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Shutting down receiver gracefully...")
            cancel_transfer_flag.set() # Signal any active protocol threads and the loop
            if target_link and target_link.status != R.Link.CLOSED:
                R.log("Receiver: Tearing down active link due to shutdown.", R.LOG_DEBUG)
                target_link.teardown()
        
    # Cleanup for both modes
    if reticulum_instance: 
        R.log("Stopping Reticulum instance...", R.LOG_INFO)
        reticulum_instance.stop()
        # Wait a moment for threads to settle, especially if link teardowns are happening
        # This can help prevent some final error messages on rapid exit.
        time.sleep(0.5) 
    print("Akita Zmodem has stopped.")

if __name__ == "__main__":
    reticulum_instance = None # Ensure it's defined in global scope for the finally block
    try:
        main()
    except Exception as e_main:
        print(f"Fatal error in Akita Zmodem __main__: {e_main}")
        import traceback
        traceback.print_exc()
    finally:
        # This final cleanup ensures Reticulum is stopped even if main() crashes badly.
        if reticulum_instance and reticulum_instance.is_running:
            R.log("Ensuring Reticulum is stopped in final cleanup.", R.LOG_DEBUG)
            reticulum_instance.stop()
