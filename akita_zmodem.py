import crcmod
import time
import asyncio
import os
import Reticulum as R
import json

# Reticulum configuration (replace with your settings)
IDENTITY = R.Identity()
DESTINATION_ADDRESS = "destination_address"
RECEIVE_DIRECTORY = "./received_files/"

# Akita Zmodem constants
AKITA_ZRQINIT = b'RZQRQY'
AKITA_ZRINIT = b'RZINIT00'
AKITA_ZFILE = b'ZFILE'
AKITA_ZDATA = b'ZDATA'
AKITA_ZEOF = b'ZEOF'
AKITA_ZFIN = b'ZFIN'
AKITA_ZACK = b'ZACK'
AKITA_ZCAN = b'ZCAN'
AKITA_ZNAK = b'ZNAK'

# CRC-16 calculation
crc16_func = crcmod.predefined.mkCrcFun('crc-16')

def akita_calculate_crc16(data):
    return crc16_func(data)

def akita_build_zmodem_packet(type, data):
    packet = type + data
    crc = akita_calculate_crc16(packet)
    crc_bytes = crc.to_bytes(2, 'little')
    return packet + crc_bytes

def akita_parse_zmodem_packet(packet):
    if len(packet) < 2:
        return None, None
    data = packet[:-2]
    received_crc = int.from_bytes(packet[-2:], 'little')
    calculated_crc = akita_calculate_crc16(data)
    if received_crc != calculated_crc:
        return None, None
    if packet.startswith(AKITA_ZRQINIT):
        return AKITA_ZRQINIT, b''
    elif packet.startswith(AKITA_ZRINIT):
        return AKITA_ZRINIT, b''
    elif packet.startswith(AKITA_ZFILE):
        return AKITA_ZFILE, data[len(AKITA_ZFILE):]
    elif packet.startswith(AKITA_ZDATA):
        return AKITA_ZDATA, data[len(AKITA_ZDATA):]
    elif packet.startswith(AKITA_ZEOF):
        return AKITA_ZEOF, b''
    elif packet.startswith(AKITA_ZFIN):
        return AKITA_ZFIN, b''
    elif packet.startswith(AKITA_ZACK):
        return AKITA_ZACK, b''
    elif packet.startswith(AKITA_ZCAN):
        return AKITA_ZCAN, b''
    elif packet.startswith(AKITA_ZNAK):
        return AKITA_ZNAK, b''
    else:
        return None, data

async def akita_reticulum_send(destination, data, timeout=5.0, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            R.Transport.send(R.Address(destination), data)
            return True
        except Exception as e:
            retries += 1
            await asyncio.sleep(random.uniform(0.5, 1.5))
    return False

async def akita_reticulum_receive(timeout=10.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            packet = R.Transport.receive(timeout=0.5)
            if packet:
                return packet.data, str(packet.source)
        except Exception as e:
            pass
        await asyncio.sleep(0.1)
    return None, None

def akita_save_checkpoint(filename, offset, size):
    checkpoint = {"filename": filename, "offset": offset, "size": size}
    with open(f"{filename}.checkpoint", "w") as f:
        json.dump(checkpoint, f)

def akita_load_checkpoint(filename):
    try:
        with open(f"{filename}.checkpoint", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def akita_delete_checkpoint(filename):
    try:
        os.remove(f"{filename}.checkpoint")
    except FileNotFoundError:
        pass

async def akita_zmodem_send_file(destination, filename):
    checkpoint = akita_load_checkpoint(filename)
    start_offset = 0
    if checkpoint:
        start_offset = checkpoint['offset']
        print(f"Resuming transfer from offset {start_offset}")
    try:
        with open(filename, 'rb') as f:
            f.seek(start_offset)
            file_data = f.read()
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return

    if not await akita_reticulum_send(destination, akita_build_zmodem_packet(AKITA_ZRQINIT, b'')):
        print("Initial handshake failed.")
        return
    received_packet, source = await akita_reticulum_receive()
    if not received_packet or akita_parse_zmodem_packet(received_packet)[0] != AKITA_ZRINIT:
        print("Invalid ZRINIT response.")
        return

    file_info = f"{filename},{len(file_data)},{start_offset}".encode('utf-8')
    if not await akita_reticulum_send(destination, akita_build_zmodem_packet(AKITA_ZFILE, file_info)):
        print("File info send failed.")
        return
    received_packet, source = await akita_reticulum_receive()
    if not received_packet or akita_parse_zmodem_packet(received_packet)[0] != AKITA_ZACK:
        print("Invalid ZACK after ZFILE.")
        return

    chunk_size = 128
    offset = start_offset
    window_size = 5
    window = []
    base_timeout = 5.0
    timeout = base_timeout

    while offset < len(file_data) + start_offset:
        while len(window) < window_size and offset < len(file_data) + start_offset:
            chunk = file_data[offset-start_offset:offset-start_offset + chunk_size]
            packet = akita_build_zmodem_packet(AKITA_ZDATA, chunk)
            if not await akita_reticulum_send(destination, packet):
                print("Failed to send packet, resending window.")
                continue
            window.append((offset, packet))
            offset += chunk_size
            akita_save_checkpoint(filename, offset, len(file_data)+start_offset)

        received_packet, source = await akita_reticulum_receive(timeout=timeout)
        if received_packet:
            packet_type, data = akita_parse_zmodem_packet(received_packet)
            if packet_type == AKITA_ZACK:
                acked_offset = int(data.decode())
                new_window = []
                for win_offset, win_packet in window:
                    if win_offset + len(win_packet) - len(AKITA_ZDATA) > acked_offset:
                        new_window.append((win_offset, win_packet))
                window = new_window
                timeout = base_timeout
            elif packet_type == AKITA_ZCAN:
                print("Transfer Cancelled by receiver.")
                return
            elif packet_type == AKITA_ZNAK:
                print("NAK received, resending window.")
                timeout *= 1.2
            else:
                timeout *= 1.2
        else:
            timeout *= 1.5
        if len(window) == 0 and offset >= len(file_data) + start_offset:
            break

    if not await akita_reticulum_send(destination, akita_build_zmodem_packet(AKITA_ZEOF, b'')):
        print("Failed to send EOF.")
        return
    received_packet, source = await akita_reticulum_receive()
    if not received_packet or akita_parse_zmodem_packet(received_packet)[0] != AKITA_ZACK:
        print("Invalid ZACK after ZEOF.")
        return

    if not await akita_reticulum_send(destination, akita_build_zmodem_packet(AKITA_ZFIN, b'')):
        print("Failed to send FIN.")
        return
    akita_delete_checkpoint(filename)
    print(f"File {filename} sent successfully.")

async def akita_zmodem_receive_file():
    received_file = None
    received_filename = None
    received_size = 0
    received_data = b''
    last_acked_offset = 0
    transfer_active = True
    checkpoint = None

    while transfer_active:
        received_packet, source = await akita_reticulum_receive()
        if received_packet:
            packet_type, data = akita_parse_zmodem_packet(received_packet)

            if packet_type == AKITA_ZRQINIT:
                await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZRINIT, b''))

            elif packet_type == AKITA_ZFILE:
                file_info = data.decode('utf-8').split(',')
                received_filename = file_info[0]
                received_size = int(file_info[1])
                start_offset = int(file_info[2])
                received_file = os.path.join(RECEIVE_DIRECTORY, received_filename)
                os.makedirs(os.path.dirname(received_file), exist_ok=True)
                if os.path.exists(received_file) and start_offset==0:
                    overwrite = input(f"File '{received_filename}' already exists. Overwrite? (y/n): ")
                    if overwrite.lower() != 'y':
                        await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZCAN, b''))
                        return
                if start_offset > 0:
                    try:
                        with open(received_file, 'rb') as f:
                            received_data = f.read()
                    except FileNotFoundError:
                        print(f"Error: Could not resume, local file not found.")
                        await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZCAN, b''))
                        return
                    if len(received_data) != start_offset:
                        print(f"Error: Could not resume, local file size mismatch.")
                        await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZCAN, b''))
                        return
                await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZACK, b''))

            elif packet_type == AKITA_ZDATA:
                received_data += data
                last_acked_offset = len(received_data)
                if akita_calculate_crc16(received_data) != akita_calculate_crc16(received_data):
                    await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZNAK, str(last_acked_offset).encode()))
                    received_data = received_data[:-len(data)]
                    last_acked_offset = len(received_data)
                else:
                    await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZACK, str(last_acked_offset).encode()))
                    akita_save_checkpoint(received_filename, last_acked_offset, received_size)

            elif packet_type == AKITA_ZEOF:
                await akita_reticulum_send(source, akita_build_zmodem_packet(AKITA_ZACK, b''))

            elif packet_type == AKITA_ZFIN:
                if received_file:
                    with open(received_file, 'wb') as f:
                        f.write(received_data)
                    print(f"File '{received_filename}' received successfully.")
                akita_delete_checkpoint(received_filename)
                return
            elif packet_type == AKITA_ZCAN:
                print("Transfer Cancelled by sender.")
                akita_delete_checkpoint(received_filename)
                return

        else:
            pass

async def main():
    R.Transport.start()
    mode = input("Enter 's' for send or 'r' for receive: ")
    if mode.lower() == 's':
        filename = input("Enter filename to send: ")
        await akita_zmodem_send_file(DESTINATION_ADDRESS, filename)
    elif mode.lower() == 'r':
        await akita_zmodem_receive_file()
    else:
        print("Invalid mode.")
    R.Transport.stop()

if __name__ == "__main__":
    asyncio.run(main())
