# Akita Zmodem for Reticulum (RNS)

Akita Zmodem for Reticulum is a file transfer utility using a Zmodem-like protocol, designed to operate robustly over the [Reticulum Network Stack](https://reticulum.network/). It facilitates direct file transfers between systems running Reticulum, with a focus on resilience for problematic or low-bandwidth networks. This is achieved by leveraging Reticulum's inherent capabilities for reliable transport and Zmodem's established mechanisms for file transfer management, including resume.

This version is licensed under the GPLv3.

## Features

* **Reticulum Native:** Operates as a proper Reticulum application using Identities, Destinations, and Links for secure and reliable communication.
* **Reliable Transfers:** Builds upon Reticulum Links for underlying packet reliability and sequencing.
* **Resume Capabilities:** Supports resuming interrupted file transfers. Checkpoints are created by the receiver, and transfers are resumed based on matching filename, size, modification time, and mode.
* **Full File Information:** Transfers filename, size, modification timestamp, and file permissions (mode). These attributes are applied to the received file.
* **Negotiable 32-bit CRC for Data:** Supports negotiation of 32-bit CRC (CRC32) for ZDATA packet payloads for enhanced data integrity checking at the Zmodem layer, in addition to Reticulum's own checks.
* **ZDLE Escaping for Protocol Data:** Critical Zmodem protocol data (like the ZFILE information subpacket) is ZDLE-escaped for robustness.
* **File Overwrite Protection:** Prompts the user before overwriting existing files on the receiver if a transfer cannot be confidently resumed.
* **Sender and Receiver Modes:** Clear command-line driven roles.
* **Persistent Identities:** Uses Reticulum identity files for stable, cryptographic addressing (default: `~/.akili_zmodem_id.key`).
* **Problematic Network Friendly:** Designed with Reticulum's strengths for challenging network conditions.
* **Basic Progress Display:** Shows percentage and byte count for receiving files.
* **Command-Line Interface:** Easy operation via CLI arguments with verbosity options.

## Prerequisites

* Python 3.7 or higher
* Reticulum Network Stack library installed (`pip install rns`)
* `crcmod` library installed (`pip install crcmod`)

## Installation

1.  **Install Reticulum:**
    If you haven't already, install the Reticulum library. The recommended way is via pip:
    ```bash
    pip install rns
    ```
    For more detailed instructions, refer to the [official Reticulum installation guide](https://reticulum.network/manual/installation.html).

2.  **Install `crcmod`:**
    This library is used for CRC (Cyclic Redundancy Check) calculations.
    ```bash
    pip install crcmod
    ```

3.  **Get Akita Zmodem Script:**
    * **Clone the repository:**
        ```bash
        git clone [https://github.com/AkitaEngineering/Akita-Zmodem-for-Reticulum]
        cd Akita-Zmodem-for-Reticulum
        ```
    * **Or, save the script:**
        Download or save the `akita_zmodem_rns.py` script to your system. Make it executable if desired:
        ```bash
        chmod +x akita_zmodem_rns.py
        ```

## Configuration & Usage

Akita Zmodem uses command-line arguments for its operation. A Reticulum identity file is required; if not specified, one will be created by default at `~/.akili_zmodem_id.key`.

**Identity Management:**
Both sender and receiver instances require a Reticulum identity.
* Use the `-i PATH` or `--identity PATH` argument to specify the path to your Reticulum identity file.
* If an identity path is not provided, or if the specified file does not exist, the script will attempt to create and save a new identity at the specified path (or the default `~/.akili_zmodem_id.key`).
* It is recommended to use a persistent, backed-up identity file for any node you wish to have a stable Reticulum address.

---

### Receiver Mode

1.  **Start the Receiver:**
    Open a terminal and run the script in receiver mode:
    ```bash
    python akita_zmodem_rns.py receive [OPTIONS]
    ```
    Or, if executable:
    ```bash
    ./akita_zmodem_rns.py receive [OPTIONS]
    ```

    **Receiver Options:**
    * `-i PATH`, `--identity PATH`: Path to your Reticulum identity file.
    * `--recvdir PATH`: Directory where received files will be saved. (Default: `~/akita_received_files/`)
    * `-v, -vv, -vvv`: Verbosity level for logging (INFO, DEBUG, EXTREME respectively).

2.  **Receiver Information:**
    Upon starting, the receiver will display:
    * Its **Full Reticulum Node Address**.
    * Its **Service Announce Hash** specific to the Akita Zmodem service.
    The sender will need one of these hashes (preferably the Service Announce Hash) to connect.

    Example output:
    ```
    Receiver started and listening for connections.
      Reticiculum Full Node Address: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
      Service Announce Hash:     fedcba9876543210 (for aspect: akita_zmodem/transfer_server)
      Received files will be saved in: /home/user/akita_received_files
    Press Ctrl+C to stop listening.
    ```
    The receiver will remain active, listening for incoming connections until manually stopped (e.g., with `Ctrl+C`). After each transfer attempt (successful or failed), it resets to listen for new connections.

---

### Sender Mode

1.  **Start the Sender:**
    Open a terminal and run the script in sender mode, providing the receiver's destination hash and the file to send:
    ```bash
    python akita_zmodem_rns.py send -d <receiver_destination_hash> -f /path/to/yourfile.ext [OPTIONS]
    ```
    Or, if executable:
    ```bash
    ./akita_zmodem_rns.py send -d <receiver_destination_hash> -f /path/to/yourfile.ext [OPTIONS]
    ```

    **Sender Options:**
    * `-d HASH`, `--destination HASH`: **Required.** The Reticulum destination hash of the receiver. This can be the receiver's Full Node Address or, preferably, its Service Announce Hash.
    * `-f PATH`, `--file PATH`: **Required.** The path to the local file you want to send.
    * `-i PATH`, `--identity PATH`: Path to your Reticulum identity file.
    * `-v, -vv, -vvv`: Verbosity level for logging.

**Example Workflow:**

1.  **On the Receiver Machine:**
    ```bash
    ./akita_zmodem_rns.py receive -vv --recvdir /media/shared_drive/transfers/
    ```
    Note the "Service Announce Hash" displayed, for example: `9f8e7d6c5b4a3210`.

2.  **On the Sender Machine:**
    ```bash
    ./akita_zmodem_rns.py send -d 9f8e7d6c5b4a3210 -f ./my_important_archive.zip -vv
    ```
    The sender will attempt to connect to the receiver and transfer the file.

## Checkpoints & Transfer Resume

* When a receiver starts downloading a file, it creates a checkpoint file (e.g., `filename.ext.checkpoint`) in the receive directory. This checkpoint stores the filename, expected total size, received offset, modification time, and file mode.
* If a transfer is interrupted (e.g., network issue, sender/receiver restarted), the Zmodem handshake will occur again upon a new connection attempt for the same file.
* The receiver will check its checkpoint against the incoming file offer from the sender. If the filename, size, mtime, and mode match, and the local partially received file is consistent with the checkpoint's offset, it will request the sender to resume from the last good offset (`ZRPOS`).
* The sender will then seek to that offset in its source file and continue sending data.
* Checkpoints are automatically deleted by the receiver upon successful and complete file transfer. If a transfer is aborted or fails partially, the checkpoint remains, allowing for a potential future resume.

## Notes & Considerations

* **Reticulum Network:** Ensure that a Reticulum network is operational and configured correctly on both the sender and receiver systems, allowing them to communicate. This might involve configuring appropriate interfaces (LoRa, Packet Radio, TCP/IP, UDP/IP, etc.) in your Reticulum configuration file.
* **Firewalls:** If operating over IP-based Reticulum interfaces (like `TC подземный интерфейс` or `UDP интерфейс`), ensure any firewalls between the sender and receiver allow the necessary traffic for Reticulum to function (typically UDP/TCP on port 4242 by default, unless configured otherwise).
* **Single Instance Receiver:** The current receiver implementation can handle one incoming transfer at a time. Once a transfer is complete or a link is closed, it becomes ready for a new connection.
* **Zmodem Simplifications:** While this implementation uses key Zmodem concepts, it is not a full, byte-for-byte compatible Zmodem implementation for all features of the original serial-line protocol. For example, ZDLE escaping is applied to Zmodem protocol control data (like ZFILE info) but not to the raw ZDATA file chunks, as Reticulum Links are expected to provide an 8-bit clean transport.
* **Logging:** Use the `-v`, `-vv`, or `-vvv` flags for increasing levels of diagnostic output, which can be helpful for troubleshooting. Reticulum's own log level is also influenced by these flags.

## Future Enhancements (Potential)

* Support for sending multiple files in a batch.
* Directory (recursive) transfers.
* More granular Zmodem sub-packetization for data (`ZCRCG`, `ZCRCQ`, etc.) for potentially different flow control behavior at the Zmodem layer.
* Implementation of more Zmodem escape sequences (`ESCCTL`, `ESC8`) if operation over less "clean" (non-RNS) intermediate transports becomes a use case.
* A graphical user interface (GUI).
