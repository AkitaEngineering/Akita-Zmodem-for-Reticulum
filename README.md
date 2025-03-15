# Akita Zmodem for Reticulum

Akita Zmodem is a robust and efficient Zmodem file transfer implementation designed specifically for the Reticulum network. It provides reliable file transfers over unstable or high-latency networks, with built-in resume capabilities and advanced error correction.

## Features

* **Reliable File Transfers:** Utilizes the Zmodem protocol for error detection and recovery.
* **Reticulum Integration:** Designed to work seamlessly with the Reticulum network stack.
* **Adaptive Windowing:** Dynamically adjusts the window size for optimal performance.
* **Timeout Management:** Handles network latency and timeouts effectively.
* **Error Handling:** Robust error handling and retransmission mechanisms.
* **CRC Checksum Verification:** Ensures data integrity.
* **Cancel Functionality:** Allows users to cancel ongoing transfers.
* **Resume Capabilities:** Supports resuming interrupted file transfers.
* **Advanced Error Correction:** Includes negative acknowledgments (NAK) for efficient error recovery.
* **File Overwrite Protection:** Prompts users before overwriting existing files.
* **Sender and Receiver Modes:** Provides both sender and receiver functionalities.
* **User-Friendly Interface:** Command-line interface for easy operation.
* **No External Dependencies:** Fully implemented Zmodem protocol within the code.

## Prerequisites

* Python 3.6 or higher
* Reticulum library installed and configured

## Installation

1.  **Install Reticulum:**
    ```bash
    # Follow the Reticulum installation instructions: [https://reticulum.network/](https://reticulum.network/)
    ```
2.  **Clone the repository:**
    ```bash
    git clone [repository_url]
    cd akita-zmodem-reticulum
    ```
3.  **Install crcmod (if not already installed):**
    ```bash
    pip install crcmod
    ```

## Configuration

1.  **Reticulum Identity:**
    * Replace the placeholder `IDENTITY` in the script with your actual Reticulum identity.
2.  **Destination Address:**
    * Replace the placeholder `DESTINATION_ADDRESS` with the Reticulum address of the receiver.
3.  **Receive Directory:**
    * Modify the `RECEIVE_DIRECTORY` variable to specify the directory where received files will be saved.

## Usage

1.  **Run the script:**
    ```bash
    python akita_zmodem.py
    ```
2.  **Select Mode:**
    * Enter `s` for sender mode or `r` for receiver mode.
3.  **Follow Prompts:**
    * If sending, enter the filename to send.

## Example

**Sending a file:**

1.  Run `python akita_zmodem.py` and enter `s`.
2.  Enter the filename you want to send.

**Receiving a file:**

1.  Run `python akita_zmodem.py` and enter `r`.
2.  The receiver will wait for incoming file transfers.

## Notes

* Ensure that a Reticulum node is running on your system.
* The receiver will save received files to the specified `RECEIVE_DIRECTORY`.
* This implementation is designed for use over Reticulum networks.
* Checkpoints are created in the same directory as the file being transfered, and are named filename.checkpoint.

## Future Enhancements

* Graphical user interface.
* More comprehensive logging.
* Further optimizations for performance.
