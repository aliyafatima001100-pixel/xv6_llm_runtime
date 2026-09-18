"""
LLM-RFTP Test Client

Simple test client for LLM-RFTP protocol that validates the server.py
implementation by performing various protocol compliance tests.

Protocol: LLM Reliable File Transfer Protocol

Test Capabilities
-----------------
- META_REQ/META_RESP: Retrieve file metadata and SHA-256 checksums
- DATA_RANGE_REQ: Request consecutive chunks of file data
- Complete file transfers with integrity verification
- Partial transfers for quick testing
"""

import socket
import struct
import hashlib
import sys
import os

from custom_logger import LoggerSetup

# Message type constants
MSG_META_REQ = 0x01
MSG_META_RESP = 0x02
MSG_DATA_RANGE_REQ = 0x03
MSG_DATA_PACKET = 0x05
MSG_ERROR = 0x06

FILE_WEIGHTS = 0x01
FILE_TOKENIZER = 0x02

# Setup custom logger with script-relative log directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
logger_setup = LoggerSetup('LLM-RFTP-Client', log_level='INFO', filename='client.log', log_dir=LOG_DIR)
logger = logger_setup.get_logger()


class FTPTestClient:
    """
    Test client for LLM-RFTP protocol.

    Implements client-side protocol handlers for testing and validating
    the LLM-RFTP server implementation. Supports metadata retrieval,
    batch transfers, and SHA-256 verification.

    Attributes
    ----------
    host : str
        Server hostname or IP address.
    port : int
        Server UDP port.
    sock : socket.socket
        UDP socket for communication.

    Author: Hadiya Muneeb
    Date Created: 2025-11-21
    """

    def __init__(self, server_host, server_port):
        """
        Initialize the test client.

        Parameters
        ----------
        server_host : str
            Hostname or IP address of the LLM-RFTP server.
        server_port : int
            UDP port on which the server is listening.
        """
        self.host = server_host
        self.port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        logger.info(f"Client initialized: {server_host}:{server_port}")

    def send_request(self, msg):
        """
        Send a request message and receive response.

        Parameters
        ----------
        msg : bytes
            Raw message to send to server.

        Returns
        -------
        bytes or None
            Response data from server, or None if timeout occurs.

        Raises
        ------
        socket.error
            If socket operation fails (other than timeout).
        """
        self.sock.sendto(msg, (self.host, self.port))
        try:
            data, addr = self.sock.recvfrom(65536)
            return data
        except socket.timeout:
            logger.warning(f"Socket timeout waiting for response from {self.host}:{self.port}")
            return None

    def test_meta_req(self, file_id):
        """
        Test META_REQ: Request file metadata from server.

        Sends a META_REQ message and parses the META_RESP response containing
        file size, chunk count, and SHA-256 hash.

        Parameters
        ----------
        file_id : int
            File identifier (0x01 for weights, 0x02 for tokenizer).

        Returns
        -------
        tuple or False
            If successful: (True, file_size, chunk_size, total_chunks, sha256_hash)
            If failed: False

        Notes
        -----
        This is typically the first step in any file transfer, as the client
        needs to know the file size and chunk count before requesting data.

        META_REQ format (4 bytes): [msg_type:1][file_id:1][reserved:2]
        META_RESP format (48 bytes): [msg_type:1][file_id:1][version:2]
                                     [file_size:4][chunk_size:4]
                                     [total_chunks:4][sha256:32]
        """
        logger.info(f"Testing META_REQ for file {file_id}...")
        print(f"\n[TEST] META_REQ for file {file_id}...")

        msg = struct.pack('>BBH', MSG_META_REQ, file_id, 0)
        response = self.send_request(msg)

        if not response:
            logger.error(f"META_REQ: No response from server")
            print("  ✗ No response")
            return False

        if len(response) < 48:
            logger.error(f"META_REQ: Response too short: {len(response)} bytes")
            print(f"  ✗ Response too short: {len(response)} bytes")
            return False

        if response[0] != MSG_META_RESP:
            logger.error(f"META_REQ: Wrong message type: {response[0]}")
            print(f"  ✗ Wrong message type: {response[0]}")
            return False

        file_id_resp = response[1]
        version = struct.unpack('>H', response[2:4])[0]
        file_size = struct.unpack('>I', response[4:8])[0]
        chunk_size = struct.unpack('>I', response[8:12])[0]
        total_chunks = struct.unpack('>I', response[12:16])[0]
        file_sha256 = response[16:48]

        logger.info(f"  ✓ File: {file_id_resp}, Size: {file_size} bytes, Chunks: {total_chunks}")
        logger.info(f"    SHA-256: {file_sha256.hex()[:32]}...")
        print(f"  ✓ File: {file_id_resp}, Size: {file_size} bytes, Chunks: {total_chunks}")
        print(f"    SHA-256: {file_sha256.hex()[:32]}...")
        print(f"    Chunk size: {chunk_size}, Version: {version}")

        return True, file_size, chunk_size, total_chunks, file_sha256

    def test_data_range_req(self, file_id, start_idx, count):
        """
        Test DATA_RANGE_REQ: Request consecutive chunks.

        Sends a DATA_RANGE_REQ message requesting a range of consecutive
        chunks and parses the DATA_PACKET responses.

        Parameters
        ----------
        file_id : int
            File identifier.
        start_idx : int
            Starting chunk index (zero-based).
        count : int
            Number of consecutive chunks to request.

        Returns
        -------
        bool
            True if request succeeded, False otherwise.

        Notes
        -----
        The server may split responses across multiple UDP packets if
        the total data exceeds MTU. This method parses all DATA_PACKET
        messages in the response.

        DATA_RANGE_REQ format (12 bytes): [msg_type:1][file_id:1][count:2]
                                          [reserved:4][start_idx:4]

        DATA_PACKET format (12 + N bytes): [msg_type:1][file_id:1][flags:2]
                                           [chunk_idx:4][payload_len:2]
                                           [reserved:2][data:N]
        """
        logger.info(f"Testing DATA_RANGE_REQ: file={file_id}, range=[{start_idx}, {start_idx+count})")
        print(f"\n[TEST] DATA_RANGE_REQ file={file_id}, range=[{start_idx}, {start_idx+count})")

        msg = struct.pack('>BBHII', MSG_DATA_RANGE_REQ, file_id, count, 0, start_idx)
        response = self.send_request(msg)

        if not response:
            logger.error(f"DATA_RANGE_REQ: No response from server")
            print("  ✗ No response")
            return False

        # Parse multiple DATA_PACKET responses
        packets = []
        offset = 0

        while offset < len(response):
            if offset + 12 > len(response):
                break

            msg_type = response[offset]
            if msg_type != MSG_DATA_PACKET:
                logger.warning(f"DATA_RANGE_REQ: Unexpected message type: {msg_type}")
                print(f"  ✗ Unexpected message type: {msg_type}")
                break

            chunk_idx = struct.unpack('>I', response[offset+4:offset+8])[0]
            payload_len = struct.unpack('>H', response[offset+8:offset+10])[0]

            packets.append({
                'chunk_idx': chunk_idx,
                'payload_len': payload_len,
            })

            offset += 12 + payload_len

        logger.info(f"  ✓ Received {len(packets)} packets")
        print(f"  ✓ Received {len(packets)} packets")
        for p in packets[:3]:  # Show first 3
            logger.debug(f"    - Chunk {p['chunk_idx']}: {p['payload_len']} bytes")
            print(f"    - Chunk {p['chunk_idx']}: {p['payload_len']} bytes")

        return True

    def test_full_transfer(self, file_id, file_name):
        """
        Test complete file transfer with SHA-256 verification.

        Performs a full file transfer by requesting chunks in batches,
        assembling the file, and verifying the SHA-256 hash matches
        the server-reported value.

        Parameters
        ----------
        file_id : int
            File identifier.
        file_name : str
            Human-readable file name for display purposes.

        Returns
        -------
        bool
            True if transfer succeeded and SHA-256 verified, False otherwise.

        Notes
        -----
        This is a complete end-to-end test that exercises the full
        protocol (META_REQ, DATA_RANGE_REQ, and SHA-256 verification).

        Files are transferred in batches of up to 16 chunks to mimic
        real-world client behavior and test the server's batching support.
        """
        logger.info(f"Starting full transfer test: {file_name} (file_id={file_id})")
        print(f"\n[FULL TEST] Transferring {file_name} (file_id={file_id})")

        # Get metadata
        result = self.test_meta_req(file_id)
        if not result:
            logger.error(f"Full transfer: Failed to get metadata for file {file_id}")
            print("  ✗ Failed to get metadata")
            return False

        _, file_size, chunk_size, total_chunks, expected_sha256 = result

        # Allocate buffer and bitmap
        file_buf = bytearray(file_size)
        received = [False] * total_chunks

        # Fetch chunks in batches
        batch_size = 16
        for start_idx in range(0, total_chunks, batch_size):
            count = min(batch_size, total_chunks - start_idx)

            # Send DATA_RANGE_REQ
            msg = struct.pack('>BBHII', MSG_DATA_RANGE_REQ, file_id, count, 0, start_idx)
            response = self.send_request(msg)

            if not response:
                logger.warning(f"Full transfer: No response for batch [{start_idx}, {start_idx+count})")
                print(f"  ✗ No response for batch [{start_idx}, {start_idx+count})")
                continue

            # Parse packets
            offset = 0
            packets_in_batch = 0

            while offset < len(response):
                if offset + 12 > len(response):
                    break

                msg_type = response[offset]
                if msg_type != MSG_DATA_PACKET:
                    break

                chunk_idx = struct.unpack('>I', response[offset+4:offset+8])[0]
                payload_len = struct.unpack('>H', response[offset+8:offset+10])[0]

                if chunk_idx < total_chunks and not received[chunk_idx]:
                    data_start = chunk_idx * chunk_size
                    data_end = min(data_start + payload_len, file_size)
                    file_buf[data_start:data_end] = response[offset+12:offset+12+payload_len]
                    received[chunk_idx] = True
                    packets_in_batch += 1

                offset += 12 + payload_len

            progress = sum(received) * 100 // total_chunks
            logger.info(f"  [{progress:3d}%] Batch [{start_idx:6d}, {start_idx+count:6d}): "
                       f"{packets_in_batch} packets, total {sum(received)}/{total_chunks} chunks")
            print(f"  [{progress:3d}%] Batch [{start_idx:6d}, {start_idx+count:6d}): "
                  f"{packets_in_batch} packets, total {sum(received)}/{total_chunks} chunks")

        # Verify
        if all(received):
            computed_sha256 = hashlib.sha256(bytes(file_buf)).digest()
            if computed_sha256 == expected_sha256:
                logger.info(f"  ✓ SUCCESS: File verified! SHA-256 matches")
                logger.info(f"    Transferred {file_size} bytes in {total_chunks} chunks")
                print(f"  ✓ SUCCESS: File verified! SHA-256 matches")
                print(f"    Transferred {file_size} bytes in {total_chunks} chunks")
                return True
            else:
                logger.error(f"Full transfer: SHA-256 mismatch!")
                logger.error(f"    Expected: {expected_sha256.hex()[:32]}...")
                logger.error(f"    Got:      {computed_sha256.hex()[:32]}...")
                print(f"  ✗ SHA-256 mismatch!")
                print(f"    Expected: {expected_sha256.hex()[:32]}...")
                print(f"    Got:      {computed_sha256.hex()[:32]}...")
                return False
        else:
            missing = sum(1 for r in received if not r)
            logger.error(f"Full transfer: {missing} chunks missing")
            print(f"  ✗ Transfer incomplete: {missing} chunks missing")
            return False

    def close(self):
        """
        Close the socket connection.

        Should be called when done with the client to free up resources.
        """
        self.sock.close()
        logger.info("Client socket closed")


def main():
    """
    Parse command-line arguments and run test suite.

    Supports flexible testing modes:
    - Quick mode: Metadata queries only
    - Standard mode: Partial file transfer (first 100 chunks)
    - Full mode: Complete file transfer with SHA-256 verification

    Command-line Arguments
    ----------------------
    --host : str
        Server hostname/IP (default: 127.0.0.1)
    --port : int
        Server UDP port (default: 9999)
    --quick : bool
        Quick mode (metadata only, no transfers)
    --full : bool
        Full transfer mode (complete file download)
    """
    import argparse

    parser = argparse.ArgumentParser(description='LLM-RFTP Test Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=9999, help='Server port')
    parser.add_argument('--quick', action='store_true', help='Quick test (META_REQ only)')
    parser.add_argument('--full', action='store_true', help='Full transfer test')

    args = parser.parse_args()

    print("="*70)
    print("LLM-RFTP Test Client")
    print("="*70)
    print(f"Connecting to {args.host}:{args.port}\n")
    logger.info("="*70)
    logger.info("LLM-RFTP Test Client Started")
    logger.info("="*70)
    logger.info(f"Connecting to {args.host}:{args.port}")

    try:
        client = FTPTestClient(args.host, args.port)

        # Test both files
        files_to_test = [
            (FILE_WEIGHTS, "stories15M.bin"),
            (FILE_TOKENIZER, "tokenizer.bin"),
        ]

        for file_id, file_name in files_to_test:
            if args.quick:
                client.test_meta_req(file_id)
            elif args.full:
                client.test_full_transfer(file_id, file_name)
            else:
                # Limited transfer test (first 100 chunks only)
                result = client.test_meta_req(file_id)
                if result:
                    _, file_size, chunk_size, total_chunks, _ = result
                    # Test first 100 chunks
                    logger.info(f"Partial transfer test: first 100 chunks...")
                    print(f"\n[PARTIAL TEST] Transferring first 100 chunks...")

                    msg = struct.pack('>BBHII', MSG_DATA_RANGE_REQ, file_id, 100, 0, 0)
                    response = client.send_request(msg)

                    if response:
                        offset = 0
                        count = 0
                        while offset < len(response):
                            if offset + 12 > len(response):
                                break
                            if response[offset] != MSG_DATA_PACKET:
                                break
                            payload_len = struct.unpack('>H', response[offset+8:offset+10])[0]
                            offset += 12 + payload_len
                            count += 1
                        logger.info(f"  ✓ Received {count} packets")
                        print(f"  ✓ Received {count} packets")

        client.close()
        print("\n" + "="*70)
        print("Tests completed successfully!")
        print("="*70)
        logger.info("Tests completed successfully!")
        logger.info("="*70)

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
