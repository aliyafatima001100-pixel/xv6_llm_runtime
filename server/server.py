"""
LLM-RFTP File Server

Serves stories15M.bin, tokenizer.bin and (when present) stories110M.bin over UDP
using the LLM-RFTP protocol.

Protocol: LLM Reliable File Transfer Protocol
Port: 9999 (UDP)

Message Types
-------------
- 0x01: META_REQ (client requests file metadata)
- 0x02: META_RESP (server sends metadata + SHA-256)
- 0x03: DATA_RANGE_REQ (client requests chunk range)
- 0x04: RETRANS_REQ (client requests specific missing chunks)
- 0x05: DATA_PACKET (server sends chunk data)
- 0x06: ERROR (error response)
"""

import socket
import struct
import hashlib
import os

from custom_logger import LoggerSetup

# Message type constants
MSG_META_REQ = 0x01
MSG_META_RESP = 0x02
MSG_DATA_RANGE_REQ = 0x03
MSG_RETRANS_REQ = 0x04
MSG_DATA_PACKET = 0x05
MSG_ERROR = 0x06

# File identifiers
FILE_WEIGHTS = 0x01
FILE_TOKENIZER = 0x02
FILE_WEIGHTS_110M = 0x03  # stories110M.bin, sharded across nodes by DistInf

# Configuration
DEFAULT_PORT = 9999
CHUNK_SIZE = 512
MAX_RANGE = 16
MAX_RETRANS = 32

# Setup custom logger with script-relative log directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
logger_setup = LoggerSetup('LLM-RFTP-Server', log_level='INFO', filename='server.log', log_dir=LOG_DIR)
logger = logger_setup.get_logger()


class FileStore:
    """
    Manages file metadata and data for efficient serving.

    This class loads a file into memory and provides efficient access to
    chunks while maintaining metadata such as file size and SHA-256 hash.

    Attributes
    ----------
    file_id : int
        Unique identifier for this file (0x01 or 0x02).
    file_path : str
        Path to the file on disk.
    data : bytes
        Complete file data loaded into memory.
    size : int
        Total size of the file in bytes.
    total_chunks : int
        Total number of chunks (CHUNK_SIZE bytes each).
    sha256 : bytes
        SHA-256 hash digest of the file (32 bytes).

    Author: Hadiya Muneeb
    Date Created: 2025-11-21
    """

    def __init__(self, file_id, file_path, optional=False):
        """
        Initialize FileStore and load file from disk.

        Parameters
        ----------
        file_id : int
            Unique file identifier (e.g., 0x01 for weights, 0x02 for tokenizer).
        file_path : str
            Path to the file to load.

        Raises
        ------
        FileNotFoundError
            If the specified file does not exist.
        Exception
            If file loading fails for any reason.
        """
        self.file_id = file_id
        self.file_path = file_path
        self.optional = optional
        self.data = None
        self.size = 0
        self.total_chunks = 0
        self.sha256 = None
        self.load_file()

    def load_file(self):
        """
        Load file from disk and compute metadata.

        Reads the entire file into memory, computes SHA-256 hash,
        and calculates total chunk count. Logs detailed file information.

        Raises
        ------
        FileNotFoundError
            If the specified file does not exist.
        Exception
            If file I/O or hash computation fails.

        Notes
        -----
        This is called automatically in __init__. Files are loaded entirely
        into memory for efficient serving to multiple clients.
        """
        try:
            if not os.path.exists(self.file_path):
                if not self.optional:
                    logger.error(f"File not found: {self.file_path}")
                raise FileNotFoundError(self.file_path)

            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            self.size = len(self.data)
            self.total_chunks = (self.size + CHUNK_SIZE - 1) // CHUNK_SIZE
            self.sha256 = hashlib.sha256(self.data).digest()

            logger.info(f"Loaded file {self.file_id}: {self.size} bytes, "
                       f"{self.total_chunks} chunks, SHA-256={self.sha256.hex()[:16]}...")
        except Exception as e:
            if not self.optional:
                logger.error(f"Failed to load file {self.file_path}: {e}")
            raise

    def get_chunk(self, chunk_idx):
        """
        Retrieve a specific chunk of data from the file.

        Parameters
        ----------
        chunk_idx : int
            Zero-based index of the chunk to retrieve.

        Returns
        -------
        bytes or None
            The chunk data (up to CHUNK_SIZE bytes), or None if chunk_idx
            is out of bounds.

        Notes
        -----
        The last chunk may be smaller than CHUNK_SIZE if the file size
        is not a multiple of CHUNK_SIZE.
        """
        if chunk_idx >= self.total_chunks or chunk_idx < 0:
            return None

        start = chunk_idx * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, self.size)
        return self.data[start:end]


class LLMRFTPServer:
    """
    UDP server implementing the LLM-RFTP protocol.

    Handles incoming LLM-RFTP protocol messages, manages file serving,
    and maintains statistics about server operations.

    Attributes
    ----------
    port : int
        UDP port to listen on.
    socket : socket.socket
        The UDP socket used for communication.
    files : dict
        Dictionary mapping file_id to FileStore objects.
    stats : dict
        Dictionary tracking various server statistics.

    Author: Hadiya Muneeb
    Date Created: 2025-11-21
    """

    def __init__(self, port=DEFAULT_PORT, file_paths=None):
        """
        Initialize the LLM-RFTP server.

        Parameters
        ----------
        port : int, optional
            UDP port to listen on (default: DEFAULT_PORT).
        file_paths : dict, optional
            Dictionary mapping file_id to file paths. If None, uses default
            paths in models/ directory.

        Raises
        ------
        Exception
            If any specified file cannot be loaded.
        """
        self.port = port
        self.socket = None
        self.files = {}
        self.stats = {
            'packets_received': 0,
            'meta_reqs': 0,
            'data_range_reqs': 0,
            'retrans_reqs': 0,
            'packets_sent': 0,
            'errors': 0,
        }

        # Default file paths. A file that is only a default may be absent; one
        # named explicitly by the caller must exist.
        #
        # The 110M checkpoint is ~418 MiB and is not kept in the repository, so
        # its absence must not stop the server: the 15M single-node path has to
        # keep working on a tree that has never fetched it.
        optional_ids = ()
        if file_paths is None:
            base_path = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(base_path, 'models')
            file_paths = {
                FILE_WEIGHTS: os.path.join(model_dir, 'stories15M.bin'),
                FILE_TOKENIZER: os.path.join(model_dir, 'tokenizer.bin'),
                FILE_WEIGHTS_110M: os.path.join(model_dir, 'stories110M.bin'),
            }
            optional_ids = (FILE_WEIGHTS_110M,)

        # Load files
        for file_id, file_path in file_paths.items():
            try:
                self.files[file_id] = FileStore(file_id, file_path,
                                                optional=file_id in optional_ids)
            except Exception as e:
                if file_id in optional_ids:
                    logger.info(f"stories110M not present, so it will not be served. This is "
                                f"expected: single-node inference uses the small stories15M model "
                                f"and is unaffected. ({file_path})")
                    continue
                logger.error(f"Failed to load file {file_id}: {e}")
                logger.error("This checkpoint is REQUIRED and is not distributed with "
                             "the tree (all three together are 495 MB). Fetch them, and "
                             "verify their SHA-256, by running from the repo root:")
                logger.error("    ./fetch-models.sh")
                raise

    def create_socket(self):
        """
        Create and bind UDP socket to the configured port.

        Raises
        ------
        Exception
            If socket creation or binding fails.

        Notes
        -----
        Sets SO_REUSEADDR socket option to allow quick rebinding after
        server restart.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            logger.info(f"Server listening on 0.0.0.0:{self.port} (UDP)")
        except Exception as e:
            logger.error(f"Failed to create socket: {e}")
            raise

    def handle_meta_req(self, data, client_addr):
        """
        Handle META_REQ message from client.

        The client requests metadata about a specific file, including its
        size, chunk count, and SHA-256 hash for integrity verification.

        Parameters
        ----------
        data : bytes
            Raw message data from client.
        client_addr : tuple
            Client address as (host, port).

        Returns
        -------
        bytes
            META_RESP message containing file metadata or ERROR message
            if request is invalid.

        Notes
        -----
        META_REQ format (4 bytes): [msg_type:1][file_id:1][reserved:2]
        META_RESP format (48 bytes): [msg_type:1][file_id:1][version:2]
                                     [file_size:4][chunk_size:4]
                                     [total_chunks:4][sha256:32]
        """
        self.stats['meta_reqs'] += 1

        if len(data) < 4:
            logger.warning(f"Malformed META_REQ from {client_addr}")
            return self.error_response(0x00, 2)

        file_id = data[1]

        if file_id not in self.files:
            logger.warning(f"Unknown file {file_id} from {client_addr}")
            return self.error_response(file_id, 1)

        f = self.files[file_id]
        response = struct.pack('>BBHIII',
            MSG_META_RESP, file_id, 1,  # msg_type, file_id, version
            f.size, CHUNK_SIZE, f.total_chunks
        ) + f.sha256

        logger.info(f"→ Sending META_RESP to {client_addr}: file={file_id}, "
                    f"size={f.size}, chunks={f.total_chunks}, sha256={f.sha256.hex()[:16]}...")
        return response

    def handle_data_range_req(self, data, client_addr):
        """
        Handle DATA_RANGE_REQ message from client.

        The client requests a range of consecutive chunks. The server
        responds with multiple DATA_PACKET messages, one per chunk.

        Parameters
        ----------
        data : bytes
            Raw message data from client.
        client_addr : tuple
            Client address as (host, port).

        Returns
        -------
        bytes
            Concatenated DATA_PACKET messages, or ERROR message if invalid.

        Notes
        -----
        DATA_RANGE_REQ format (12 bytes): [msg_type:1][file_id:1][count:2]
                                          [reserved:4][start_idx:4]

        The server caps count at MAX_RANGE (16) if the client requests more.
        """
        self.stats['data_range_reqs'] += 1

        if len(data) < 12:
            logger.warning(f"Malformed DATA_RANGE_REQ from {client_addr}")
            return self.error_response(0x00, 2)

        file_id = data[1]
        count = struct.unpack('>H', data[2:4])[0]
        start_idx = struct.unpack('>I', data[8:12])[0]

        if count > MAX_RANGE:
            logger.warning(f"DATA_RANGE_REQ count {count} > {MAX_RANGE}")
            count = MAX_RANGE

        if file_id not in self.files:
            logger.warning(f"Unknown file {file_id} from {client_addr}")
            return self.error_response(file_id, 1)

        f = self.files[file_id]

        if start_idx >= f.total_chunks:
            logger.warning(f"DATA_RANGE_REQ start_idx {start_idx} >= {f.total_chunks}")
            return self.error_response(file_id, 2)

        # Build response: send each chunk as a separate UDP packet
        packets_sent = 0
        for i in range(start_idx, min(start_idx + count, f.total_chunks)):
            chunk_data = f.get_chunk(i)
            if chunk_data is not None:
                pkt = self.data_packet(file_id, i, chunk_data)
                self.socket.sendto(pkt, client_addr)
                packets_sent += 1
                self.stats['packets_sent'] += 1

        # logger.info(f"→ Sent DATA_RANGE_REQ response to {client_addr}: file={file_id}, " 
        #             f"range=[{start_idx}, {min(start_idx + count, f.total_chunks)}), "
        #             f"sent {packets_sent} packets")

        return None  # Already sent, no response to return

    def handle_retrans_req(self, data, client_addr):
        """
        Handle RETRANS_REQ message from client.

        The client requests retransmission of specific missing chunks by
        their indices. The server responds with DATA_PACKET messages for
        each requested chunk.

        Parameters
        ----------
        data : bytes
            Raw message data from client.
        client_addr : tuple
            Client address as (host, port).

        Returns
        -------
        bytes
            Concatenated DATA_PACKET messages, or ERROR message if invalid.

        Notes
        -----
        RETRANS_REQ format (4 + N*4 bytes): [msg_type:1][file_id:1]
                                            [count:2][indices:N*4]

        The server caps count at MAX_RETRANS (32) if the client requests more.
        Invalid chunk indices are silently skipped.
        """
        self.stats['retrans_reqs'] += 1

        if len(data) < 4:
            logger.warning(f"Malformed RETRANS_REQ from {client_addr}")
            return self.error_response(0x00, 2)

        file_id = data[1]
        count = struct.unpack('>H', data[2:4])[0]

        if count > MAX_RETRANS:
            logger.warning(f"RETRANS_REQ count {count} > {MAX_RETRANS}")
            count = MAX_RETRANS

        if file_id not in self.files:
            logger.warning(f"Unknown file {file_id} from {client_addr}")
            return self.error_response(file_id, 1)

        f = self.files[file_id]

        # Parse chunk indices and send each as a separate UDP packet
        packets_sent = 0
        for idx in range(count):
            if offset + 4 > len(data):
                break

            chunk_idx = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4

            if 0 <= chunk_idx < f.total_chunks:
                chunk_data = f.get_chunk(chunk_idx)
                if chunk_data is not None:
                    pkt = self.data_packet(file_id, chunk_idx, chunk_data)
                    self.socket.sendto(pkt, client_addr)
                    packets_sent += 1
                    self.stats['packets_sent'] += 1

        logger.info(f"→ Sent RETRANS_REQ response to {client_addr}: file={file_id}, "
                    f"requested_indices={count}, sent {packets_sent} packets")

        return None  # Already sent, no response to return

    def data_packet(self, file_id, chunk_idx, chunk_data):
        """
        Build a DATA_PACKET message.

        Parameters
        ----------
        file_id : int
            File identifier.
        chunk_idx : int
            Zero-based chunk index.
        chunk_data : bytes
            Chunk data payload (typically CHUNK_SIZE bytes or less).

        Returns
        -------
        bytes
            Complete DATA_PACKET message with header and payload.

        Notes
        -----
        DATA_PACKET format (12 + N bytes): [msg_type:1][file_id:1][flags:2]
                                           [chunk_idx:4][payload_len:2]
                                           [reserved:2][data:N]
        """
        payload_len = len(chunk_data)
        header = struct.pack('>BBHIHH',
            MSG_DATA_PACKET, file_id, 0,     # msg_type, file_id, flags
            chunk_idx, payload_len, 0        # chunk_idx, payload_len, reserved
        )
        return header + chunk_data

    def error_response(self, file_id, error_code):
        """
        Build an ERROR message.

        Parameters
        ----------
        file_id : int
            File identifier (0x00 if error not specific to a file).
        error_code : int
            Error code (1=unknown file, 2=malformed, 3=server error).

        Returns
        -------
        bytes
            ERROR message (4 bytes).

        Notes
        -----
        ERROR format (4 bytes): [msg_type:1][file_id:1][reserved:2]
                                [error_code:2]
        """
        self.stats['errors'] += 1
        return struct.pack('>BBHH', MSG_ERROR, file_id, 0, error_code)

    def handle_message(self, data, client_addr):
        """
        Route incoming message to appropriate handler.

        Examines the message type and dispatches to the corresponding
        handler function (META_REQ, DATA_RANGE_REQ, or RETRANS_REQ).

        Parameters
        ----------
        data : bytes
            Raw message data from client.
        client_addr : tuple
            Client address as (host, port).

        Returns
        -------
        bytes or None
            Response message from handler, or None if no response.

        Notes
        -----
        Exceptions in handlers are caught and logged, returning an
        ERROR response to the client.
        """
        self.stats['packets_received'] += 1

        if len(data) < 1:
            logger.warning(f"Empty message from {client_addr}")
            return None

        msg_type = data[0]

        try:
            if msg_type == MSG_META_REQ:
                return self.handle_meta_req(data, client_addr)
            elif msg_type == MSG_DATA_RANGE_REQ:
                return self.handle_data_range_req(data, client_addr)
            elif msg_type == MSG_RETRANS_REQ:
                return self.handle_retrans_req(data, client_addr)
            else:
                logger.warning(f"Unknown message type {msg_type} from {client_addr}")
                return self.error_response(0x00, 2)
        except Exception as e:
            logger.error(f"Error handling message from {client_addr}: {e}")
            self.stats['errors'] += 1
            return self.error_response(0x00, 3)  # Server error

    def run(self):
        """
        Main server loop.

        Listens for incoming UDP packets, dispatches them to handlers,
        and sends responses back to clients. Runs until interrupted
        by KeyboardInterrupt (Ctrl+C).

        Logs server startup, statistics, and any errors encountered.
        """
        self.create_socket()
        logger.info("="*60)
        logger.info("LLM-RFTP Server Started")
        logger.info("="*60)

        try:
            while True:
                try:
                    data, client_addr = self.socket.recvfrom(65536)
                    # logger.info(f"← Received packet from {client_addr}: {len(data)} bytes, msg_type=0x{data[0]:02x}")

                    response = self.handle_message(data, client_addr)

                    # Send response if handler didn't send it already
                    if response:
                        self.socket.sendto(response, client_addr)
                        logger.info(f"→ Sent response to {client_addr}: {len(response)} bytes")

                except KeyboardInterrupt:
                    logger.info("Server shutdown requested")
                    break
                except Exception as e:
                    logger.error(f"Error in server loop: {e}", exc_info=True)

        finally:
            self.close()

    def close(self):
        """
        Close the server socket and log final statistics.

        Called on server shutdown to clean up resources and print
        a summary of server activity.
        """
        if self.socket:
            self.socket.close()

        logger.info("="*60)
        logger.info("Server Statistics:")
        logger.info(f"  Packets received: {self.stats['packets_received']}")
        logger.info(f"  META_REQs: {self.stats['meta_reqs']}")
        logger.info(f"  DATA_RANGE_REQs: {self.stats['data_range_reqs']}")
        logger.info(f"  RETRANS_REQs: {self.stats['retrans_reqs']}")
        logger.info(f"  Packets sent: {self.stats['packets_sent']}")
        logger.info(f"  Errors: {self.stats['errors']}")
        logger.info("="*60)


def main():
    """
    Parse command-line arguments and run the server.

    Supports configurable port and file paths for testing with
    different files or port numbers.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description='LLM-RFTP File Server'
    )
    parser.add_argument(
        '--port', type=int, default=DEFAULT_PORT,
        help=f'UDP port to listen on (default: {DEFAULT_PORT})'
    )
    parser.add_argument(
        '--weights', type=str,
        help='Path to weights file (default: models/stories15M.bin)'
    )
    parser.add_argument(
        '--tokenizer', type=str,
        help='Path to tokenizer file (default: models/tokenizer.bin)'
    )
    parser.add_argument(
        '--weights-110m', type=str,
        help='Path to the 110M weights file served as FILE_WEIGHTS_110M '
             '(default: models/stories110M.bin, skipped if absent)'
    )

    args = parser.parse_args()

    # Build file paths - only if command-line args are provided
    file_paths = None
    if args.weights or args.tokenizer or args.weights_110m:
        # If only one arg provided, still need to build full dict with defaults
        base_path = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.join(base_path, 'models')
        file_paths = {
            FILE_WEIGHTS: args.weights or os.path.join(model_dir, 'stories15M.bin'),
            FILE_TOKENIZER: args.tokenizer or os.path.join(model_dir, 'tokenizer.bin'),
        }

        # Serve the 110M checkpoint only when it was named explicitly or is
        # actually present; an explicit path that does not exist is still fatal.
        weights_110m = args.weights_110m or os.path.join(model_dir, 'stories110M.bin')
        if args.weights_110m or os.path.exists(weights_110m):
            file_paths[FILE_WEIGHTS_110M] = weights_110m

    # Create and run server (file_paths=None uses __init__ defaults)
    server = LLMRFTPServer(port=args.port, file_paths=file_paths)
    server.run()


if __name__ == '__main__':
    main()
