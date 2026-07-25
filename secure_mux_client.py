#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import ipaddress
import hashlib
import os
import queue
import selectors
import shlex
import socket
import struct
import threading
import time
from collections import deque
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_MAGIC = b"XFM4"
PROTOCOL_NAME = "XFM4"
MAX_FRAME_SIZE = 8 * 1024 * 1024
MAX_PACKET_PAYLOAD = MAX_FRAME_SIZE - 128
PUBLIC_KEY_SIZE = 32
AEAD_TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 256 * 1024
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 1024 * 1024
SEND_QUEUE_SIZE = 64
RECEIVE_FILE_QUEUE_SIZE = 32

FRAME_LENGTH = struct.Struct("!I")
SEQUENCE = struct.Struct("!Q")
PACKET_HEADER = struct.Struct("!BQ")
FILE_START_FIXED = struct.Struct("!QIH")
FILE_CHUNK_FIXED = struct.Struct("!Q")
FILE_END_FIXED = struct.Struct("!Q32s")
FILE_ACK_FIXED = struct.Struct("!B32sH")
TEXT_STREAM_ID = 0

TYPE_TEXT = 0x01
TYPE_FILE_START = 0x10
TYPE_FILE_CHUNK = 0x11
TYPE_FILE_END = 0x12
TYPE_FILE_CANCEL = 0x13
TYPE_FILE_ACK = 0x14

PRIORITY_TEXT = 0
PRIORITY_CONTROL = 1
PRIORITY_FILE = 10

FILE_PACKET_TYPES = {TYPE_FILE_START, TYPE_FILE_CHUNK, TYPE_FILE_END}


class ProtocolError(Exception):
    """Raised when a peer sends an invalid protocol frame."""


class ConnectionClosed(Exception):
    """Raised when the TCP connection closes during a framed read."""


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionClosed("Connection closed")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if not payload or len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid frame length: {len(payload)}")
    sock.sendall(FRAME_LENGTH.pack(len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    length = FRAME_LENGTH.unpack(recv_exact(sock, FRAME_LENGTH.size))[0]
    if length == 0 or length > MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid frame length: {length}")
    return recv_exact(sock, length)


def public_key_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_session_material(
    shared_secret: bytes,
    client_public: bytes,
    server_public: bytes,
) -> Tuple[bytes, bytes, str]:
    transcript = PROTOCOL_MAGIC + client_public + server_public
    transcript_hash = hashlib.sha256(transcript).digest()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=transcript_hash,
        info=b"xfm4/x25519/chacha20poly1305/session-v1",
    ).derive(shared_secret)

    client_to_server = material[:32]
    server_to_client = material[32:64]
    fingerprint_key = material[64:96]
    digest = hashlib.sha256(
        b"xfm4/session-fingerprint/v1" + transcript + fingerprint_key
    ).hexdigest().upper()[:40]
    fingerprint = "-".join(digest[index:index + 4] for index in range(0, 40, 4))
    return client_to_server, server_to_client, fingerprint


def nonce_from_sequence(sequence: int) -> bytes:
    if sequence < 0 or sequence >= (1 << 64):
        raise OverflowError("Message sequence exhausted")
    return b"\x00\x00\x00\x00" + SEQUENCE.pack(sequence)


def format_size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    number = float(value)
    for unit in units:
        if number < 1024.0 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1024.0
    return f"{value} B"


def sanitize_filename(name: str) -> str:
    cleaned = Path(name.replace("\x00", "")).name.strip()
    if cleaned in {"", ".", ".."}:
        return "received-file.bin"
    return cleaned


def strip_wrapping_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) < 2:
        return stripped
    first = stripped[0]
    last = stripped[-1]
    if first == last and first in {"\"", "'"}:
        return stripped[1:-1]
    return stripped


def split_command_line(command_line: str) -> List[str]:
    posix_mode = os.name != "nt"
    parsed = shlex.split(command_line, posix=posix_mode)
    cleaned: List[str] = []
    for item in parsed:
        cleaned.append(strip_wrapping_quotes(item))
    return cleaned


def resolve_path_expression(expression: str) -> Tuple[List[Path], str]:
    cleaned = strip_wrapping_quotes(expression)
    if not cleaned:
        return [], "Empty path expression"

    expanded = os.path.expandvars(os.path.expanduser(cleaned))
    matches: List[Path] = []

    if glob.has_magic(expanded):
        raw_matches = glob.glob(expanded)
        raw_matches.sort()
        for raw_match in raw_matches:
            candidate = Path(raw_match).resolve(strict=False)
            if candidate.is_file():
                matches.append(candidate)
        if matches:
            return matches, ""
        return [], f"No files matched pattern: {cleaned}"

    candidate = Path(expanded).resolve(strict=False)
    if candidate.is_file():
        matches.append(candidate)
        return matches, ""
    if candidate.exists():
        return [], f"Path is not a regular file: {candidate}"
    return [], f"File not found: {candidate} (working directory: {Path.cwd()})"


def resolve_send_paths(arguments: Iterable[str]) -> Tuple[List[Path], List[str]]:
    tokens: List[str] = []
    for argument in arguments:
        cleaned = strip_wrapping_quotes(str(argument))
        if cleaned:
            tokens.append(cleaned)

    resolved: List[Path] = []
    errors: List[str] = []
    seen: set[str] = set()
    index = 0

    while index < len(tokens):
        best_paths: List[Path] = []
        best_end = index
        end = index + 1

        while end <= len(tokens):
            expression = " ".join(tokens[index:end])
            candidates, error = resolve_path_expression(expression)
            if candidates:
                best_paths = candidates
                best_end = end
                break
            end += 1

        if not best_paths:
            unused_candidates, error = resolve_path_expression(tokens[index])
            errors.append(error)
            index += 1
            continue

        for candidate in best_paths:
            identity = os.path.normcase(str(candidate))
            if identity in seen:
                continue
            seen.add(identity)
            resolved.append(candidate)
        index = best_end

    return resolved, errors


def unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while True:
        candidate = directory / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def encode_reason(reason: str, limit: int = 4096) -> bytes:
    data = reason.encode("utf-8", errors="replace")[:limit]
    return struct.pack("!H", len(data)) + data


def decode_reason(payload: bytes) -> str:
    if len(payload) < 2:
        return ""
    length = struct.unpack("!H", payload[:2])[0]
    if len(payload) != 2 + length:
        raise ProtocolError("Invalid reason-field length")
    return payload[2:].decode("utf-8", errors="replace")


class LocalLog:
    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.path = directory / f"chat_{timestamp}.log"
        self._file = self.path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = message.splitlines()
        if not lines:
            lines = [""]
        with self._lock:
            if self._file.closed:
                return
            for line in lines:
                self._file.write(f"[{timestamp}] {line}\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file.closed:
                return
            self._file.close()


class Console:
    def __init__(self, prompt: str, local_log: LocalLog) -> None:
        self.prompt = prompt
        self.local_log = local_log
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        with self._lock:
            print(message, flush=True)
            self.local_log.write(message)

    def async_write(self, message: str) -> None:
        with self._lock:
            print(f"\r{message}\n{self.prompt}", end="", flush=True)
            self.local_log.write(message)

    def record_input(self, line: str) -> None:
        self.local_log.write(f"{self.prompt}{line}")


def normalize_ip_address(address: object) -> str:
    if isinstance(address, tuple) and address:
        host = str(address[0])
    else:
        host = str(address)

    scope_index = host.find("%")
    address_without_scope = host
    if scope_index >= 0:
        address_without_scope = host[:scope_index]

    try:
        parsed = ipaddress.ip_address(address_without_scope)
    except ValueError:
        return host

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return host


def format_endpoint(address: object) -> str:
    if not isinstance(address, tuple) or len(address) < 2:
        return str(address)
    host = normalize_ip_address(address)
    port = address[1]
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def strip_ipv6_brackets(host: str) -> str:
    stripped = host.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped[1:-1]
    return stripped


class EncryptedChannel:
    def __init__(self, sock: socket.socket, send_key: bytes, receive_key: bytes) -> None:
        self.sock = sock
        self._send_cipher = ChaCha20Poly1305(send_key)
        self._receive_cipher = ChaCha20Poly1305(receive_key)
        self._send_sequence = 0
        self._receive_sequence = 0

    def send_packet(self, plaintext: bytes) -> None:
        if not plaintext or len(plaintext) > MAX_PACKET_PAYLOAD:
            raise ProtocolError(f"Invalid plaintext packet length: {len(plaintext)}")
        sequence_bytes = SEQUENCE.pack(self._send_sequence)
        nonce = nonce_from_sequence(self._send_sequence)
        ciphertext = self._send_cipher.encrypt(
            nonce,
            plaintext,
            PROTOCOL_MAGIC + sequence_bytes,
        )
        send_frame(self.sock, sequence_bytes + ciphertext)
        self._send_sequence += 1

    def receive_packet(self) -> bytes:
        frame = recv_frame(self.sock)
        if len(frame) < SEQUENCE.size + AEAD_TAG_SIZE:
            raise ProtocolError("Encrypted frame is too short")

        sequence_bytes = frame[:SEQUENCE.size]
        sequence = SEQUENCE.unpack(sequence_bytes)[0]
        if sequence != self._receive_sequence:
            raise ProtocolError(
                f"Invalid message sequence: expected {self._receive_sequence}, received {sequence}"
            )

        try:
            plaintext = self._receive_cipher.decrypt(
                nonce_from_sequence(sequence),
                frame[SEQUENCE.size:],
                PROTOCOL_MAGIC + sequence_bytes,
            )
        except InvalidTag as exc:
            raise ProtocolError("Message authentication failed") from exc

        self._receive_sequence += 1
        if not plaintext or len(plaintext) > MAX_PACKET_PAYLOAD:
            raise ProtocolError("Invalid decrypted packet length")
        return plaintext


@dataclass(order=True)
class SendQueueItem:
    priority: int
    order: int
    packet_type: int = field(compare=False)
    stream_id: int = field(compare=False)
    packet: bytes = field(compare=False)


class SendManager:
    def __init__(
        self,
        channel: EncryptedChannel,
        stop_event: threading.Event,
        on_error: Callable[[BaseException], None],
    ) -> None:
        self._channel = channel
        self._stop_event = stop_event
        self._on_error = on_error
        self._queue: queue.PriorityQueue[SendQueueItem] = queue.PriorityQueue(
            maxsize=SEND_QUEUE_SIZE
        )
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._cancelled_streams: set[int] = set()
        self._cancel_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run,
            name="network-sender",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def enqueue(
        self,
        packet_type: int,
        stream_id: int,
        payload: bytes,
        priority: int,
    ) -> bool:
        if self._stop_event.is_set():
            return False
        packet = PACKET_HEADER.pack(packet_type, stream_id) + payload
        if len(packet) > MAX_PACKET_PAYLOAD:
            raise ProtocolError("Protocol packet exceeds the maximum length")

        with self._counter_lock:
            order = self._counter
            self._counter += 1
        item = SendQueueItem(priority, order, packet_type, stream_id, packet)

        while not self._stop_event.is_set():
            try:
                self._queue.put(item, timeout=0.25)
                return True
            except queue.Full:
                continue
        return False

    def mark_stream_cancelled(self, stream_id: int) -> None:
        with self._cancel_lock:
            self._cancelled_streams.add(stream_id)

    def _must_skip(self, item: SendQueueItem) -> bool:
        if item.packet_type not in FILE_PACKET_TYPES:
            return False
        with self._cancel_lock:
            return item.stream_id in self._cancelled_streams

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    item = self._queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                if self._must_skip(item):
                    continue
                self._channel.send_packet(item.packet)
        except (OSError, ConnectionClosed, ProtocolError, OverflowError) as exc:
            if not self._stop_event.is_set():
                self._on_error(exc)


@dataclass
class OutboundTransfer:
    stream_id: int
    path: Path
    size: int
    chunk_size: int
    state: str = "queued"
    offset: int = 0
    file_handle: Optional[BinaryIO] = None
    hasher: object = field(default_factory=hashlib.sha256)
    digest: Optional[bytes] = None
    error: str = ""
    started_at: float = field(default_factory=time.monotonic)
    last_reported_percent: int = -1


@dataclass
class IncomingTransfer:
    stream_id: int
    filename: str
    declared_size: int
    chunk_size: int
    final_path: Path
    temporary_path: Path
    task_queue: queue.Queue
    expected_offset: int = 0
    written: int = 0
    state: str = "receiving"
    error: str = ""
    cancel_event: threading.Event = field(default_factory=threading.Event)
    worker: Optional[threading.Thread] = None


class TransferManager:
    def __init__(
        self,
        download_dir: Path,
        local_stream_parity: int,
        configured_chunk_size: int,
        send_manager: SendManager,
        console: Console,
        stop_event: threading.Event,
    ) -> None:
        self.download_dir = download_dir
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.local_stream_parity = local_stream_parity
        self.peer_stream_parity = 1 - local_stream_parity
        self.chunk_size = configured_chunk_size
        self.send_manager = send_manager
        self.console = console
        self.stop_event = stop_event

        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._outbound: Dict[int, OutboundTransfer] = {}
        self._incoming: Dict[int, IncomingTransfer] = {}
        self._schedule: Deque[int] = deque()
        self._next_stream_id = 1 if local_stream_parity == 1 else 2
        self._history: Deque[str] = deque(maxlen=32)
        self._scheduler = threading.Thread(
            target=self._scheduler_loop,
            name="file-scheduler",
            daemon=True,
        )

    def start(self) -> None:
        self._scheduler.start()

    def add_files(self, paths: Iterable[str]) -> List[int]:
        resolved_paths, path_errors = resolve_send_paths(paths)
        for path_error in path_errors:
            self.console.write(f"Skipped: {path_error}")

        if not resolved_paths:
            self.console.write(
                "No valid files were found. Quote paths containing spaces, or use a wildcard pattern."
            )
            return []

        stream_ids: List[int] = []
        with self._condition:
            for path in resolved_paths:
                try:
                    file_stat = path.stat()
                except OSError as exc:
                    self.console.write(f"Skipped unreadable path: {path}: {exc}")
                    continue
                if not path.is_file():
                    self.console.write(f"Skipped non-file path: {path}")
                    continue

                stream_id = self._next_stream_id
                self._next_stream_id += 2
                transfer = OutboundTransfer(
                    stream_id=stream_id,
                    path=path,
                    size=file_stat.st_size,
                    chunk_size=self.chunk_size,
                )
                self._outbound[stream_id] = transfer
                self._schedule.append(stream_id)
                stream_ids.append(stream_id)
                self.console.write(
                    f"Queued file: 0x{stream_id:016x} | {path.name} | "
                    f"{format_size(transfer.size)}"
                )
            self._condition.notify_all()

        if stream_ids:
            self.console.write(
                f"Queued {len(stream_ids)} file(s) for multiplexed round-robin transfer."
            )
        return stream_ids

    def cancel_outbound(self, stream_id: int, reason: str = "Cancelled by local user") -> bool:
        with self._lock:
            transfer = self._outbound.get(stream_id)
            if transfer is None or transfer.state in {"complete", "cancelled", "failed"}:
                return False
            transfer.state = "cancelled"
            transfer.error = reason
            if transfer.file_handle is not None:
                try:
                    transfer.file_handle.close()
                except OSError:
                    pass
                transfer.file_handle = None
            self.send_manager.mark_stream_cancelled(stream_id)

        self.send_manager.enqueue(
            TYPE_FILE_CANCEL,
            stream_id,
            encode_reason(reason),
            PRIORITY_CONTROL,
        )
        self.console.async_write(f"Cancelled outbound stream 0x{stream_id:016x}: {reason}")
        return True

    def handle_remote_cancel(self, stream_id: int, reason: str) -> None:
        with self._lock:
            outbound = self._outbound.get(stream_id)
            if outbound is not None and outbound.state not in {"complete", "cancelled", "failed"}:
                outbound.state = "cancelled"
                outbound.error = reason or "Cancelled by peer"
                if outbound.file_handle is not None:
                    try:
                        outbound.file_handle.close()
                    except OSError:
                        pass
                    outbound.file_handle = None
                self.send_manager.mark_stream_cancelled(stream_id)
                self.console.async_write(
                    f"Peer cancelled outbound stream 0x{stream_id:016x}: {outbound.error}"
                )
                return

            incoming = self._incoming.get(stream_id)
            if incoming is not None:
                incoming.state = "cancelled"
                incoming.error = reason or "Cancelled by peer"
                incoming.cancel_event.set()
                self._put_incoming_task(incoming, ("cancel", incoming.error))

    def handle_ack(self, stream_id: int, payload: bytes) -> None:
        if len(payload) < FILE_ACK_FIXED.size:
            raise ProtocolError("FILE_ACK is too short")
        status, remote_digest, message_length = FILE_ACK_FIXED.unpack(
            payload[:FILE_ACK_FIXED.size]
        )
        message = payload[FILE_ACK_FIXED.size:]
        if len(message) != message_length:
            raise ProtocolError("Invalid FILE_ACK message length")
        text = message.decode("utf-8", errors="replace")

        with self._lock:
            transfer = self._outbound.get(stream_id)
            if transfer is None:
                raise ProtocolError(f"Unknown FILE_ACK stream: 0x{stream_id:016x}")

            local_digest = transfer.digest
            local_hash = local_digest.hex() if local_digest is not None else "unavailable"
            remote_hash = remote_digest.hex()
            hashes_match = local_digest is not None and local_digest == remote_digest

            hash_report = (
                f"SHA-256 result for outbound stream 0x{stream_id:016x}:\n"
                f"  Expected (sender): {local_hash}\n"
                f"  Actual (receiver): {remote_hash}"
            )

            if status == 0 and hashes_match:
                transfer.state = "complete"
                elapsed = max(time.monotonic() - transfer.started_at, 0.001)
                speed = transfer.size / elapsed
                summary = (
                    f"Send complete: 0x{stream_id:016x} | {transfer.path.name} | "
                    f"{format_size(transfer.size)} | average {format_size(int(speed))}/s | "
                    f"SHA-256 verified"
                )
            else:
                transfer.state = "failed"
                transfer.error = text or "Receiver verification failed"
                summary = (
                    f"Send failed: 0x{stream_id:016x} | {transfer.path.name} | "
                    f"{transfer.error}"
                )
            self._history.append(summary)

        self.console.async_write(f"{hash_report}\n{summary}")

    def handle_file_start(self, stream_id: int, payload: bytes) -> None:
        if stream_id == 0 or stream_id % 2 != self.peer_stream_parity:
            raise ProtocolError(f"Invalid peer stream_id: 0x{stream_id:016x}")
        if len(payload) < FILE_START_FIXED.size:
            raise ProtocolError("FILE_START is too short")

        declared_size, chunk_size, name_length = FILE_START_FIXED.unpack(
            payload[:FILE_START_FIXED.size]
        )
        name_bytes = payload[FILE_START_FIXED.size:]
        if len(name_bytes) != name_length:
            raise ProtocolError("Invalid FILE_START filename length")
        if chunk_size < MIN_CHUNK_SIZE or chunk_size > MAX_CHUNK_SIZE:
            raise ProtocolError(f"Invalid chunk size: {chunk_size}")
        filename = sanitize_filename(name_bytes.decode("utf-8", errors="replace"))

        with self._lock:
            if stream_id in self._incoming or stream_id in self._outbound:
                raise ProtocolError(f"Duplicate stream_id: 0x{stream_id:016x}")
            final_path = unique_path(self.download_dir, filename)
            temporary_path = unique_path(
                self.download_dir,
                f".{final_path.name}.{stream_id:016x}.part",
            )
            transfer = IncomingTransfer(
                stream_id=stream_id,
                filename=filename,
                declared_size=declared_size,
                chunk_size=chunk_size,
                final_path=final_path,
                temporary_path=temporary_path,
                task_queue=queue.Queue(maxsize=RECEIVE_FILE_QUEUE_SIZE),
            )
            worker = threading.Thread(
                target=self._incoming_writer_loop,
                args=(transfer,),
                name=f"file-writer-{stream_id:016x}",
                daemon=True,
            )
            transfer.worker = worker
            self._incoming[stream_id] = transfer
            worker.start()

        self.console.async_write(
            f"Receiving file: 0x{stream_id:016x} | {filename} | "
            f"{format_size(declared_size)}"
        )

    def handle_file_chunk(self, stream_id: int, payload: bytes) -> None:
        if len(payload) < FILE_CHUNK_FIXED.size:
            raise ProtocolError("FILE_CHUNK is too short")
        offset = FILE_CHUNK_FIXED.unpack(payload[:FILE_CHUNK_FIXED.size])[0]
        chunk = payload[FILE_CHUNK_FIXED.size:]
        if not chunk:
            raise ProtocolError("FILE_CHUNK is empty")

        with self._lock:
            transfer = self._incoming.get(stream_id)
            if transfer is None or transfer.state != "receiving":
                raise ProtocolError(f"Unknown or closed inbound stream: 0x{stream_id:016x}")
            if offset != transfer.expected_offset:
                raise ProtocolError(
                    f"Invalid file offset for stream 0x{stream_id:016x}: expected "
                    f"{transfer.expected_offset}, received {offset}"
                )
            if len(chunk) > transfer.chunk_size:
                raise ProtocolError("File chunk exceeds the negotiated chunk size")
            if offset + len(chunk) > transfer.declared_size:
                raise ProtocolError("File chunk exceeds the declared file size")
            transfer.expected_offset += len(chunk)

        self._put_incoming_task(transfer, ("chunk", chunk))

    def handle_file_end(self, stream_id: int, payload: bytes) -> None:
        if len(payload) != FILE_END_FIXED.size:
            raise ProtocolError("Invalid FILE_END length")
        total_size, expected_digest = FILE_END_FIXED.unpack(payload)
        with self._lock:
            transfer = self._incoming.get(stream_id)
            if transfer is None or transfer.state != "receiving":
                raise ProtocolError(f"Unknown or closed inbound stream: 0x{stream_id:016x}")
            if total_size != transfer.declared_size:
                raise ProtocolError("FILE_END size does not match FILE_START")
            if transfer.expected_offset != total_size:
                raise ProtocolError(
                    f"Incomplete file data at FILE_END: {transfer.expected_offset}/{total_size}"
                )
            transfer.state = "verifying"
        self._put_incoming_task(transfer, ("end", total_size, expected_digest))

    def list_transfers(self) -> List[str]:
        lines: List[str] = []
        with self._lock:
            for stream_id in sorted(self._outbound):
                item = self._outbound[stream_id]
                percent = 100.0 if item.size == 0 else (item.offset * 100.0 / item.size)
                lines.append(
                    f"outbound 0x{stream_id:016x} | {item.state:11s} | "
                    f"{percent:6.2f}% | {item.path.name}"
                )
            for stream_id in sorted(self._incoming):
                item = self._incoming[stream_id]
                percent = 100.0 if item.declared_size == 0 else (
                    item.expected_offset * 100.0 / item.declared_size
                )
                lines.append(
                    f"inbound  0x{stream_id:016x} | {item.state:11s} | "
                    f"{percent:6.2f}% | {item.filename}"
                )
            if self._history:
                lines.append("Recent transfer history:")
                lines.extend(f"  {entry}" for entry in list(self._history)[-5:])
        return lines or ["No active file transfers"]

    def shutdown(self) -> None:
        with self._lock:
            for transfer in self._outbound.values():
                if transfer.file_handle is not None:
                    try:
                        transfer.file_handle.close()
                    except OSError:
                        pass
                    transfer.file_handle = None
            incoming = list(self._incoming.values())
        for transfer in incoming:
            transfer.cancel_event.set()
            self._put_incoming_task(transfer, ("cancel", "Connection closed"), block=False)

    def _scheduler_loop(self) -> None:
        while not self.stop_event.is_set():
            with self._condition:
                while not self._schedule and not self.stop_event.is_set():
                    self._condition.wait(timeout=0.5)
                if self.stop_event.is_set():
                    return
                stream_id = self._schedule.popleft()
                transfer = self._outbound.get(stream_id)

            if transfer is None:
                continue
            try:
                should_reschedule = self._advance_outbound(transfer)
            except (OSError, ProtocolError, ValueError) as exc:
                with self._lock:
                    transfer.state = "failed"
                    transfer.error = str(exc)
                    if transfer.file_handle is not None:
                        try:
                            transfer.file_handle.close()
                        except OSError:
                            pass
                        transfer.file_handle = None
                self.send_manager.mark_stream_cancelled(stream_id)
                self.send_manager.enqueue(
                    TYPE_FILE_CANCEL,
                    stream_id,
                    encode_reason(str(exc)),
                    PRIORITY_CONTROL,
                )
                self.console.async_write(
                    f"Failed to read file for stream 0x{stream_id:016x}: {transfer.path.name}: {exc}"
                )
                should_reschedule = False

            if should_reschedule and not self.stop_event.is_set():
                with self._condition:
                    self._schedule.append(stream_id)
                    self._condition.notify()

    def _advance_outbound(self, transfer: OutboundTransfer) -> bool:
        with self._lock:
            if transfer.state in {"cancelled", "failed", "complete", "waiting_ack"}:
                return False

            if transfer.state == "queued":
                transfer.file_handle = transfer.path.open("rb")
                filename = transfer.path.name.encode("utf-8")
                if len(filename) > 65535:
                    raise ValueError("Filename is too long")
                payload = FILE_START_FIXED.pack(
                    transfer.size,
                    transfer.chunk_size,
                    len(filename),
                ) + filename
                if not self.send_manager.enqueue(
                    TYPE_FILE_START,
                    transfer.stream_id,
                    payload,
                    PRIORITY_FILE,
                ):
                    return False
                transfer.state = "sending"
                return True

            if transfer.file_handle is None:
                raise OSError("Outbound file handle is unavailable")
            chunk = transfer.file_handle.read(transfer.chunk_size)
            if chunk:
                offset = transfer.offset
                transfer.hasher.update(chunk)
                transfer.offset += len(chunk)
                payload = FILE_CHUNK_FIXED.pack(offset) + chunk
                if not self.send_manager.enqueue(
                    TYPE_FILE_CHUNK,
                    transfer.stream_id,
                    payload,
                    PRIORITY_FILE,
                ):
                    return False
                self._report_send_progress(transfer)
                return True

            transfer.file_handle.close()
            transfer.file_handle = None
            if transfer.offset != transfer.size:
                raise OSError(
                    f"File size changed during transfer: expected {transfer.size}, "
                    f"read {transfer.offset}"
                )
            transfer.digest = transfer.hasher.digest()
            self.console.async_write(
                f"Final SHA-256 for outbound stream 0x{transfer.stream_id:016x}: "
                f"{transfer.digest.hex()}"
            )
            payload = FILE_END_FIXED.pack(transfer.size, transfer.digest)
            if not self.send_manager.enqueue(
                TYPE_FILE_END,
                transfer.stream_id,
                payload,
                PRIORITY_FILE,
            ):
                return False
            transfer.state = "waiting_ack"
            return False

    def _report_send_progress(self, transfer: OutboundTransfer) -> None:
        if transfer.size == 0:
            percent = 100
        else:
            percent = int(transfer.offset * 100 / transfer.size)
        bucket = percent // 10
        if bucket > transfer.last_reported_percent:
            transfer.last_reported_percent = bucket
            self.console.async_write(
                f"Send progress 0x{transfer.stream_id:016x}: {transfer.path.name} "
                f"{percent}% ({format_size(transfer.offset)}/{format_size(transfer.size)})"
            )

    def _put_incoming_task(
        self,
        transfer: IncomingTransfer,
        task: tuple,
        block: bool = True,
    ) -> None:
        while not self.stop_event.is_set():
            try:
                transfer.task_queue.put(task, timeout=0.25 if block else 0.0)
                return
            except queue.Full:
                if not block:
                    return
                continue

    def _incoming_writer_loop(self, transfer: IncomingTransfer) -> None:
        hasher = hashlib.sha256()
        file_handle: Optional[BinaryIO] = None
        actual_digest = b"\x00" * 32
        try:
            file_handle = transfer.temporary_path.open("xb")
            while not self.stop_event.is_set() and not transfer.cancel_event.is_set():
                try:
                    task = transfer.task_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                kind = task[0]
                if kind == "chunk":
                    data = task[1]
                    file_handle.write(data)
                    hasher.update(data)
                    transfer.written += len(data)
                    continue
                if kind == "cancel":
                    transfer.error = str(task[1])
                    transfer.state = "cancelled"
                    return
                if kind != "end":
                    raise ProtocolError(f"Unknown writer task: {kind}")

                total_size = task[1]
                expected_digest = task[2]
                actual_digest = hasher.digest()
                expected_hash = expected_digest.hex()
                actual_hash = actual_digest.hex()
                self.console.async_write(
                    f"SHA-256 verification for inbound stream 0x{transfer.stream_id:016x}:\n"
                    f"  Expected (sender): {expected_hash}\n"
                    f"  Actual (receiver): {actual_hash}"
                )

                if transfer.written != total_size:
                    raise ProtocolError(
                        f"Written size mismatch: {transfer.written}/{total_size}"
                    )
                if actual_digest != expected_digest:
                    raise ProtocolError(
                        f"SHA-256 mismatch: expected {expected_hash}, actual {actual_hash}"
                    )

                file_handle.flush()
                os.fsync(file_handle.fileno())
                file_handle.close()
                file_handle = None
                os.replace(transfer.temporary_path, transfer.final_path)
                with self._lock:
                    transfer.state = "complete"
                    summary = (
                        f"Receive complete: 0x{transfer.stream_id:016x} | "
                        f"{transfer.final_path.name} | {format_size(total_size)} | "
                        f"SHA-256 verified | saved to {transfer.final_path}"
                    )
                    self._history.append(summary)
                message = str(transfer.final_path.name).encode("utf-8")[:4096]
                ack = FILE_ACK_FIXED.pack(0, actual_digest, len(message)) + message
                self.send_manager.enqueue(
                    TYPE_FILE_ACK,
                    transfer.stream_id,
                    ack,
                    PRIORITY_CONTROL,
                )
                self.console.async_write(summary)
                return
        except (OSError, ProtocolError) as exc:
            transfer.state = "failed"
            transfer.error = str(exc)
            error_message = str(exc).encode("utf-8", errors="replace")[:4096]
            ack = FILE_ACK_FIXED.pack(1, actual_digest, len(error_message)) + error_message
            self.send_manager.enqueue(
                TYPE_FILE_ACK,
                transfer.stream_id,
                ack,
                PRIORITY_CONTROL,
            )
            self.console.async_write(
                f"Receive failed 0x{transfer.stream_id:016x}: "
                f"{transfer.filename}: {exc}"
            )
        finally:
            if file_handle is not None:
                try:
                    file_handle.close()
                except OSError:
                    pass
            if transfer.state != "complete":
                try:
                    transfer.temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass



class PeerSession:
    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        receive_key: bytes,
        fingerprint: str,
        local_stream_parity: int,
        download_dir: Path,
        chunk_size: int,
        local_name: str,
        peer_name: str,
        local_log: LocalLog,
        text_handler: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.sock = sock
        self.fingerprint = fingerprint
        self.local_name = local_name
        self.peer_name = peer_name
        self.stop_event = threading.Event()
        self.console = Console(f"{local_name}> ", local_log)
        self._text_handler = text_handler
        self._channel = EncryptedChannel(sock, send_key, receive_key)
        self._send_manager = SendManager(
            self._channel,
            self.stop_event,
            self._fatal_error,
        )
        self._transfers = TransferManager(
            download_dir=download_dir,
            local_stream_parity=local_stream_parity,
            configured_chunk_size=chunk_size,
            send_manager=self._send_manager,
            console=self.console,
            stop_event=self.stop_event,
        )
        self._receiver = threading.Thread(
            target=self._receive_loop,
            name="network-receiver",
            daemon=True,
        )

    def start(self) -> None:
        self._send_manager.start()
        self._transfers.start()
        self._receiver.start()

    def send_text(self, text: str) -> None:
        encoded = text.encode("utf-8")
        if len(encoded) > 1024 * 1024:
            raise ValueError("A text message cannot exceed 1 MiB")
        self._send_manager.enqueue(TYPE_TEXT, TEXT_STREAM_ID, encoded, PRIORITY_TEXT)

    def send_files(self, paths: Iterable[str]) -> List[int]:
        return self._transfers.add_files(paths)

    def cancel_transfer(self, stream_id: int) -> bool:
        return self._transfers.cancel_outbound(stream_id)

    def transfer_status(self) -> List[str]:
        return self._transfers.list_transfers()

    def close(self) -> None:
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        self._transfers.shutdown()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _receive_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                packet = self._channel.receive_packet()
                if len(packet) < PACKET_HEADER.size:
                    raise ProtocolError("Protocol packet header is too short")
                packet_type, stream_id = PACKET_HEADER.unpack(
                    packet[:PACKET_HEADER.size]
                )
                payload = packet[PACKET_HEADER.size:]
                self._dispatch(packet_type, stream_id, payload)
        except (OSError, ConnectionClosed, ProtocolError) as exc:
            if not self.stop_event.is_set():
                self._fatal_error(exc)

    def _dispatch(self, packet_type: int, stream_id: int, payload: bytes) -> None:
        if packet_type == TYPE_TEXT:
            if stream_id != TEXT_STREAM_ID:
                raise ProtocolError("Text messages must use stream_id 0")
            text = payload.decode("utf-8", errors="replace")
            if self._text_handler is not None:
                self._text_handler(text)
            else:
                self.console.async_write(f"{self.peer_name}> {text}")
        elif packet_type == TYPE_FILE_START:
            self._transfers.handle_file_start(stream_id, payload)
        elif packet_type == TYPE_FILE_CHUNK:
            self._transfers.handle_file_chunk(stream_id, payload)
        elif packet_type == TYPE_FILE_END:
            self._transfers.handle_file_end(stream_id, payload)
        elif packet_type == TYPE_FILE_CANCEL:
            self._transfers.handle_remote_cancel(stream_id, decode_reason(payload))
        elif packet_type == TYPE_FILE_ACK:
            self._transfers.handle_ack(stream_id, payload)
        else:
            raise ProtocolError(f"Unknown packet type: 0x{packet_type:02x}")

    def _fatal_error(self, exc: BaseException) -> None:
        if self.stop_event.is_set():
            return
        self.console.async_write(f"Connection terminated: {exc}")
        self.close()


def run_command_loop(session: PeerSession) -> None:
    help_text = (
        "Commands:\n"
        "  /send <file1> [file2 ...]  Send one or more files concurrently\n"
        "  /transfers                 Show transfer status\n"
        "  /cancel <stream_id>        Cancel a local outbound stream\n"
        "  /fingerprint               Show the current session fingerprint\n"
        "  /help                      Show command help\n"
        "  /quit                      Close the connection\n"
        "Enter any other text to send a message. Paths with spaces may be quoted."
    )
    session.console.write(help_text)
    while not session.stop_event.is_set():
        try:
            line = input(session.console.prompt)
        except (EOFError, KeyboardInterrupt):
            session.console.write("")
            break
        session.console.record_input(line)
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("/"):
            try:
                session.send_text(line)
            except (ValueError, ProtocolError) as exc:
                session.console.write(f"Failed to send message: {exc}")
            continue

        try:
            parts = split_command_line(stripped)
        except ValueError as exc:
            session.console.write(f"Command parsing failed: {exc}")
            continue
        if not parts:
            continue

        command = parts[0].lower()
        if command == "/quit":
            break
        if command == "/help":
            session.console.write(help_text)
        elif command == "/fingerprint":
            session.console.write(f"Session fingerprint: {session.fingerprint}")
        elif command == "/transfers":
            statuses = session.transfer_status()
            for status in statuses:
                session.console.write(status)
        elif command == "/send":
            if len(parts) < 2:
                session.console.write("Usage: /send <file1> [file2 ...]")
            else:
                session.send_files(parts[1:])
        elif command == "/cancel":
            if len(parts) != 2:
                session.console.write("Usage: /cancel <stream_id>")
                continue
            try:
                stream_id = int(parts[1], 0)
            except ValueError:
                session.console.write(
                    "stream_id must be decimal or hexadecimal with a 0x prefix"
                )
                continue
            if not session.cancel_transfer(stream_id):
                session.console.write(
                    f"No cancellable outbound stream found: 0x{stream_id:016x}"
                )
        else:
            session.console.write(
                f"Unknown command: {command}. Enter /help for command help."
            )
    session.close()

def client_handshake(sock: socket.socket) -> Tuple[bytes, bytes, str]:
    client_private = X25519PrivateKey.generate()
    client_public_bytes = public_key_bytes(client_private.public_key())
    send_frame(sock, PROTOCOL_MAGIC + client_public_bytes)

    response = recv_frame(sock)
    if len(response) != len(PROTOCOL_MAGIC) + PUBLIC_KEY_SIZE:
        raise ProtocolError("Invalid server handshake length")
    if response[:len(PROTOCOL_MAGIC)] != PROTOCOL_MAGIC:
        raise ProtocolError("Protocol version mismatch")

    server_public_bytes = response[len(PROTOCOL_MAGIC):]
    server_public = X25519PublicKey.from_public_bytes(server_public_bytes)
    shared_secret = client_private.exchange(server_public)
    client_to_server, server_to_client, fingerprint = derive_session_material(
        shared_secret,
        client_public_bytes,
        server_public_bytes,
    )
    return client_to_server, server_to_client, fingerprint


def main() -> None:
    parser = argparse.ArgumentParser(
        description="XFM4 X25519 + ChaCha20-Poly1305 bidirectional multiplexed client"
    )
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Server IPv4, IPv6, or hostname")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument(
        "--download-dir",
        default="client_downloads",
        help="Directory for received files",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for timestamped local chat logs",
    )
    parser.add_argument(
        "--chunk-size-kib",
        type=int,
        default=DEFAULT_CHUNK_SIZE // 1024,
        help="Outbound file chunk size, 4-1024 KiB",
    )
    args = parser.parse_args()

    chunk_size = args.chunk_size_kib * 1024
    if chunk_size < MIN_CHUNK_SIZE or chunk_size > MAX_CHUNK_SIZE:
        parser.error("--chunk-size-kib must be between 4 and 1024")

    log_directory = Path(args.log_dir).expanduser().resolve()
    local_log = LocalLog(log_directory)
    console = Console("", local_log)
    sock: Optional[socket.socket] = None
    server_host = strip_ipv6_brackets(args.host)

    try:
        console.write(f"Local log: {local_log.path}")
        console.write(f"Connecting to {format_endpoint((server_host, args.port))} ...")
        sock = socket.create_connection((server_host, args.port), timeout=20)
        peer_address = sock.getpeername()
        peer_ip = normalize_ip_address(peer_address)
        peer_endpoint = format_endpoint(peer_address)
        console.write(f"Connected to {peer_endpoint}")

        send_key, receive_key, fingerprint = client_handshake(sock)
        sock.settimeout(None)
        console.write(
            f"Encrypted session established with {peer_ip}. Fingerprint: {fingerprint}"
        )

        session = PeerSession(
            sock=sock,
            send_key=send_key,
            receive_key=receive_key,
            fingerprint=fingerprint,
            local_stream_parity=1,
            download_dir=Path(args.download_dir).expanduser().resolve(),
            chunk_size=chunk_size,
            local_name="You",
            peer_name=peer_ip,
            local_log=local_log,
        )
        session.start()
        run_command_loop(session)
    except (OSError, ConnectionClosed, ProtocolError, ValueError) as exc:
        console.write(f"Connection failed: {exc}")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    finally:
        local_log.close()


if __name__ == "__main__":
    main()
