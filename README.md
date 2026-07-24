[**English**](README.md) | [简体中文](README.zh-CN.md)

# 🔐 XFM4 SecureMux

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Protocol](https://img.shields.io/badge/Protocol-XFM4-2F80ED)](#-xfm4-protocol)
[![Encryption](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305-6A5ACD)](#-encryption-workflow)
[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](#-license)

XFM4 SecureMux is a bidirectional encrypted communication tool written in Python. It carries text messages and multiple large-file transfers over a single TCP connection while preserving responsiveness through logical-stream multiplexing, chunked I/O, priority scheduling, bounded queues, and a multithreaded architecture.

Repository: <https://github.com/wangyifan349/xfm4-secure-mux>

## ✨ Features

- 🔑 Creates a fresh ephemeral X25519 key pair for every connection
- 🧬 Uses HKDF-SHA256 to derive separate client-to-server and server-to-client keys, plus session-fingerprint material
- 🔒 Protects every post-handshake application packet with ChaCha20-Poly1305 authenticated encryption
- 🧭 Displays the same session fingerprint on both peers for out-of-band verification
- 💬 Continues sending and displaying text messages while files are being transferred
- 📦 Reads large files in fixed-size chunks instead of loading them entirely into memory
- 🛣️ Multiplexes multiple files over one TCP connection with independent `stream_id` values
- 🔄 Allows the client and server to send files, receive files, and exchange messages simultaneously
- ⚡ Gives text and control packets higher scheduling priority than file data
- 🧵 Separates network sending, network receiving, file scheduling, and file writing into dedicated threads
- ✅ Verifies the received size and SHA-256 digest before acknowledging file completion
- 🧯 Supports cancellation of locally initiated file transfers
- 🗂️ Sanitizes received filenames, uses temporary files, and resolves name collisions automatically

## 📁 Project Layout

```text
xfm4-secure-mux/
├── secure_mux_server.py    # XFM4 server
├── secure_mux_client.py    # XFM4 client
├── README.md               # English documentation
└── README.zh-CN.md         # Chinese documentation
```

## 📋 Requirements

- Python 3.9 or later
- `cryptography`
- An operating system with TCP sockets and thread support

Install the dependency directly. A virtual environment is not required:

```bash
python -m pip install --upgrade cryptography
```

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/wangyifan349/xfm4-secure-mux.git
cd xfm4-secure-mux
```

### 2. Start the server

```bash
python secure_mux_server.py --host 0.0.0.0 --port 9000 --download-dir server_downloads
```

The server listens on port `9000` on all IPv4 interfaces and stores received files in `server_downloads`.

### 3. Start the client

Connect from the same computer:

```bash
python secure_mux_client.py 127.0.0.1 --port 9000 --download-dir client_downloads
```

Connect across a local network:

```bash
python secure_mux_client.py 192.168.1.10 --port 9000 --download-dir client_downloads
```

After the connection is established, both peers display the same session fingerprint. The current program output is localized in Chinese, for example:

```text
加密会话已建立，会话指纹: 17D9-4AB9-77C4-DBB1-83EA-53EF-067B-999B-1CF0-F967
```

Before transferring important data, compare the fingerprint through a separate trusted channel such as a voice call, an in-person conversation, or an existing verified messaging channel.

### 4. Send a text message

After the connection is established, type a message and press Enter:

```text
客户端> hello
```

Text messaging remains available while files are being transferred.

### 5. Send one file

```text
/send ./example.zip
```

### 6. Send multiple files concurrently

```text
/send ./video.mp4 ./archive.zip ./backup.iso
```

Quote paths that contain spaces:

```text
/send "./large files/video one.mp4" "./large files/video two.mp4"
```

Each file receives an independent `stream_id`. The scheduler advances active streams in round-robin order instead of waiting for one file to finish before starting the next.

## ⌨️ Interactive Commands

| Command | Description |
|---|---|
| `<text>` | Send an encrypted UTF-8 text message |
| `/send <file1> [file2 ...]` | Add one or more regular files to the send queue |
| `/transfers` | Show active, receiving, and recently completed transfers |
| `/cancel <stream_id>` | Cancel a local outgoing stream; decimal and `0x` hexadecimal values are accepted |
| `/fingerprint` | Display the current session fingerprint again |
| `/help` | Show the built-in command help |
| `/quit` | Close the current connection and exit |

Examples:

```text
/transfers
/fingerprint
/cancel 0x1
```

`/cancel` operates on an outgoing stream initiated by the local peer. The sender stops scheduling data for that stream and sends a `FILE_CANCEL` control packet to the remote peer.

## ⚙️ Command-Line Options

### Server

```text
python secure_mux_server.py [--host HOST] [--port PORT]
                            [--download-dir DIRECTORY]
                            [--chunk-size-kib SIZE]
```

| Option | Default | Description |
|---|---:|---|
| `--host` | `0.0.0.0` | TCP listen address |
| `--port` | `9000` | TCP listen port |
| `--download-dir` | `server_downloads` | Directory for received files |
| `--chunk-size-kib` | `256` | Local outgoing file chunk size, from 4 to 1024 KiB |

The current server handles one connected client at a time. After that connection closes, it returns to `accept()` and waits for the next client.

### Client

```text
python secure_mux_client.py [host] [--port PORT]
                            [--download-dir DIRECTORY]
                            [--chunk-size-kib SIZE]
```

| Option | Default | Description |
|---|---:|---|
| `host` | `127.0.0.1` | Server address |
| `--port` | `9000` | Server port |
| `--download-dir` | `client_downloads` | Directory for received files |
| `--chunk-size-kib` | `256` | Local outgoing file chunk size, from 4 to 1024 KiB |

Chunk size is a sender-side property. The peers may use different `--chunk-size-kib` values because the receiver obtains the chunk size for each stream from its `FILE_START` packet.

## 🔐 Encryption Workflow

### 1. TCP connection

The client first opens a normal TCP connection. TCP supplies reliable, ordered byte delivery. XFM4 adds frame boundaries, encryption, logical streams, packet types, and file-transfer state above TCP.

### 2. Ephemeral X25519 handshake

The client and server generate new ephemeral X25519 key pairs for every connection. Private keys remain in process memory and are not written to disk.

Handshake sequence:

```text
Client                                              Server
  │                                                    │
  │  PROTOCOL_MAGIC "XFM4" + Client X25519 Public Key │
  ├───────────────────────────────────────────────────>│
  │                                                    │
  │  PROTOCOL_MAGIC "XFM4" + Server X25519 Public Key │
  │<───────────────────────────────────────────────────┤
  │                                                    │
  │  X25519(client_private, server_public)             │
  │  X25519(server_private, client_public)             │
  │                                                    │
  │          Both sides obtain the same secret         │
```

The public-key handshake messages use a four-byte length prefix. ChaCha20-Poly1305 is not used for these two messages because the session keys do not exist until the key exchange has completed.

### 3. HKDF-SHA256 key derivation

Both peers construct the same handshake transcript:

```text
transcript = "XFM4" || client_public_key || server_public_key
```

They then derive 96 bytes of session material:

```text
transcript_hash = SHA-256(transcript)
HKDF-SHA256(
    input_key_material = X25519 shared secret,
    salt               = transcript_hash,
    info               = "xfm4/x25519/chacha20poly1305/session-v1",
    output_length      = 96 bytes
)
```

The result is divided as follows:

```text
0..31   Client -> Server ChaCha20-Poly1305 key
32..63  Server -> Client ChaCha20-Poly1305 key
64..95  Session fingerprint key material
```

The two directions use different 256-bit keys. Each direction therefore has an independent encryption key, sequence-number space, and nonce space.

### 4. Session fingerprint

The fingerprint is calculated from the transcript and the fingerprint material produced by HKDF:

```text
SHA-256(
    "xfm4/session-fingerprint/v1"
    || transcript
    || fingerprint_key
)
```

The program takes the first 40 hexadecimal characters, converts them to uppercase, and groups them in blocks of four. Both peers independently produce the same value because they use the same transcript, shared secret, and HKDF parameters.

Fingerprint verification is complete only when both parties compare the full value through an independent trusted channel. Use `/fingerprint` to display it again.

### 5. ChaCha20-Poly1305 encrypted frames

After the handshake, every application packet is authenticated and encrypted, including text, file metadata, file chunks, completion messages, cancellation notices, and acknowledgements.

Each direction maintains an unsigned 64-bit sequence number starting at `0`:

```text
nonce = 0x00000000 || uint64_be(sequence_number)
AAD   = "XFM4" || uint64_be(sequence_number)
```

ChaCha20-Poly1305 uses:

- A 32-byte directional key
- A 12-byte nonce
- The protocol identifier and sequence number as AAD
- A 16-byte authentication tag

The sequence number is outside the ciphertext but is authenticated as AAD. The receiver accepts only the exact next expected sequence number before attempting decryption. An authentication failure, unexpected sequence number, or invalid frame length terminates the current connection.

### 6. Encrypted frame format

Post-handshake TCP frames use this layout:

```text
+----------------------+------------------------------------------+
| 4 bytes              | encrypted frame length, uint32 big-endian|
+----------------------+------------------------------------------+
| 8 bytes              | sequence number, uint64 big-endian       |
+----------------------+------------------------------------------+
| variable             | ChaCha20 ciphertext                      |
+----------------------+------------------------------------------+
| 16 bytes             | Poly1305 authentication tag              |
+----------------------+------------------------------------------+
```

The four-byte frame length and eight-byte sequence number are not confidential. Packet type, `stream_id`, message text, filename, file size, file data, SHA-256 digest, and control messages are all inside the authenticated-encryption boundary.

## 🛣️ XFM4 Protocol

Every decrypted application packet begins with the same header:

```text
+----------------------+------------------------------------------+
| 1 byte               | packet_type                              |
+----------------------+------------------------------------------+
| 8 bytes              | stream_id, uint64 big-endian             |
+----------------------+------------------------------------------+
| variable             | packet-specific payload                  |
+----------------------+------------------------------------------+
```

### Packet types

| Type | Value | Purpose |
|---|---:|---|
| `TEXT` | `0x01` | UTF-8 text message |
| `FILE_START` | `0x10` | Declare filename, file size, and chunk size |
| `FILE_CHUNK` | `0x11` | Carry an absolute file offset and file data |
| `FILE_END` | `0x12` | Declare final size and SHA-256 digest |
| `FILE_CANCEL` | `0x13` | Cancel a stream and provide a reason |
| `FILE_ACK` | `0x14` | Report successful or failed reception |

### `stream_id` allocation

```text
stream_id = 0              Text messages
stream_id = 1, 3, 5, ...   File streams initiated by the client
stream_id = 2, 4, 6, ...   File streams initiated by the server
```

Odd/even partitioning lets both peers create streams concurrently without requesting identifiers from a central allocator. The receiver validates the expected parity and rejects invalid or conflicting stream identifiers.

## 📦 File-Transfer Workflow

### `FILE_START`

The sender begins with file metadata:

```text
uint64  declared_file_size
uint32  chunk_size
uint16  filename_size
bytes   UTF-8 filename
```

The receiver:

1. Validates the `stream_id`, filename length, and chunk size.
2. Sanitizes the filename and keeps only a safe basename.
3. Chooses a collision-free destination filename.
4. Creates a `.part` temporary path.
5. Starts a dedicated writer thread and bounded queue for that stream.

### `FILE_CHUNK`

Each data packet contains:

```text
uint64  absolute_file_offset
bytes   chunk_data
```

The receiver requires:

- The offset to equal the next expected offset for that stream.
- The data length not to exceed the chunk size declared by `FILE_START`.
- The end position not to exceed the declared total file size.

After validation, the network-receive thread places the chunk in the stream's write queue. Its writer thread writes the data sequentially and updates the SHA-256 state.

### `FILE_END`

After reading the complete source file, the sender transmits:

```text
uint64  total_file_size
bytes   SHA-256 digest, 32 bytes
```

The receiver waits until all queued data has been written and then verifies:

- The `FILE_START` size, received offset, and `FILE_END` size agree.
- The number of bytes written equals the declared size.
- The locally calculated SHA-256 digest matches the sender's digest.

After successful verification, the receiver:

1. Calls `flush()` on the file object.
2. Calls `fsync()` to request synchronization of file data.
3. Closes the temporary file.
4. Uses `os.replace()` to atomically move the `.part` file to its final name.
5. Sends a successful `FILE_ACK` containing the local SHA-256 digest and final filename.

The sender marks the transfer as `complete` only after receiving a successful `FILE_ACK` with the same digest.

### `FILE_CANCEL` and `FILE_ACK`

`FILE_CANCEL` carries a UTF-8 reason for stopping a stream. `FILE_ACK` contains:

```text
uint8   status               # 0 = success, 1 = failure
bytes   SHA-256, 32 bytes
uint16  message_size
bytes   UTF-8 message
```

A failed acknowledgement normally includes the reason for a write error or verification failure.

## 🧵 Concurrency and Multiplexing

Each connection uses the following execution units:

| Execution unit | Thread name in code | Responsibility |
|---|---|---|
| Main thread | — | Read terminal input, process commands, and submit text or file jobs |
| Network sender | `network-sender` | Own all socket writes and send encrypted packets by priority |
| Network receiver | `network-receiver` | Read, validate, decrypt, and dispatch packets by type and `stream_id` |
| File scheduler | `file-scheduler` | Advance outgoing file streams in round-robin order |
| File writer | `file-writer-<stream_id>` | Write one incoming file and calculate its SHA-256 digest |

Overall data flow:

```text
Terminal input
    │
    ├── text ───────────────────────────────────────┐
    │                                               │
    └── /send files ──> round-robin file scheduler │
                                                    ▼
                                      bounded priority queue
                                  text > control > file data
                                                    │
                                                    ▼
                                      single network-sender
                                                    │
                                      ChaCha20-Poly1305
                                                    │
                                                    ▼
                                               TCP socket
                                                    │
                                                    ▼
                                         network-receiver
                                                    │
                          ┌─────────────────────────┴──────────────┐
                          ▼                                        ▼
                    display text                         dispatch by stream_id
                                                                   │
                                                                   ▼
                                                    per-file bounded queue
                                                                   │
                                                                   ▼
                                                        file-writer thread
```

### Why only one thread writes to the socket

Allowing multiple threads to call `sendall()` directly complicates sequence-number ownership, packet priority, frame boundaries, and error propagation. XFM4 submits every outgoing packet to one priority queue and gives `network-sender` exclusive ownership of encryption and socket writes. This guarantees:

- Strictly increasing outgoing sequence numbers
- No interleaving of encrypted frames from competing writers
- Priority handling for text and control packets
- Centralized handling of connection failures

### Round-robin file scheduling

The file scheduler maintains a queue of active outgoing streams. Each time it selects a `stream_id`, it performs one step:

- Not started: queue `FILE_START`.
- Sending: read and queue one file chunk.
- End of file: queue `FILE_END` and wait for `FILE_ACK`.

A stream that still has work is returned to the end of the scheduler queue. Chunks from multiple large files therefore enter the network queue in interleaved order, providing logical concurrency over one TCP connection.

### Packet priorities

Lower internal values mean higher scheduling priority:

```text
TEXT       priority 0
CONTROL    priority 1
FILE DATA  priority 10
```

When the bounded send queue is full, producers may briefly wait for capacity. Once packets are queued, text and control traffic are selected before unsent file-data packets. Data already placed in the operating system's TCP buffer cannot be overtaken by a later message.

### Backpressure and memory bounds

- The network priority queue holds at most 64 packets.
- Each incoming file write queue holds at most 32 tasks.
- The sender reads only one chunk per scheduling step.
- The receiver maintains at most 64 active incoming file streams.

When network transmission or disk writing is slower than production, producer threads block on bounded queues instead of reading unlimited data into memory.

## 📏 Protocol Limits

| Item | Current value |
|---|---:|
| Protocol identifier | `XFM4` |
| X25519 public key | 32 bytes |
| ChaCha20-Poly1305 key | 32 bytes per direction |
| ChaCha20-Poly1305 nonce | 12 bytes |
| Poly1305 tag | 16 bytes |
| Sequence number | 64-bit per direction |
| Maximum encrypted TCP frame | 8 MiB |
| Maximum UTF-8 text message | 1 MiB |
| Default file chunk | 256 KiB |
| Configurable chunk range | 4–1024 KiB |
| Maximum UTF-8 filename | 4096 bytes |
| Active incoming file streams | Up to 64 |
| Concurrent clients handled by server | 1 |

The current implementation does not provide transfer resumption. During a normal cancellation or shutdown, file-writer threads attempt to remove incomplete `.part` files. A forced process termination may leave `.part` files in the download directory. An interrupted file must be sent again after reconnection.

## 🗂️ File Storage Rules

- The server stores files in `server_downloads` by default.
- The client stores files in `client_downloads` by default.
- Missing directories are created automatically.
- Remote path information is not reused; only a sanitized basename is accepted.
- Name conflicts are resolved as `name (1).ext`, `name (2).ext`, and so on.
- Incomplete files use hidden-style `.part` temporary names.
- A final file appears only after size and SHA-256 verification succeeds.

## 🔧 Usage Examples

Start a server on a custom port with 512 KiB chunks:

```bash
python secure_mux_server.py \
  --host 0.0.0.0 \
  --port 9443 \
  --download-dir ./received/server \
  --chunk-size-kib 512
```

Connect to that server:

```bash
python secure_mux_client.py 192.168.1.10 \
  --port 9443 \
  --download-dir ./received/client \
  --chunk-size-kib 512
```

Send multiple files and continue chatting:

```text
/send "./release/app.tar.gz" "./release/database backup.sql"
客户端> 两个文件已经开始发送
/transfers
```

## 💖 Sponsor the Project

If XFM4 SecureMux is useful to you, you can support its continued development with Bitcoin:

```text
bc1qymelsaghkfw992ee2tyzz0ph8xcy33u3gs7jl5
```

Verify the address before sending. Blockchain transactions are generally irreversible.

## 📜 License

This project is released under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).

You may use, copy, modify, and distribute the project under the terms of AGPL-3.0. When distributing a modified version or making modified program functionality available to users over a network, comply with the source-code availability and license-preservation requirements of AGPL-3.0. The complete license text is authoritative: <https://www.gnu.org/licenses/agpl-3.0.html>

Place a complete `LICENSE` file in the repository root and preserve the applicable copyright and SPDX notices in source files.

## 🤝 Contributing

Issues and pull requests are welcome:

<https://github.com/wangyifan349/xfm4-secure-mux>

When changing the wire protocol, update all of the following together:

- `PROTOCOL_MAGIC`
- Handshake transcript and HKDF `info`
- Packet formats and packet-type values
- Client and server parsing logic
- Protocol documentation in both README files

The client and server must use compatible protocol identifiers, packet layouts, and key-derivation parameters. Otherwise, the handshake or subsequent packet parsing will fail.
