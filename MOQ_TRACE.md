# quic_trace instrumentation

This branch adds the `quic_trace:*` transport hooks of the
[moq-trace](https://github.com/5062/moq-trace) toolkit to mvfst, so that the
moxygen relay's MoQ objects can be joined to the QUIC packets, STREAM frames, and
UDP system calls that carried them. It is a measurement fork, not intended for
upstream submission.

The branch starts at `f21cfe029`, the mvfst revision that moxygen pins.

## What the instrumentation emits

| Call site | Emission |
| --- | --- |
| `QuicAsyncUDPSocketImpl::recvmmsgNetworkData` | RX `udp_socket` around the `recvmmsg` call, and the call's completion stamped on every datagram it returned |
| `QuicServerWorker` read dispatcher | RX `udp_socket` around each `recvmsg` or `recvfrom` of folly's read loop, with GRO datagrams, and the call's completion stamped on the datagram `onDataAvailable` receives |
| `FollyQuicAsyncUDPSocket::write`, `writeGSO`, `writem`, `writemGSO` | TX `udp_socket` around each `sendmsg` or `sendmmsg`, naming the connection whose batch sent, with buffers, GSO datagrams, and bytes |
| `onServerReadDataFromOpen` | RX packet from the read's completion: `read_queue`, `header_parse`, `header_unprotect`, `payload_decrypt`, one `frame_process` per frame other than padding, and its outcome |
| `QuicReadCodec` | the boundaries of the parse stages and the packet number space the header names, stamped only for a traced packet |
| server `ReadStreamFrame` handling | RX `quic_stream_frame`, `success` when the stream buffered the bytes, `dropped` when it was no longer open for receiving, and `malformed` when processing it failed |
| `continuousMemoryBuildScheduleEncrypt`, `iobufChainBasedBuildScheduleEncrypt` | TX packet from the start of frame encoding: `frame_encode`, `packet_encrypt`, then `send_queue`, and its STREAM frames with their retransmission flag |
| `IOBufQuicBatch` | TX packet end at the completion of the send that carried its batch, or `dropped` when that send failed |
| first packet of a server connection, `QuicPathManager` path switch | `quic_connection_path` |
| `pacedWriteDataToSocket` | `quic_send_blocked` for the first of amplification, the congestion window, and pacing that keeps data from being sent |
| flow control, `QuicStreamManager` connection-blocked streams, pending write callbacks | per stream `quic_send_blocked` while stream or connection flow control holds the stream's pending writes, and while the full send buffer holds back the application's write |

Each connection allocates a process-wide connection ID from the toolkit and
exposes it as `TransportInfo::quicTraceConnectionId`, which moxygen stamps on its
MoQ objects. RX socket events carry no connection ID, because one server socket
serves every connection, and TX socket events name the connection whose batch
made the send.

## Boundaries

- **Read path.** RX packets start at the completion of the receive system call,
  on both of the server worker's read paths. mvfst's own `recvmmsg` read, which
  `TransportSettings::shouldUseWrapperRecvmmsgForBatchRecv` selects, brackets
  its call directly. On the default path folly makes the call, so the worker
  installs a netops dispatcher on its socket that times each `recvmsg` or
  `recvfrom` and hands the completion to `onDataAvailable` through a
  thread-local value, since folly calls it synchronously after the read. folly
  reads through the dispatcher only with the patch moxygen's traced build
  applies (`moq_trace/folly-read-dispatcher.patch` in the moxygen fork). Without
  it, or when a socket already has a dispatcher override, folly's reads go
  untimed and their packets get no RX trace.
- **Sends.** A send's completion is read right after the system call returns and
  shared with the batch through a thread-local value, so the `udp_socket` event
  and every packet the call carried end at the same instant. mvfst retries no
  failed send, would-block included, and recovers the batch as lost, so a failed
  send ends its packets `dropped`. A partial `sendmmsg` counts only the accepted
  messages in its socket event, but ends every packet of the batch at the send.
  The moxygen relay uses GSO, which sends a batch in one buffer.
- **Undecryptable packets.** A packet that arrives before its keys ends `dropped`,
  and when mvfst replays it with the keys it is traced again from its original
  read time.
- **Packet outcomes.** These match the Quinn fork's. A packet that parses but
  leaves processing through an error ends `malformed`, a duplicate or one from
  a peer that may not migrate ends `dropped`, and one whose processing
  completes, including one that closes the connection, ends `success`. Decoding
  a packet's frames, which the codec does before any is processed, belongs to
  no phase. A frame that ends processing with an error leaves its
  `frame_process` phase abandoned.
- **Server only.** The RX packet hooks sit in the server state machine. The
  client receives no packet traces.
- **Send-blocked intervals.** The transmit reasons are evaluated after every
  write attempt, so an interval ends at the first write after the limit lifts.
  Only the first transmit limit that holds is recorded, in the order
  amplification, congestion window, pacing. A blocked write records its interval
  on its stream, with the stream ID, as in Quinn and Google QUICHE: connection
  flow control from when the scheduler finds the stream blocked until MAX_DATA
  arrives, and the send buffer while a write callback waits for buffer space.

## Build

The hooks compile behind `MVFST_MOQ_TRACE`. The CMake option of the same name
finds the toolkit's `quic_trace` package on `CMAKE_PREFIX_PATH`, defines the
macro, and links the facade. The macro changes struct layouts in mvfst headers,
so a project that compiles other code against those headers, such as proxygen,
must define it for that code too. moxygen's standalone build does this when
`MOXYGEN_MOQ_TRACE` is on.
