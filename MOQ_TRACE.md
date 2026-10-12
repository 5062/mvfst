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
| `FollyQuicAsyncUDPSocket::write`, `writeGSO`, `writem`, `writemGSO` | TX `udp_socket` around each `sendmsg` or `sendmmsg`, with buffers, GSO datagrams, and bytes |
| `onServerReadDataFromOpen` | RX packet from the read's completion: `read_queue`, `header_parse`, `header_unprotect`, `payload_decrypt`, `frame_process`, and its outcome |
| `QuicReadCodec` | the boundaries of the parse stages, stamped only for a traced packet |
| server `ReadStreamFrame` handling | RX `quic_stream_frame`, `success` when the stream buffered the bytes and `dropped` when it was no longer open for receiving |
| `continuousMemoryBuildScheduleEncrypt`, `iobufChainBasedBuildScheduleEncrypt` | TX packet from the start of frame encoding: `frame_encode`, `packet_encrypt`, then `send_queue`, and its STREAM frames with their retransmission flag |
| `IOBufQuicBatch` | TX packet end at the completion of the send that carried its batch, or `dropped` when that send failed |
| first packet of a server connection, `QuicPathManager` path switch | `quic_connection_path` |
| `pacedWriteDataToSocket`, flow control | `quic_send_blocked` for the congestion window, pacing, amplification, connection flow control, and per-stream flow control |

Each connection allocates a process-wide connection ID from the toolkit and
exposes it as `TransportInfo::quicTraceConnectionId`, which moxygen stamps on its
MoQ objects. Socket events carry no connection ID, because one server socket
serves every connection.

## Boundaries

- **Read path.** RX packets start at the completion of the receive system call,
  so only datagrams from mvfst's own `recvmmsg` read are traced. That read path
  is selected by `TransportSettings::shouldUseWrapperRecvmmsgForBatchRecv`, which
  the moxygen relay sets with `-recvmmsg`. folly's read callback hides its system
  call, so a datagram it returns has no read time and its packets get no RX
  trace.
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
- **Server only.** The RX packet hooks sit in the server state machine. The
  client receives no packet traces.
- **Send-blocked intervals.** The connection-wide reasons are evaluated after
  every write attempt, so an interval ends at the first write after the limit
  lifts. Only the first transmit limit that holds is recorded, in the order
  amplification, congestion window, pacing.

## Build

The hooks compile behind `MVFST_MOQ_TRACE`. The CMake option of the same name
finds the toolkit's `quic_trace` package on `CMAKE_PREFIX_PATH`, defines the
macro, and links the facade. The macro changes struct layouts in mvfst headers,
so a project that compiles other code against those headers, such as proxygen,
must define it for that code too. moxygen's standalone build does this when
`MOXYGEN_MOQ_TRACE` is on.
