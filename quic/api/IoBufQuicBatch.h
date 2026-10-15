/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriter.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/QuicTrace.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

struct BufQuicBatchResult {
  uint64_t packetsSent{0};
  uint64_t bytesSent{0};
};

class IOBufQuicBatch {
 public:
  IOBufQuicBatch(
      BatchWriterPtr&& batchWriter,
      QuicAsyncUDPSocket& sock,
      const quic::SocketAddress& peerAddress,
      QuicTransportStatsCallback* statsCallback,
      QuicClientConnectionState::HappyEyeballsState* happyEyeballsState);

  ~IOBufQuicBatch() = default;

  // returns true if it succeeds and false if the loop should end
  [[nodiscard]] quic::Expected<bool, QuicError> write(
      BufPtr&& buf,
      size_t encodedSize);

#if defined(MVFST_MOQ_TRACE)
  // Write a traced packet. Its trace waits in the batch from the end of its
  // encryption until the send that carries it completes, and ends there.
  [[nodiscard]] quic::Expected<bool, QuicError>
  write(BufPtr&& buf, size_t encodedSize, quic_trace::PendingSend&& trace);
#endif

  [[nodiscard]] quic::Expected<bool, QuicError> flush();

#if defined(MVFST_MOQ_TRACE)
  // Name the connection whose packets this batch sends on its udp_socket
  // events.
  void setQuicTraceConnectionId(uint64_t connectionId) {
    quicTraceConnectionId_ = connectionId;
  }
#endif

  FOLLY_ALWAYS_INLINE uint64_t getPktSent() const {
    return result_.packetsSent;
  }

  FOLLY_ALWAYS_INLINE BufQuicBatchResult getResult() const {
    return result_;
  }

  [[nodiscard]] int getLastRetryableErrno() const {
    return lastRetryableErrno_;
  }

 private:
  void reset();

  // flushes the internal buffers
  [[nodiscard]] quic::Expected<bool, QuicError> flushInternal();

  /**
   * Returns whether or not the errno can be retried later.
   */
  bool isRetriableError(int err);

  BatchWriterPtr batchWriter_;
  QuicAsyncUDPSocket& sock_;
  const quic::SocketAddress& peerAddress_;
  QuicTransportStatsCallback* statsCallback_{nullptr};
  QuicClientConnectionState::HappyEyeballsState* happyEyeballsState_;
  BufQuicBatchResult result_;
  int lastRetryableErrno_{};

#if defined(MVFST_MOQ_TRACE)
  // Finish the accepted prefix at each socket attempt. Any remaining packets
  // are dropped when the flush ends, because mvfst does not retry that suffix.
  void quicTraceMarkSent();
  void quicTraceDropUnsent();

  // Cumulative byte ends include untraced packets, so sampling cannot shift
  // the accepted prefix. Empty traces need no entry or allocation.
  std::vector<std::pair<size_t, quic_trace::PendingSend>> quicTracePending_;
  size_t quicTraceBatchBytes_{0};
  std::optional<uint64_t> quicTraceConnectionId_;
#endif
};

} // namespace quic
