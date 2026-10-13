/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/ScopeGuard.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/SocketUtil.h>
#include <quic/common/StringUtils.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

namespace quic {
IOBufQuicBatch::IOBufQuicBatch(
    BatchWriterPtr&& batchWriter,
    QuicAsyncUDPSocket& sock,
    const quic::SocketAddress& peerAddress,
    QuicTransportStatsCallback* statsCallback,
    QuicClientConnectionState::HappyEyeballsState* happyEyeballsState)
    : batchWriter_(std::move(batchWriter)),

      sock_(sock),
      peerAddress_(peerAddress),
      statsCallback_(statsCallback),
      happyEyeballsState_(happyEyeballsState) {}

quic::Expected<bool, QuicError> IOBufQuicBatch::write(
    BufPtr&& buf,
    size_t encodedSize) {
#if defined(MVFST_MOQ_TRACE)
  return write(std::move(buf), encodedSize, quic_trace::PendingSend());
}

quic::Expected<bool, QuicError> IOBufQuicBatch::write(
    BufPtr&& buf,
    size_t encodedSize,
    quic_trace::PendingSend&& trace) {
#endif
  result_.packetsSent++;
  result_.bytesSent += encodedSize;

  // see if we need to flush the prev buffer(s)
  if (batchWriter_->needsFlush(encodedSize)) {
    // continue even if we get an error here
    auto result = flush();
    if (!result.has_value()) {
      return result;
    }
  }

#if defined(MVFST_MOQ_TRACE)
  // Join the batch only after the flush of the previous one, so the packet
  // ends at the send that carries it.
  quicTracePending_.append(std::move(trace));
#endif

  // try to append the new buffers
  if (batchWriter_->append(std::move(buf), encodedSize, peerAddress_, &sock_)) {
    // return if we get an error here
    return flush();
  }

  return true;
}

quic::Expected<bool, QuicError> IOBufQuicBatch::flush() {
  auto ret = flushInternal();
  reset();

  return ret;
}

void IOBufQuicBatch::reset() {
  batchWriter_->reset();
}

bool IOBufQuicBatch::isRetriableError(int err) {
  return err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS;
}

quic::Expected<bool, QuicError> IOBufQuicBatch::flushInternal() {
  if (batchWriter_->empty()) {
    return true;
  }

#if defined(MVFST_MOQ_TRACE)
  quicTraceSendConnectionId = quicTraceConnectionId_;
  SCOPE_EXIT {
    quicTraceSendConnectionId.reset();
  };
#endif
  bool written = false;
  Optional<int> firstSocketErrno;
  if (!happyEyeballsState_ || happyEyeballsState_->shouldWriteToFirstSocket) {
#if defined(MVFST_MOQ_TRACE)
    quicTraceLastSendNs.reset();
#endif
    auto consumed = batchWriter_->write(sock_, peerAddress_);
    if (consumed < 0) {
      firstSocketErrno = errno;
      lastRetryableErrno_ = errno;
    }
    written = (consumed >= 0);
#if defined(MVFST_MOQ_TRACE)
    // mvfst retries no failed send, would-block included, and recovers the
    // batch as lost, so a failed send drops every packet it held.
    quicTraceFinishPending(
        written ? QUIC_TRACE_PACKET_OUTCOME_SUCCESS
                : QUIC_TRACE_PACKET_OUTCOME_DROPPED);
    if (firstSocketErrno) {
      errno = *firstSocketErrno;
    }
#endif
    if (happyEyeballsState_) {
      happyEyeballsState_->shouldWriteToFirstSocket =
          (consumed >= 0 || isRetriableError(errno));

      if (!happyEyeballsState_->shouldWriteToFirstSocket) {
        sock_.pauseRead();
      }
    }
  }

  // If error occurred on first socket, kick off second socket immediately
  if (!written && happyEyeballsState_ &&
      happyEyeballsState_->connAttemptDelayTimeout &&
      happyEyeballsState_->connAttemptDelayTimeout
          ->isTimerCallbackScheduled()) {
    happyEyeballsState_->connAttemptDelayTimeout->cancelTimerCallback();
    happyEyeballsState_->connAttemptDelayTimeout->timeoutExpired();
  }

  Optional<int> secondSocketErrno;
  if (happyEyeballsState_ && happyEyeballsState_->shouldWriteToSecondSocket) {
    auto consumed = batchWriter_->write(
        *happyEyeballsState_->secondSocket,
        happyEyeballsState_->secondPeerAddress);
    if (consumed < 0) {
      secondSocketErrno = errno;
    }

    // written is marked true if either socket write succeeds
    written |= (consumed >= 0);
    happyEyeballsState_->shouldWriteToSecondSocket =
        (consumed >= 0 || isRetriableError(errno));
    if (!happyEyeballsState_->shouldWriteToSecondSocket) {
      happyEyeballsState_->secondSocket->pauseRead();
    }
  }

  if (!written && statsCallback_) {
    if (firstSocketErrno.has_value()) {
      QUIC_STATS(
          statsCallback_,
          onUDPSocketWriteError,
          QuicTransportStatsCallback::errnoToSocketErrorType(
              firstSocketErrno.value()));
    }
    if (secondSocketErrno.has_value()) {
      QUIC_STATS(
          statsCallback_,
          onUDPSocketWriteError,
          QuicTransportStatsCallback::errnoToSocketErrorType(
              secondSocketErrno.value()));
    }
  }

  // If we have no happy eyeballs state, we only care if the first socket had
  // an error. Otherwise we check both.
  if ((!happyEyeballsState_ && firstSocketErrno.has_value() &&
       !isRetriableError(firstSocketErrno.value())) ||
      (happyEyeballsState_ && !happyEyeballsState_->shouldWriteToFirstSocket &&
       !happyEyeballsState_->shouldWriteToSecondSocket)) {
    auto firstSocketErrorMsg = firstSocketErrno.has_value()
        ? fmt::format("{}, ", quic::errnoStr(firstSocketErrno.value()))
        : "";
    auto secondSocketErrorMsg = secondSocketErrno.has_value()
        ? quic::errnoStr(secondSocketErrno.value())
        : "";
    auto errorMsg =
        fmt::format("{}{}", firstSocketErrorMsg, secondSocketErrorMsg);
    // Both sockets becomes fatal, close connection
    MVVLOG(4) << "Error writing to the socket " << errorMsg << " "
              << peerAddress_;

    // We can get write error for any reason, close the conn only if network
    // is unreachable, for all others, we throw a transport exception
    if (isNetworkUnreachable(errno)) {
      return quic::make_unexpected(QuicError(
          LocalErrorCode::CONNECTION_ABANDONED,
          fmt::format("Error on socket write {}", errorMsg)));
    } else {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          fmt::format("Error on socket write {}", errorMsg)));
    }
  }

  if (!written) {
    // This can happen normally, so ignore. Now we treat most errors same
    // as a loss to avoid looping.
    return false; // done
  }

  return true; // success, not done yet
}

#if defined(MVFST_MOQ_TRACE)
void IOBufQuicBatch::quicTraceFinishPending(quic_trace_packet_outcome outcome) {
  if (quicTracePending_.empty()) {
    return;
  }
  // A writer that made no system call leaves no completion; end the packets
  // where the attempt returned.
  const uint64_t sentNs = quicTraceLastSendNs.value_or(quic_trace::now_ns());
  quicTracePending_.finish_at(outcome, sentNs);
}
#endif
} // namespace quic
