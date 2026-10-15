/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/ScopeGuard.h>
#include <folly/net/test/MockNetOpsDispatcher.h>
#include <gtest/gtest.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

namespace {
bool recording = false;
std::vector<struct quic_trace_quic_packet_end> packetEnds;
std::vector<struct quic_trace_udp_socket_end> socketEnds;
} // namespace

// Observe the real facade's events without needing a live LTTng session.
extern "C" bool __real_quic_trace_quic_packet_end_enabled();
extern "C" bool __wrap_quic_trace_quic_packet_end_enabled() {
  return recording || __real_quic_trace_quic_packet_end_enabled();
}
extern "C" void __real_quic_trace_quic_packet_end(
    const struct quic_trace_quic_packet_end* event);
extern "C" void __wrap_quic_trace_quic_packet_end(
    const struct quic_trace_quic_packet_end* event) {
  if (recording) {
    packetEnds.push_back(*event);
  } else {
    __real_quic_trace_quic_packet_end(event);
  }
}
extern "C" bool __real_quic_trace_udp_socket_end_enabled();
extern "C" bool __wrap_quic_trace_udp_socket_end_enabled() {
  return recording || __real_quic_trace_udp_socket_end_enabled();
}
extern "C" void __real_quic_trace_udp_socket_end(
    const struct quic_trace_udp_socket_end* event);
extern "C" void __wrap_quic_trace_udp_socket_end(
    const struct quic_trace_udp_socket_end* event) {
  if (recording) {
    socketEnds.push_back(*event);
  } else {
    __real_quic_trace_udp_socket_end(event);
  }
}

namespace quic::testing {
using namespace ::testing;

TEST(QuicBatchTrace, FinishesOnlyPacketsAcceptedBySendmmsg) {
  for (auto path :
       {DataPathType::ChainedMemory, DataPathType::ContinuousMemory}) {
    for (auto mode :
         {QuicBatchingMode::BATCHING_MODE_SENDMMSG,
          QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO}) {
      const bool gso = mode == QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO;
      const unsigned messages = gso ? 2 : 4;
      // -2 skips Happy Eyeballs; -1 fails its second attempt.
      for (int secondResult : {-2, -1, static_cast<int>(messages)}) {
        const bool secondSocket = secondResult != -2;
        for (int accepted : {-1, 0, 1, static_cast<int>(messages)}) {
          SCOPED_TRACE(static_cast<int>(path));
          SCOPED_TRACE(static_cast<int>(mode));
          SCOPED_TRACE(accepted);
          SCOPED_TRACE(secondResult);
          packetEnds.clear();
          socketEnds.clear();
          recording = true;
          SCOPE_EXIT { recording = false; };
          folly::EventBase evb;
          auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
          folly::AsyncUDPSocket socket(&evb);
          socket.bind(SocketAddress("127.0.0.1", 0));
          auto dispatcher =
              std::make_shared<NiceMock<folly::netops::test::MockDispatcher>>();
          dispatcher->forwardToDefaultImpl();
          socket.setOverrideNetOpsDispatcher(dispatcher);
          int attempts = 0;
          EXPECT_CALL(*dispatcher, sendmmsg(_, _, messages, _))
              .Times(secondSocket ? 4 : 2)
              .WillRepeatedly([&](auto, mmsghdr* msgs, auto, auto) {
                const int sent = attempts++ == 0 ? accepted : secondResult;
                for (int i = 0; i < sent; ++i) {
                  msgs[i].msg_len = 0;
                  for (size_t j = 0; j < msgs[i].msg_hdr.msg_iovlen; ++j) {
                    msgs[i].msg_len += msgs[i].msg_hdr.msg_iov[j].iov_len;
                  }
                }
                errno = sent < 0 ? EAGAIN : 0;
                return sent;
              });
          FollyQuicAsyncUDPSocket sock(qEvb, socket);
          folly::AsyncUDPSocket fallback(&evb);
          fallback.bind(SocketAddress("127.0.0.1", 0));
          fallback.setOverrideNetOpsDispatcher(dispatcher);
          QuicClientConnectionState conn(
              FizzClientQuicHandshakeContext::Builder().build());
          BufAccessor accessor(4096);
          conn.bufAccessor = &accessor;
          const SocketAddress peer("127.0.0.1", 1234);
          auto& happy = conn.happyEyeballsState;
          if (secondSocket) {
            happy.shouldWriteToFirstSocket = true;
            happy.shouldWriteToSecondSocket = true;
            happy.secondPeerAddress = peer;
            happy.secondSocket =
                std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, fallback);
          }
          IOBufQuicBatch batch(
              BatchWriterFactory::makeBatchWriter(mode, 4, path, conn, true),
              sock,
              peer,
              nullptr,
              secondSocket ? &happy : nullptr);
          const std::array<size_t, 4> sizes{8, 8, 4, 12};
          // Also exercise an untraced leading packet on the in-place path.
          const size_t firstTraced =
              path == DataPathType::ContinuousMemory ? 1 : 0;
          for (size_t round = 0; round < 2; ++round) {
            packetEnds.clear();
            socketEnds.clear();
            attempts = 0;
            for (size_t i = 0; i < sizes.size(); ++i) {
              auto buf = folly::IOBuf::copyBuffer(std::string(sizes[i], 'p'));
              if (path == DataPathType::ContinuousMemory) {
                memcpy(accessor.writableTail(), buf->data(), sizes[i]);
                accessor.append(sizes[i]);
                buf.reset();
              }
              quic_trace::PacketContext context;
              context.direction = QUIC_TRACE_DIRECTION_TX;
              context.packet_number = i;
              quic_trace::PendingSend pending;
              if (i >= firstTraced) {
                pending.add(quic_trace::Packet(context));
              }
              auto result =
                  batch.write(std::move(buf), sizes[i], std::move(pending));
              ASSERT_TRUE(result.has_value());
            }
            ASSERT_EQ(socketEnds.size(), secondSocket ? 2 : 1);
            ASSERT_EQ(packetEnds.size(), sizes.size() - firstTraced);
            const size_t sentPackets =
                accepted <= 0 ? 0
                              : (accepted == static_cast<int>(messages)
                                     ? sizes.size()
                                     : (gso ? 3 : accepted));
            for (size_t i = 0; i < packetEnds.size(); ++i) {
              const size_t packet = i + firstTraced;
              EXPECT_EQ(packetEnds[i].packet_number, packet);
              EXPECT_EQ(
                  packetEnds[i].outcome,
                  (packet < sentPackets || secondResult > 0)
                      ? QUIC_TRACE_PACKET_OUTCOME_SUCCESS
                      : QUIC_TRACE_PACKET_OUTCOME_DROPPED);
              EXPECT_EQ(
                  packetEnds[i].timestamp_ns,
                  (packet < sentPackets ? socketEnds.front()
                                        : socketEnds.back())
                      .timestamp_ns);
            }
          }
        }
      }
    }
  }
}
} // namespace quic::testing
