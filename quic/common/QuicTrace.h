/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

// Helpers for the quic_trace:* transport hooks of the moq-trace toolkit.
// Everything here compiles away unless MVFST_MOQ_TRACE is defined, which the
// MVFST_MOQ_TRACE CMake option does for every target that includes mvfst
// headers.

#if defined(MVFST_MOQ_TRACE)

#include <quic_trace/trace.hpp>

#include <sys/socket.h>
#include <cstdint>
#include <optional>

namespace quic {

/**
 * The completion of the latest send system call made on this thread.
 *
 * The socket wrapper sets it right after the call returns, and the batch that
 * made the call reads it as soon as the call unwinds to it, so both the
 * udp_socket event and the packets the send carried end at the same instant.
 * No other send can run on the thread in between.
 */
inline thread_local std::optional<uint64_t> quicTraceLastSendNs;

/**
 * Map a packet's protection type to the provider's packet space.
 *
 * A template, so this header needs no codec types: pass quic::ProtectionType.
 */
template <typename ProtectionTypeT>
quic_trace_packet_space quicTracePacketSpace(ProtectionTypeT protectionType) {
  switch (protectionType) {
    case ProtectionTypeT::Initial:
      return QUIC_TRACE_PACKET_SPACE_INITIAL;
    case ProtectionTypeT::Handshake:
      return QUIC_TRACE_PACKET_SPACE_HANDSHAKE;
    case ProtectionTypeT::ZeroRtt:
      return QUIC_TRACE_PACKET_SPACE_ZERO_RTT;
    default:
      return QUIC_TRACE_PACKET_SPACE_DATA;
  }
}

/**
 * Describe one end of a connection path for quic_connection_path.
 *
 * An address that is not IPv4 or IPv6, such as one never resolved, is
 * recorded as the unspecified IPv6 address with its port.
 */
template <typename Address>
quic_trace::PathEndpoint quicTracePathEndpoint(const Address& address) {
  const auto family = address.getFamily();
  if (family != AF_INET && family != AF_INET6) {
    return quic_trace::PathEndpoint::ipv6({}, address.getPort());
  }
  sockaddr_storage storage{};
  address.getAddress(&storage);
  return quic_trace::PathEndpoint::from_sockaddr(
      reinterpret_cast<const sockaddr*>(&storage));
}

/**
 * Boundaries of one packet's stages inside QuicReadCodec::parsePacket, on the
 * trace clock.
 *
 * The codec stamps a stage only when its caller asked it to, so an untraced
 * read reads no clock. A stage the packet never reached stays unset.
 */
struct QuicTraceParseStamps {
  std::optional<uint64_t> unprotectStartNs;
  std::optional<uint64_t> decryptStartNs;
  std::optional<uint64_t> decodeStartNs;
};

} // namespace quic

#endif // MVFST_MOQ_TRACE
