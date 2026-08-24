/**
 * @file src/stream.h
 * @brief Declarations for the streaming protocols.
 */
#pragma once

// standard includes
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

// lib includes
#include <boost/asio.hpp>

// local includes
#include "audio.h"
#include "crypto.h"
#include "stream_policy.h"
#include "video.h"

namespace platf::virtual_display {
  class session_lease_t;
}

#if defined(LUMEN_EXPERIMENTAL_MSQUIC) || defined(SUNSHINE_TESTS)
  namespace lumen::protocol_v3::media {
    class TransportSink;
  }

  namespace lumen::protocol_v3::runtime {
    class SessionResourceFactory;
  }
#endif

namespace stream {
  constexpr auto VIDEO_STREAM_PORT = 9;  ///< GameStream base-port offset used for the video UDP stream.
  constexpr auto CONTROL_PORT = 10;  ///< GameStream base-port offset used for the control channel.
  constexpr auto AUDIO_STREAM_PORT = 11;  ///< GameStream base-port offset used for the audio UDP stream.
  constexpr auto MICROPHONE_STREAM_PORT = 12;  ///< Lumen base-port offset used for authenticated client microphone UDP input.

  struct session_t;

#ifdef SUNSHINE_TESTS
  namespace session {
    /**
     * @brief Copy the session's video configuration for integration tests.
     *
     * @param session Allocated test session, or `nullptr`.
     * @return Session video configuration, or a default configuration for `nullptr`.
     */
    [[nodiscard]] video::config_t video_config_for_test(const std::shared_ptr<session_t> &session);
  }  // namespace session
#endif

  /**
   * @brief Test whether the platform client-microphone backend is usable.
   *
   * @return `true` when a microphone sink can be opened and its ABI validated.
   */
  [[nodiscard]] bool client_microphone_available();

  /**
   * @brief Convert the complete binary microphone session identifier into a route key.
   *
   * @param session_id Exact 16-byte identifier returned by RTSP SETUP.
   * @return Binary-safe key preserving every byte, including zeroes.
   */
  [[nodiscard]] std::string client_microphone_route_key(const std::array<std::uint8_t, 16> &session_id);

  /**
   * @brief Bounded 128-datagram replay window for authenticated microphone input.
   *
   * Call `may_accept()` before authentication as a cheap rejection and call
   * `commit()` only after the packet's authentication tag succeeds.
   */
  class microphone_replay_window_t {
  public:
    /**
     * @brief Check whether a sequence is neither duplicate nor too old.
     *
     * @param sequence Monotonic microphone datagram sequence.
     * @return `true` when authentication should be attempted.
     */
    [[nodiscard]] bool may_accept(std::uint64_t sequence) const;

    /**
     * @brief Check whether a sequence would advance the authenticated high-water mark.
     * @param sequence Monotonic microphone datagram sequence.
     * @return `true` before the first commit or when `sequence` is newer than every committed packet.
     */
    [[nodiscard]] bool would_advance(std::uint64_t sequence) const;

    /**
     * @brief Mark an authenticated sequence as received.
     *
     * @param sequence Authenticated sequence previously accepted by `may_accept()`.
     */
    void commit(std::uint64_t sequence);

    /**
     * @brief Clear all replay history for a newly negotiated RTSP generation.
     */
    void reset();

  private:
    std::array<std::uint64_t, 2> bitmap_ {};  ///< Bits for the highest sequence and 127 predecessors.
    std::uint64_t highest_ {};  ///< Highest authenticated sequence observed.
    bool initialized_ {};  ///< Whether `highest_` and `bitmap_` contain committed state.
  };

  /**
   * @brief Source-endpoint policy applied after microphone packet authentication.
   */
  class microphone_endpoint_tracker_t {
  public:
    /**
     * @brief Accept an authenticated endpoint or perform an authenticated NAT rebind.
     *
     * The first accepted packet must be HELLO. Once claimed, any authenticated
     * replay-new packet may update the endpoint to support NAT port changes.
     *
     * @param endpoint Source endpoint of the authenticated datagram.
     * @param hello Whether the datagram is a HELLO packet.
     * @return `true` when the packet may proceed to state handling.
     */
    [[nodiscard]] bool accept_authenticated(const boost::asio::ip::udp::endpoint &endpoint, bool hello);

    /**
     * @brief Determine whether an authenticated HELLO already claimed an endpoint.
     *
     * @return `true` after the first accepted HELLO.
     */
    [[nodiscard]] bool claimed() const;

    /**
     * @brief Return the currently authenticated source endpoint.
     *
     * @return Claimed endpoint, or a default endpoint before HELLO.
     */
    [[nodiscard]] const boost::asio::ip::udp::endpoint &endpoint() const;

    /**
     * @brief Forget the claimed endpoint at session teardown.
     */
    void reset();

  private:
    boost::asio::ip::udp::endpoint endpoint_;  ///< Last authenticated source endpoint.
    bool claimed_ {};  ///< Whether HELLO established the endpoint.
  };

  /**
   * @brief Stream configuration shared by capture and network senders.
   */
  struct config_t {
    audio::config_t audio;  ///< Audio capture configuration for the stream.
    video::config_t monitor;  ///< Video capture and encoder configuration for the selected monitor.

    std::shared_ptr<const stream_policy::EffectiveStreamPolicy> optimization_policy;  ///< Immutable policy resolved once during RTSP ANNOUNCE.
    stream_policy::ClientProtocol client_protocol {stream_policy::ClientProtocol::vanilla};  ///< Exact negotiated client family.

    int packetsize;  ///< Maximum payload size for network packets.
    int minRequiredFecPackets;  ///< Minimum recovery packets required before FEC is emitted.
    int mlFeatureFlags;  ///< Moonlight feature flags negotiated for this session.
    int controlProtocolType;  ///< GameStream control protocol variant selected by the client.
    int audioQosType;  ///< Audio QoS type.
    int videoQosType;  ///< Video QoS type.
    std::uint64_t video_path_budget_bps {};  ///< Declared or measured per-session wire-rate ceiling.

    uint32_t encryptionFlagsEnabled;  ///< Bitmask of GameStream encryption features enabled for the session.

    bool client_microphone;  ///< Whether this session negotiated authenticated client microphone input.
    std::shared_ptr<platf::virtual_display::session_lease_t> virtual_display_lease;  ///< Exactly-once ownership of an active Lumen VDD generation.

    std::optional<int> gcmap;  ///< Optional game-controller mapping override from the launch request.
  };

  namespace session {
    /**
     * @brief Enumerates supported state options.
     */
    enum class state_e : int {
      STOPPED,  ///< The session is stopped
      STOPPING,  ///< The session is stopping
      STARTING,  ///< The session is starting
      RUNNING,  ///< The session is running
    };

    /**
     * @brief Allocate and initialize platform input state for a stream.
     *
     * @param config Configuration values to apply.
     * @param launch_session Launch session.
     * @return Allocated object or identifier, or an error value on failure.
     */
    std::shared_ptr<session_t> alloc(config_t &config, rtsp_stream::launch_session_t &launch_session);
    /**
     * @brief Start a streaming session for the supplied peer address.
     *
     * @param session Active streaming or pairing session for the request.
     * @param addr_string Addr string.
     * @return Start status.
     */
    int start(const std::shared_ptr<session_t> &session, const std::string &addr_string);
    /**
     * @brief Stop a streaming session and prevent more packets from being queued.
     *
     * @param session Active streaming or pairing session for the request.
     */
    void stop(session_t &session);
    /**
     * @brief Wait for worker threads owned by the session to exit.
     *
     * @param session Active streaming or pairing session for the request.
     */
    void join(session_t &session);
    /**
     * @brief Platform handle returned from stream setup.
     *
     * @param session Active streaming or pairing session for the request.
     * @return Current lifecycle state for the stream session.
     */
    state_e state(session_t &session);
    /**
     * @brief Return the paired client certificate for a stream session.
     *
     * @param session Active streaming or pairing session for the request.
     * @return PEM certificate associated with the session's client.
     */
    const std::string &client_cert(session_t &session);

    /**
     * @brief Claim the single global client-microphone owner slot.
     *
     * @param launch_session_id Launch session attempting to enable microphone input.
     * @return `true` when the slot was free or already owned by the same launch session.
     */
    [[nodiscard]] bool claim_client_microphone(std::uint32_t launch_session_id);

    /**
     * @brief Release the client-microphone owner slot when held by a launch session.
     *
     * @param launch_session_id Launch session whose ownership is ending.
     */
    void release_client_microphone(std::uint32_t launch_session_id);
  }  // namespace session

#if defined(LUMEN_EXPERIMENTAL_MSQUIC) || defined(SUNSHINE_TESTS)
  /**
   * @brief Create the native START-owned protocol-v3 capture/input/media factory.
   *
   * The factory uses the existing capture, encoder, audio, input, and virtual
   * microphone primitives without entering RTSP or legacy UDP transport.
   *
   * @param transport Authenticated QUIC media sink retained by the runtime.
   * @return Owned factory used by the production v3 SessionBackend.
   */
  std::unique_ptr<lumen::protocol_v3::runtime::SessionResourceFactory>
    make_protocol_v3_session_resource_factory(
      lumen::protocol_v3::media::TransportSink &transport
    );
#endif
}  // namespace stream
