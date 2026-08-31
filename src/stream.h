/**
 * @file src/stream.h
 * @brief Declarations for the streaming protocols.
 */
#pragma once

// standard includes
#include <array>
#include <cstddef>
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

namespace rtsp_stream {
  struct launch_session_t;
}


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

  /**
   * @brief Run direct-frame shutdown before releasing its display-generation lease.
   *
   * @tparam StopFrameSource Callable that stops and resets the direct-frame source.
   * @tparam ReleaseDisplayLease Callable that releases and resets the VDD lease.
   * @param stop_frame_source Source shutdown action.
   * @param release_display_lease Lease release action.
   * @return Result returned by `release_display_lease` after source shutdown.
   */
  template<class StopFrameSource, class ReleaseDisplayLease>
  [[nodiscard]] bool ordered_virtual_display_cleanup(
    StopFrameSource &&stop_frame_source,
    ReleaseDisplayLease &&release_display_lease
  ) noexcept {
    std::forward<StopFrameSource>(stop_frame_source)();
    return std::forward<ReleaseDisplayLease>(release_display_lease)();
  }

  /**
   * @brief Decide whether legacy HDR may return to physical capture after VDD open fails.
   *
   * @param policy_optional Whether the configured legacy VDD policy permits fallback.
   * @param hdr_requested Whether the stream requested HDR capture.
   * @param topology_restored Whether VDD teardown restored the prior topology.
   * @return True only for optional HDR after a verified rollback.
   */
  [[nodiscard]] constexpr bool allow_legacy_physical_hdr_fallback(
    const bool policy_optional,
    const bool hdr_requested,
    const bool topology_restored
  ) noexcept {
    return policy_optional && hdr_requested && topology_restored;
  }

#ifdef _WIN32
  /**
   * @brief Stop/reset a session's direct-frame source, then release/reset its VDD lease.
   *
   * @param config Session configuration owning the source and lease.
   * @return True when no lease existed or the active lease released successfully.
   */
  [[nodiscard]] bool cleanup_virtual_display(config_t &config) noexcept;
#endif

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

#ifdef SUNSHINE_TESTS
    /** @brief Observations from the production ordered worker-start boundary. */
    struct startup_order_probe_t {
      state_e worker_observed_state {state_e::STOPPED};  ///< State observed immediately after the worker is launched.
      state_e final_state {state_e::STOPPED};  ///< State after the early worker requests stop.
      bool stop_transitioned {};  ///< Whether the early stop advanced RUNNING to STOPPING.
      bool worker_observed_committed_startup {};  ///< Whether RUNNING acquire observed prior startup side effects.
    };

    /**
     * @brief Exercise the exact STARTING, worker launch, startup commit, and RUNNING boundary.
     *
     * @return Deterministic observations from an early worker stop interleaving.
     */
    [[nodiscard]] startup_order_probe_t startup_order_probe_for_test();

    /** @brief Observations from a deterministic throw after one worker is constructed. */
    struct startup_failure_probe_t {
      state_e final_state {state_e::STOPPED};  ///< Terminal state that released the STARTING waiter.
      bool controlled_failure {};  ///< Whether the construction exception reached the startup caller.
      bool worker_joined {};  ///< Whether the already-constructed worker joined promptly.
      bool worker_entered_body {};  ///< Whether the worker incorrectly entered RUNNING-only work.
      bool commit_called {};  ///< Whether startup side effects ran after worker construction failed.
    };

    /**
     * @brief Throw after one worker and observe the exact production startup rollback boundary.
     *
     * @param fail_during_commit Whether to fail after construction inside startup commit.
     * @return Deterministic terminal-state, join, worker-gate, and side-effect observations.
     */
    [[nodiscard]] startup_failure_probe_t startup_failure_probe_for_test(bool fail_during_commit);

    /** @brief Observations from control admission racing failed startup rollback. */
    struct control_rollback_probe_t {
      bool controlled_failure {};  ///< Whether the deterministic startup failure reached the caller.
      bool unclaimed_session_rejected_while_starting {};  ///< Whether slow-path admission rejected the STARTING session.
      bool peer_alias_rejected_while_starting {};  ///< Whether fast-path admission rejected a STARTING peer alias.
      bool session_registration_removed {};  ///< Whether rollback erased the raw session registration.
      bool peer_alias_removed {};  ///< Whether rollback erased every peer alias targeting the session.
      bool all_bound_peers_disconnected {};  ///< Whether rollback disconnected every bound peer alias.
      bool bound_peer_cleared {};  ///< Whether rollback cleared the session's bound peer field.
      bool lookup_after_owner_release_rejected {};  ///< Whether lookup remained safe after destroying the session owner.
    };

    /**
     * @brief Race control admission against construction or commit failure and exercise rollback.
     *
     * @param fail_during_commit Whether startup fails during commit rather than worker construction.
     * @return Registry, peer cleanup, and post-destruction lookup observations.
     */
    [[nodiscard]] control_rollback_probe_t control_rollback_probe_for_test(bool fail_during_commit);
#endif

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
     * @brief Return the application process generation captured by a stream session.
     *
     * @param session Active streaming session.
     * @return Monotonic process generation associated with the RTSP launch.
     */
    std::uint64_t process_generation(session_t &session);

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

#ifdef SUNSHINE_TESTS
  /** @brief Raw observations from the exact production audio packet queue. */
  struct audio_packet_queue_probe_t {
    audio::AudioPacketDestination::enqueue_result_e first_enqueue;  ///< Admission of the first capacity-one packet.
    audio::AudioPacketDestination::enqueue_result_e full_enqueue;  ///< Admission while the capacity-one queue is full.
    audio::AudioPacketDestination::enqueue_result_e refill_enqueue;  ///< Admission after popping the first packet.
    audio::AudioPacketDestination::enqueue_result_e enqueue_after_repeated_close;  ///< Admission after two close calls.
    bool first_pop_present {};  ///< Whether the first queued packet was returned.
    std::uint8_t first_pop_tag {};  ///< Payload tag returned by the first pop.
    bool pop_after_repeated_close_present {};  ///< Whether close retained a queued packet.
    bool waiter_blocked_before_close {};  ///< Whether an empty-queue consumer remained blocked before close.
    bool waiter_ready_after_close {};  ///< Whether close woke the blocked consumer within the bounded wait.
    bool waiter_pop_present {};  ///< Whether the close-woken consumer received a packet.
  };

  /** @brief Raw observations from exact legacy audio destinations. */
  struct audio_destination_isolation_probe_t {
    audio::AudioPacketDestination::enqueue_result_e legacy_first_enqueue;  ///< First legacy owner admission.
    audio::AudioPacketDestination::enqueue_result_e legacy_second_while_full;  ///< Second owner admission while the shared queue is full.
    audio::AudioPacketDestination::enqueue_result_e legacy_second_after_pop;  ///< Second owner admission after capacity is released.
    audio::AudioPacketDestination::enqueue_result_e legacy_first_after_close;  ///< Closed first owner admission.
    audio::AudioPacketDestination::enqueue_result_e legacy_second_after_first_close;  ///< Live second owner admission after first closes.
    audio::AudioPacketDestination::enqueue_result_e legacy_second_after_owner_expiry;  ///< Second owner admission after its session expires.
    std::uint8_t legacy_first_pop_owner {};  ///< Session identity returned for the first legacy packet.
    std::uint8_t legacy_first_pop_tag {};  ///< Payload tag returned for the first legacy packet.
    std::uint8_t legacy_second_pop_owner {};  ///< Session identity returned for the second legacy packet.
    std::uint8_t legacy_second_pop_tag {};  ///< Payload tag returned for the second legacy packet.
    std::uint8_t legacy_second_after_close_owner {};  ///< Session identity returned after the first destination closes.
    std::uint8_t legacy_second_after_close_tag {};  ///< Payload tag returned after the first destination closes.
  };

  /** @brief Exercise exact capacity, pop, and close semantics of audio_packet_queue_t. */
  [[nodiscard]] audio_packet_queue_probe_t audio_packet_queue_probe_for_test();

  /** @brief Exercise exact legacy production destination isolation. */
  [[nodiscard]] audio_destination_isolation_probe_t audio_destination_isolation_probe_for_test();

  /**
   * @brief Raw observations from concurrent legacy video/audio UDP peer routing.
   */
  struct legacy_udp_peer_isolation_probe_t {
    std::uint16_t video_source_port {};  ///< Source port owned by the video-side client socket.
    std::uint16_t audio_source_port {};  ///< Source port owned by the audio-side client socket.
    std::uint16_t routed_video_port {};  ///< Last source port routed through the video receive path.
    std::uint16_t routed_audio_port {};  ///< Last source port routed through the audio receive path.
    std::size_t video_ping_count {};  ///< Number of video pings delivered through the production router.
    std::size_t audio_ping_count {};  ///< Number of audio pings delivered through the production router.
    bool every_video_peer_isolated {};  ///< Whether every video ping retained the video source endpoint.
    bool every_audio_peer_isolated {};  ///< Whether every audio ping retained the audio source endpoint.
    bool audio_datagram_reached_audio_socket {};  ///< Whether an audio reply reached the audio client socket.
    bool audio_datagram_reached_video_socket {};  ///< Whether an audio reply leaked to the video client socket.
  };

  /**
   * @brief Exercise the production legacy UDP router with simultaneous video and audio peers.
   *
   * @return Source-port routing and reply-delivery observations.
   */
  [[nodiscard]] legacy_udp_peer_isolation_probe_t legacy_udp_peer_isolation_probe_for_test();

#endif

}  // namespace stream
