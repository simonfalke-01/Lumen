/**
 * @file src/stream.cpp
 * @brief Definitions for the streaming protocols.
 */

// standard includes
#include <array>
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <future>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// lib includes
#include <boost/endian/arithmetic.hpp>
#include <openssl/err.h>
#include <rs.h>

extern "C" {
  // clang-format off
#include <moonlight-common-c/src/Limelight-internal.h>
  // clang-format on
}

// local includes
#include "client_microphone.h"
#include "client_microphone_protocol.h"
#include "config.h"
#include "display_device.h"
#include "globals.h"
#include "input.h"
#include "input_state.h"
#include "logging.h"
#include "network.h"
#include "platform/common.h"
#include "process.h"
#if defined(LUMEN_EXPERIMENTAL_MSQUIC) || defined(SUNSHINE_TESTS)
  #include "protocol_common/input_state.h"
  #include "protocol_v3/media_pipeline.h"
  #include "protocol_v3/runtime.h"
#endif
#include "stream.h"
#include "protocol_v3/start_mode_contract.h"
#include "sync.h"
#include "system_tray.h"
#include "thread_safe.h"
#include "utility.h"
#include "video_egress_queue.h"
#include "video_packetizer.h"

#ifdef _WIN32
  #include "platform/windows/fused_d3d11_policy.h"
  #include "platform/windows/virtual_display.h"
  #include "platform/windows/virtual_display_frame.h"
  #include "platform/windows/virtual_microphone.h"
#endif

constexpr int IDX_START_A = 0;  ///< Control-stream message index for the first stream-start packet.
constexpr int IDX_START_B = 1;  ///< Control-stream message index for the second stream-start packet.
constexpr int IDX_INVALIDATE_REF_FRAMES = 2;  ///< Control-stream message index for invalidate ref frames.
constexpr int IDX_LOSS_STATS = 3;  ///< Control-stream message index for loss stats.
constexpr int IDX_INPUT_DATA = 5;  ///< Control-stream message index for input data.
constexpr int IDX_RUMBLE_DATA = 6;  ///< Control-stream message index for rumble data.
constexpr int IDX_TERMINATION = 7;  ///< Control-stream message index for termination.
constexpr int IDX_PERIODIC_PING = 8;  ///< Control-stream message index for periodic ping.
constexpr int IDX_REQUEST_IDR_FRAME = 9;  ///< Control-stream message index for request idr frame.
constexpr int IDX_ENCRYPTED = 10;  ///< Control-stream message index for encrypted.
constexpr int IDX_HDR_MODE = 11;  ///< Control-stream message index for hdr mode.
constexpr int IDX_RUMBLE_TRIGGER_DATA = 12;  ///< Control-stream message index for rumble trigger data.
constexpr int IDX_SET_MOTION_EVENT = 13;  ///< Control-stream message index for set motion event.
constexpr int IDX_SET_RGB_LED = 14;  ///< Control-stream message index for set rgb led.
constexpr int IDX_SET_ADAPTIVE_TRIGGERS = 15;  ///< Control-stream message index for set adaptive triggers.

static const short packetTypes[] = {
  0x0305,  // Start A
  0x0307,  // Start B
  0x0301,  // Invalidate reference frames
  0x0201,  // Loss Stats
  0x0204,  // Frame Stats (unused)
  0x0206,  // Input data
  0x010b,  // Rumble data
  0x0109,  // Termination
  0x0200,  // Periodic Ping
  0x0302,  // IDR frame
  0x0001,  // fully encrypted
  0x010e,  // HDR mode
  0x5500,  // Rumble triggers (Sunshine protocol extension)
  0x5501,  // Set motion event (Sunshine protocol extension)
  0x5502,  // Set RGB LED (Sunshine protocol extension)
  0x5503,  // Set Adaptive triggers (Sunshine protocol extension)
};

namespace asio = boost::asio;
namespace sys = boost::system;

using asio::ip::tcp;
using asio::ip::udp;

using namespace std::literals;

namespace stream {
#ifdef _WIN32
  bool cleanup_virtual_display(config_t &config) noexcept {
    return ordered_virtual_display_cleanup(
      [&config]() noexcept {
        if (config.monitor.virtual_display_frame_source) {
          config.monitor.virtual_display_frame_source->stop();
          config.monitor.virtual_display_frame_source.reset();
        }
        config.monitor.virtual_display_active = false;
        config.monitor.virtual_display_direct_required = false;
      },
      [&config]() noexcept {
        const bool released = !config.virtual_display_lease || config.virtual_display_lease->release();
        config.virtual_display_lease.reset();
        return released;
      }
    );
  }
#endif

  bool microphone_replay_window_t::may_accept(std::uint64_t sequence) const {
    if (!initialized_ || sequence > highest_) {
      return true;
    }

    const auto distance = highest_ - sequence;
    if (distance >= 128) {
      return false;
    }

    const auto word = static_cast<std::size_t>(distance / 64);
    const auto bit = static_cast<unsigned int>(distance % 64);
    return (bitmap_[word] & (std::uint64_t {1} << bit)) == 0;
  }

  bool microphone_replay_window_t::would_advance(std::uint64_t sequence) const {
    return !initialized_ || sequence > highest_;
  }

  void microphone_replay_window_t::commit(std::uint64_t sequence) {
    if (!initialized_) {
      initialized_ = true;
      highest_ = sequence;
      bitmap_[0] = 1;
      bitmap_[1] = 0;
      return;
    }

    if (sequence > highest_) {
      const auto distance = sequence - highest_;
      if (distance >= 128) {
        bitmap_ = {1, 0};
      } else if (distance >= 64) {
        bitmap_[1] = bitmap_[0] << (distance - 64);
        bitmap_[0] = 1;
      } else {
        bitmap_[1] = (bitmap_[1] << distance) | (bitmap_[0] >> (64 - distance));
        bitmap_[0] = (bitmap_[0] << distance) | 1;
      }
      highest_ = sequence;
      return;
    }

    const auto distance = highest_ - sequence;
    if (distance < 128) {
      const auto word = static_cast<std::size_t>(distance / 64);
      const auto bit = static_cast<unsigned int>(distance % 64);
      bitmap_[word] |= std::uint64_t {1} << bit;
    }
  }

  void microphone_replay_window_t::reset() {
    bitmap_ = {};
    highest_ = 0;
    initialized_ = false;
  }

  bool microphone_endpoint_tracker_t::accept_authenticated(const udp::endpoint &endpoint, bool hello) {
    if (!claimed_ && !hello) {
      return false;
    }

    endpoint_ = endpoint;
    claimed_ = true;
    return true;
  }

  bool microphone_endpoint_tracker_t::claimed() const {
    return claimed_;
  }

  const udp::endpoint &microphone_endpoint_tracker_t::endpoint() const {
    return endpoint_;
  }

  void microphone_endpoint_tracker_t::reset() {
    endpoint_ = {};
    claimed_ = false;
  }

  bool client_microphone_available() {
#ifdef _WIN32
    auto microphone = platf::win_audio::make_virtual_microphone();
    return microphone && microphone->probe();
#else
    return false;
#endif
  }

  /**
   * @brief Enumerates supported socket options.
   */
  enum class socket_e : int {
    video,  ///< Video
    audio  ///< Audio
  };

#pragma pack(push, 1)

  /**
   * @brief Packed RTP header for an audio packet.
   */
  struct audio_packet_t {
    RTP_PACKET rtp;  ///< RTP header that prefixes this payload.
  };

  /**
   * @brief Packed control-channel header used before control payloads.
   */
  struct control_header_v2 {
    std::uint16_t type;  ///< Control message type.
    std::uint16_t payloadLength;  ///< Payload length.

    /**
     * @brief Return a pointer to the protocol payload following the packet header.
     *
     * @return Parsed or serialized payload data.
     */
    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }
  };

  /**
   * @brief Control-channel termination message payload.
   */
  struct control_terminate_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint32_t ec;  ///< Error code reported by the termination message.
  };

  /**
   * @brief Control payload that sets controller rumble motors.
   */
  struct control_rumble_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint32_t useless;  ///< Reserved field kept for protocol compatibility.

    std::uint16_t id;  ///< Controller identifier associated with this message.
    std::uint16_t lowfreq;  ///< Low-frequency rumble motor intensity.
    std::uint16_t highfreq;  ///< High-frequency rumble motor intensity.
  };

  /**
   * @brief Control payload that sets trigger rumble motors.
   */
  struct control_rumble_triggers_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint16_t id;  ///< Controller identifier associated with this message.
    std::uint16_t left;  ///< Left trigger or motor intensity.
    std::uint16_t right;  ///< Right trigger or motor intensity.
  };

  /**
   * @brief Control payload that enables or disables motion reports.
   */
  struct control_set_motion_event_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint16_t id;  ///< Controller identifier associated with this message.
    std::uint16_t reportrate;  ///< Requested motion report rate.
    std::uint8_t type;  ///< Protocol or controller type discriminator.
  };

  /**
   * @brief Control payload that sets controller RGB LED color.
   */
  struct control_set_rgb_led_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint16_t id;  ///< Controller identifier associated with this message.
    std::uint8_t r;  ///< Red LED channel.
    std::uint8_t g;  ///< Green LED channel.
    std::uint8_t b;  ///< Blue LED channel.
  };

  /**
   * @brief Control payload that configures DualSense adaptive triggers.
   */
  struct control_adaptive_triggers_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint16_t id;  ///< Controller identifier associated with this message.
    /**
     * 0x04 - Right trigger
     * 0x08 - Left trigger
     */
    std::uint8_t event_flags;
    std::uint8_t type_left;  ///< Adaptive-trigger mode for the left trigger.
    std::uint8_t type_right;  ///< Adaptive-trigger mode for the right trigger.
    std::uint8_t left[DS_EFFECT_PAYLOAD_SIZE];  ///< Left adaptive-trigger effect payload.
    std::uint8_t right[DS_EFFECT_PAYLOAD_SIZE];  ///< Right adaptive-trigger effect payload.
  };

  /**
   * @brief Control payload that toggles HDR mode and carries metadata.
   */
  struct control_hdr_mode_t {
    control_header_v2 header;  ///< Control message header preceding this payload.

    std::uint8_t enabled;  ///< Nonzero when HDR should be enabled.

    // Sunshine protocol extension
    SS_HDR_METADATA metadata;  ///< HDR10 metadata sent with the control message.
  };

  /**
   * @brief Packed encrypted control-channel envelope.
   */
  typedef struct control_encrypted_t {
    std::uint16_t encryptedHeaderType;  ///< Always LE 0x0001.
    std::uint16_t length;  ///< Size of seq, tag, secondary header, and data.

    // seq is accepted as an arbitrary value in Moonlight
    std::uint32_t seq;  ///< Monotonically increasing sequence number used as the AES-GCM IV.

    /**
     * @brief Return a pointer to the protocol payload following the packet header.
     *
     * @return Parsed or serialized payload data.
     */
    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }

    // encrypted control_header_v2 and payload data follow
  } *control_encrypted_p;  ///< Alias for control encrypted p.

  /**
   * @brief Packed RTP and FEC headers for an audio recovery packet.
   */
  struct audio_fec_packet_t {
    RTP_PACKET rtp;  ///< RTP header that prefixes this payload.
    AUDIO_FEC_HEADER fecHeader;  ///< Audio forward-error-correction header.
  };

#pragma pack(pop)

  /**
   * @brief Round a byte count up to the next PKCS#7 padding boundary.
   *
   * @param size Number of bytes or elements requested.
   * @return `size` rounded up to the next PKCS#7 block boundary.
   */
  constexpr std::size_t round_to_pkcs7_padded(std::size_t size) {
    return ((size + 15) / 16) * 16;
  }

  constexpr std::size_t MAX_AUDIO_PACKET_SIZE = 1400;  ///< Protocol or platform constant for max audio packet size.

  /**
   * @brief AES key storage used for audio packet encryption.
   */
  using audio_aes_t = std::array<char, round_to_pkcs7_padded(MAX_AUDIO_PACKET_SIZE)>;

  /**
   * @brief Audio/video session identifier carried by GameStream packets.
   */
  using av_session_id_t = std::variant<asio::ip::address, std::string>;  // IP address or SS-Ping-Payload from RTSP handshake
  /**
   * @brief Mail queue carrying encoded stream packets to sender threads.
   */
  using message_queue_t = std::shared_ptr<safe::queue_t<std::pair<udp::endpoint, std::string>>>;
  /**
   * @brief Shared queue set used to distribute packet queues to broadcast workers.
   */
  using message_queue_queue_t = std::shared_ptr<safe::queue_t<std::tuple<socket_e, av_session_id_t, message_queue_t>>>;

  // return bytes written on success
  // return -1 on error
  static inline int encode_audio(bool encrypted, const audio::buffer_t &plaintext, uint8_t *destination, crypto::aes_t &iv, crypto::cipher::cbc_t &cbc) {
    // If encryption isn't enabled
    if (!encrypted) {
      std::copy(std::begin(plaintext), std::end(plaintext), destination);
      return (int) plaintext.size();
    }

    return cbc.encrypt(std::string_view {(char *) std::begin(plaintext), plaintext.size()}, destination, &iv);
  }

  static inline void while_starting_do_nothing(std::atomic<session::state_e> &state) {
    while (state.load(std::memory_order_acquire) == session::state_e::STARTING) {
      std::this_thread::sleep_for(1ms);
    }
  }

  /**
   * @brief ENet control server that routes incoming control packets to stream sessions.
   */
  class control_server_t {
  public:
    /**
     * @brief Bind the underlying socket or graphics resource to its target.
     *
     * @param address_family Address family.
     * @param port TCP or UDP port number.
     * @return Network operation status.
     */
    int bind(net::af_e address_family, std::uint16_t port) {
      _host = net::host_create(address_family, _addr, port);

      return !(bool) _host;
    }

    // Get session associated with address.
    // If none are found, try to find a session not yet claimed. (It will be marked by a port of value 0
    // If none of those are found, return nullptr
    /**
     * @brief Return the session value from the backend.
     *
     * @param peer Remote endpoint associated with the socket.
     * @param connect_data Connect data.
     * @return Existing session for the peer/connect-data pair, or nullptr when none matches.
     */
    session_t *get_session(const net::peer_t peer, uint32_t connect_data);

    // Circular dependency:
    //   iterate refers to session
    //   session refers to broadcast_ctx_t
    //   broadcast_ctx_t refers to control_server_t
    // Therefore, iterate is implemented further down the source file
    /**
     * @brief Visit each active control server session.
     *
     * @param timeout Maximum time to wait for the operation.
     */
    void iterate(std::chrono::milliseconds timeout);

    /**
     * @brief Call the handler for a given control stream message.
     * @param type The message type.
     * @param session The session the message was received on.
     * @param payload The payload of the message.
     * @param reinjected `true` if this message is being reprocessed after decryption.
     */
    void call(std::uint16_t type, session_t *session, const std::string_view &payload, bool reinjected);

    /**
     * @brief Register or visit handlers stored in the map.
     *
     * @param type Protocol, message, or resource type selector.
     * @param cb Callback invoked for each matching message or session.
     */
    void map(uint16_t type, std::function<void(session_t *, const std::string_view &)> cb) {
      _map_type_cb.emplace(type, std::move(cb));
    }

    /**
     * @brief Send the serialized response over the active socket.
     *
     * @param payload Optional payload body to include in the response.
     * @param peer Remote endpoint associated with the socket.
     * @return Network operation status.
     */
    int send(const std::string_view &payload, net::peer_t peer) {
      auto packet = enet_packet_create(payload.data(), payload.size(), ENET_PACKET_FLAG_RELIABLE);
      if (enet_peer_send(peer, 0, packet)) {
        enet_packet_destroy(packet);

        return -1;
      }

      return 0;
    }

    /**
     * @brief Flush pending packets to the stream socket.
     */
    void flush() {
      enet_host_flush(_host.get());
    }

    // Callbacks
    std::unordered_map<std::uint16_t, std::function<void(session_t *, const std::string_view &)>> _map_type_cb;  ///< Control-message handlers keyed by packet type.

    // All active sessions (including those still waiting for a peer to connect)
    sync_util::sync_t<std::vector<session_t *>> _sessions;  ///< Active sessions registered with the control server.

    // ENet peer to session mapping for sessions with a peer connected
    sync_util::sync_t<std::map<net::peer_t, session_t *>> _peer_to_session;  ///< Peer to session.

    ENetAddress _addr;  ///< Local ENet address used by the control channel.
    net::host_t _host;  ///< ENet host object that owns the control socket.
  };

  /**
   * @brief UDP broadcast socket and target address state.
   */
  struct microphone_datagram_t {
    std::vector<std::uint8_t> bytes;  ///< Complete LMC1 datagram bytes.
    udp::endpoint peer;  ///< Source endpoint supplied by the UDP socket.
  };

  /**
   * @brief Bounded per-session queue carrying routed microphone datagrams.
   */
  using microphone_queue_t = std::shared_ptr<safe::queue_t<microphone_datagram_t>>;

  /**
   * @brief Bounded queue with exact audio-destination admission semantics.
   */
  template<class Packet>
  class audio_packet_queue_t {
  public:
    explicit audio_packet_queue_t(const std::size_t capacity = 32):
        capacity_ {capacity} {
    }

    [[nodiscard]] audio::AudioPacketDestination::enqueue_result_e enqueue(Packet packet) {
      std::lock_guard lock {mutex_};
      if (closed_) {
        return audio::AudioPacketDestination::enqueue_result_e::closed;
      }
      if (packets_.size() >= capacity_) {
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      packets_.push(std::move(packet));
      changed_.notify_one();
      return audio::AudioPacketDestination::enqueue_result_e::enqueued;
    }

    [[nodiscard]] std::optional<Packet> pop() {
      std::unique_lock lock {mutex_};
      changed_.wait(lock, [this]() {
        return closed_ || !packets_.empty();
      });
      if (closed_) {
        return std::nullopt;
      }
      auto packet = std::move(packets_.front());
      packets_.pop();
      return packet;
    }

    void close() noexcept {
      std::lock_guard lock {mutex_};
      closed_ = true;
      packets_ = {};
      changed_.notify_all();
    }

  private:
    std::size_t capacity_;
    std::queue<Packet> packets_;
    std::mutex mutex_;
    std::condition_variable changed_;
    bool closed_ {};
  };

  /**
   * @brief Encoded legacy packet paired with a typed, non-owning session route.
   */
  struct legacy_audio_packet_t {
    std::weak_ptr<session_t> session;
    audio::packet_t packet;
  };

  using legacy_audio_packet_queue_t = audio_packet_queue_t<legacy_audio_packet_t>;

  /**
   * @brief Convert a binary microphone session identifier into a map key.
   *
   * @param session_id Exact 16-byte session identifier.
   * @return Binary string preserving every identifier byte.
   */
  std::string client_microphone_route_key(const std::array<std::uint8_t, 16> &session_id) {
    return {
      reinterpret_cast<const char *>(session_id.data()),
      session_id.size()
    };
  }

  struct broadcast_ctx_t {
    message_queue_queue_t message_queue_queue;  ///< Queues carrying encoded video and audio packets to sender threads.

    std::jthread recv_thread;  ///< Thread that receives incoming control-channel messages.
    std::jthread video_thread;  ///< Thread that sends encoded video packets.
    std::jthread audio_thread;  ///< Thread that sends encoded audio packets.
    std::jthread control_thread;  ///< Thread that runs the ENet control server.
    std::jthread microphone_thread;  ///< Thread that routes reverse client microphone UDP datagrams.

    asio::io_context io_context;  ///< Asio context used by the UDP broadcast sockets.

    udp::socket video_sock {io_context};  ///< UDP socket bound for video packet transmission.
    udp::socket audio_sock {io_context};  ///< UDP socket bound for audio packet transmission.
    udp::socket microphone_sock {io_context};  ///< UDP socket bound for client microphone input.

    video::egress_queue_t video_egress;  ///< Fair bounded per-session encoded-video scheduler.
    std::shared_ptr<legacy_audio_packet_queue_t> audio_packets {std::make_shared<legacy_audio_packet_queue_t>()};  ///< Encoded legacy audio waiting for UDP transmission.

    sync_util::sync_t<std::unordered_map<std::string, std::weak_ptr<session_t>>> microphone_routes;  ///< Session-ID routes for reverse microphone UDP traffic.
    std::atomic_bool microphone_bound {};  ///< Whether the optional microphone UDP socket is bound and accepting datagrams.

    control_server_t control_server;  ///< ENet server for GameStream control packets.
  };

  /**
   * @brief Runtime state for one audio/video streaming session.
   */
  struct session_t {
    config_t config;  ///< Stream or encoder configuration captured for the worker.

    safe::mail_t mail;  ///< Mailbox used to distribute packets and lifecycle events.

    std::shared_ptr<input::input_t> input;  ///< Platform input device state for this stream.

    std::jthread audioThread;  ///< Audio thread.
    std::jthread videoThread;  ///< Video thread.
    std::jthread microphoneThread;  ///< Optional client microphone authentication, decode, and injection thread.

    std::chrono::steady_clock::time_point pingTimeout;  ///< Deadline for receiving the next client ping.

    safe::shared_t<broadcast_ctx_t>::ptr_t broadcast_ref;  ///< Shared broadcast context retained while the session is active.

    boost::asio::ip::address localAddress;  ///< Local address.

    struct {
      std::string ping_payload;

      int lowseq;
      udp::endpoint peer;

      std::optional<crypto::cipher::gcm_t> cipher;
      std::uint64_t gcm_iv_counter;

      safe::mail_raw_t::event_t<bool> idr_events;
      safe::mail_raw_t::event_t<std::pair<int64_t, int64_t>> invalidate_ref_frames_events;

      stream_policy::SessionPacingState pacing;  ///< Per-session packet pacing and duplicate timestamp basis.

      video_packetizer::Workspace packetizer;  ///< Per-session reusable packetization and FEC workspace.

      std::unique_ptr<platf::deinit_t> qos;
    } video;  ///< Video worker thread state for the active stream.

    struct {
      crypto::cipher::cbc_t cipher;
      std::string ping_payload;

      std::uint16_t sequenceNumber;
      // avRiKeyId == util::endian::big(First (sizeof(avRiKeyId)) bytes of launch_session->iv)
      std::uint32_t avRiKeyId;
      std::uint32_t timestamp;
      udp::endpoint peer;

      util::buffer_t<char> shards;
      util::buffer_t<uint8_t *> shards_p;

      audio_fec_packet_t fec_packet;
      std::unique_ptr<platf::deinit_t> qos;
      std::shared_ptr<audio::AudioPacketDestination> destination;  ///< Typed weak route from the encoder to this legacy session.
    } audio;  ///< Audio capture configuration for the stream..

    struct {
      crypto::cipher::gcm_t cipher;
      crypto::aes_t legacy_input_enc_iv;  // Only used when the client doesn't support full control stream encryption
      crypto::aes_t incoming_iv;
      crypto::aes_t outgoing_iv;

      std::uint32_t connect_data;  // Used for new clients with ML_FF_SESSION_ID_V1
      std::string expected_peer_address;  // Only used for legacy clients without ML_FF_SESSION_ID_V1

      net::peer_t peer;
      std::uint32_t seq;

      platf::feedback_queue_t feedback_queue;
      safe::mail_raw_t::event_t<video::hdr_info_t> hdr_queue;
    } control;  ///< Runtime state for the encrypted GameStream control channel.

    struct {
      std::array<std::uint8_t, 16> session_id {};  ///< Public routing identifier returned by SETUP.
      std::array<std::uint8_t, 16> salt {};  ///< HKDF salt returned by SETUP.
      std::array<std::uint8_t, 4> nonce_prefix {};  ///< HKDF-derived GCM nonce prefix.
      std::optional<crypto::aes_256_gcm_t> cipher;  ///< Microphone-specific AES-256-GCM key.
      microphone_replay_window_t replay;  ///< Authenticated 128-packet replay window.
      microphone_endpoint_tracker_t endpoints;  ///< Authenticated HELLO and NAT-rebind policy.
      microphone_queue_t datagrams;  ///< Bounded queue populated by the shared UDP router.
      std::unique_ptr<client_microphone::sink_t> sink;  ///< Platform virtual microphone injection backend.
      std::unique_ptr<client_microphone::receiver_t> receiver;  ///< Jitter, Opus, FEC, and PCM delivery core.
      std::uint64_t generation {};  ///< Current nonzero driver and decoder generation.
      std::uint64_t reset_sequence_barrier {};  ///< Newest authenticated RESET sequence already applied.
      bool reset_barrier_active {};  ///< Whether delayed pre-RESET media must be rejected.
      bool ended {};  ///< Whether authenticated END closed the negotiated generation.
    } microphone;  ///< Optional client-to-host microphone runtime state.

    std::uint32_t launch_session_id;  ///< RTSP launch-session ID associated with this stream.
    std::string client_cert;  ///< PEM certificate for the paired client owning the stream.

    safe::mail_raw_t::event_t<bool> shutdown_event;  ///< Event raised when the stream should shut down.
    safe::signal_t controlEnd;  ///< Signal raised when the control channel exits.

    std::atomic<session::state_e> state;  ///< Current lifecycle state observed by stream workers.
  };

  /**
   * @brief Legacy GameStream adapter for the shared UDP audio sender.
   */
  class legacy_audio_packet_destination final: public audio::AudioPacketDestination {
  public:
    legacy_audio_packet_destination(
      std::weak_ptr<session_t> session,
      std::weak_ptr<legacy_audio_packet_queue_t> packets
    ):
        session_ {std::move(session)},
        packets_ {std::move(packets)} {
    }

    [[nodiscard]] enqueue_result_e enqueue(audio::packet_t packet) override {
      std::lock_guard lock {mutex_};
      if (closed_) {
        return enqueue_result_e::closed;
      }
      auto packets = packets_.lock();
      if (!packets || session_.expired()) {
        closed_ = true;
        return enqueue_result_e::closed;
      }
      return packets->enqueue({session_, std::move(packet)});
    }

    void close() noexcept override {
      std::lock_guard lock {mutex_};
      closed_ = true;
    }

  private:
    std::weak_ptr<session_t> session_;
    std::weak_ptr<legacy_audio_packet_queue_t> packets_;
    std::mutex mutex_;
    bool closed_ {};
  };

  /**
   * First part of cipher must be struct of type control_encrypted_t
   *
   * returns empty string_view on failure
   * returns string_view pointing to payload data
   */
  template<std::size_t max_payload_size>
  static inline std::string_view encode_control(session_t *session, const std::string_view &plaintext, std::array<std::uint8_t, max_payload_size> &tagged_cipher) {
    static_assert(
      max_payload_size >= sizeof(control_encrypted_t) + sizeof(crypto::cipher::tag_size),
      "max_payload_size >= sizeof(control_encrypted_t) + sizeof(crypto::cipher::tag_size)"
    );

    if (session->config.controlProtocolType != 13) {
      return plaintext;
    }

    auto seq = session->control.seq++;

    auto &iv = session->control.outgoing_iv;
    if (session->config.encryptionFlagsEnabled & SS_ENC_CONTROL_V2) {
      // We use the deterministic IV construction algorithm specified in NIST SP 800-38D
      // Section 8.2.1. The sequence number is our "invocation" field and the 'CH' in the
      // high bytes is the "fixed" field. Because each client provides their own unique
      // key, our values in the fixed field need only uniquely identify each independent
      // use of the client's key with AES-GCM in our code.
      //
      // The sequence number is 32 bits long which allows for 2^32 control stream messages
      // to be sent to each client before the IV repeats.
      iv.resize(12);
      std::copy_n((uint8_t *) &seq, sizeof(seq), std::begin(iv));
      iv[10] = 'H';  // Host originated
      iv[11] = 'C';  // Control stream
    } else {
      // Nvidia's old style encryption uses a 16-byte IV
      iv.resize(16);

      iv[0] = (std::uint8_t) seq;
    }

    auto packet = (control_encrypted_p) tagged_cipher.data();

    auto bytes = session->control.cipher.encrypt(plaintext, packet->payload(), &iv);
    if (bytes <= 0) {
      BOOST_LOG(error) << "Couldn't encrypt control data"sv;
      return {};
    }

    std::uint16_t packet_length = bytes + crypto::cipher::tag_size + sizeof(control_encrypted_t::seq);

    packet->encryptedHeaderType = util::endian::little(0x0001);
    packet->length = util::endian::little(packet_length);
    packet->seq = util::endian::little(seq);

    return std::string_view {(char *) tagged_cipher.data(), packet_length + sizeof(control_encrypted_t) - sizeof(control_encrypted_t::seq)};
  }

  /**
   * @brief Start periodic mDNS and service-discovery broadcasts.
   *
   * @param ctx Native context object used by the operation or callback.
   * @return 0 on success; nonzero when broadcast setup fails.
   */
  int start_broadcast(broadcast_ctx_t &ctx);
  /**
   * @brief Stop broadcast processing.
   *
   * @param ctx Native context object used by the operation or callback.
   */
  void end_broadcast(broadcast_ctx_t &ctx);

  static auto broadcast = safe::make_shared<broadcast_ctx_t>(start_broadcast, end_broadcast);

  session_t *control_server_t::get_session(const net::peer_t peer, uint32_t connect_data) {
    {
      // Fast path - look up existing session by peer
      auto lg = _peer_to_session.lock();
      auto it = _peer_to_session->find(peer);
      if (it != _peer_to_session->end()) {
        return it->second;
      }
    }

    // Slow path - process new session
    TUPLE_2D(peer_port, peer_addr, platf::from_sockaddr_ex((sockaddr *) &peer->address.address));
    auto lg = _sessions.lock();
    for (auto pos = std::begin(*_sessions); pos != std::end(*_sessions); ++pos) {
      auto session_p = *pos;

      // Skip sessions that are already established
      if (session_p->control.peer) {
        continue;
      }

      // Identify the connection by the unique connect data if the client supports it.
      // Only fall back to IP address matching for clients without session ID support.
      if (session_p->config.mlFeatureFlags & ML_FF_SESSION_ID_V1) {
        if (session_p->control.connect_data != connect_data) {
          continue;
        } else {
          BOOST_LOG(debug) << "Initialized new control stream session by connect data match [v2]"sv;
        }
      } else {
        if (session_p->control.expected_peer_address != peer_addr) {
          continue;
        } else {
          BOOST_LOG(debug) << "Initialized new control stream session by IP address match [v1]"sv;
        }
      }

      // Once the control stream connection is established, RTSP session state can be torn down
      rtsp_stream::launch_session_clear(session_p->launch_session_id);

      session_p->control.peer = peer;

      // Use the local address from the control connection as the source address
      // for other communications to the client. This is necessary to ensure
      // proper routing on multi-homed hosts.
      auto local_address = platf::from_sockaddr((sockaddr *) &peer->localAddress.address);
      try {
        session_p->localAddress = boost::asio::ip::make_address(local_address);
      } catch (const boost::system::system_error &e) {
        BOOST_LOG(error) << "boost::system::system_error in address parsing: " << e.what() << " (code: " << e.code() << ")"sv;
        throw;
      }

      BOOST_LOG(debug) << "Control local address ["sv << local_address << ']';
      BOOST_LOG(debug) << "Control peer address ["sv << peer_addr << ':' << peer_port << ']';

      // Insert this into the map for O(1) lookups in the future
      auto ptslg = _peer_to_session.lock();
      _peer_to_session->emplace(peer, session_p);
      return session_p;
    }

    return nullptr;
  }

  /**
   * @brief Call the handler for a given control stream message.
   * @param type The message type.
   * @param session The session the message was received on.
   * @param payload The payload of the message.
   * @param reinjected `true` if this message is being reprocessed after decryption.
   */
  void control_server_t::call(std::uint16_t type, session_t *session, const std::string_view &payload, bool reinjected) {
    // If we are using the encrypted control stream protocol, drop any messages that come off the wire unencrypted
    if (session->config.controlProtocolType == 13 && !reinjected && type != packetTypes[IDX_ENCRYPTED]) {
      BOOST_LOG(error) << "Dropping unencrypted message on encrypted control stream: "sv << util::hex(type).to_string_view();
      return;
    }

    auto cb = _map_type_cb.find(type);
    if (cb == std::end(_map_type_cb)) {
      BOOST_LOG(debug)
        << "type [Unknown] { "sv << util::hex(type).to_string_view() << " }"sv << std::endl
        << "---data---"sv << std::endl
        << util::hex_vec(payload) << std::endl
        << "---end data---"sv;
    } else {
      cb->second(session, payload);
    }
  }

  void control_server_t::iterate(std::chrono::milliseconds timeout) {
    ENetEvent event;
    auto res = enet_host_service(_host.get(), &event, (enet_uint32) timeout.count());

    if (res > 0) {
      auto session = get_session(event.peer, event.data);
      if (!session) {
        BOOST_LOG(warning) << "Rejected connection from ["sv << platf::from_sockaddr((sockaddr *) &event.peer->address.address) << "]: it's not properly set up"sv;
        enet_peer_disconnect_now(event.peer, 0);

        return;
      }

      session->pingTimeout = std::chrono::steady_clock::now() + config::stream.ping_timeout;

      switch (event.type) {
        case ENET_EVENT_TYPE_RECEIVE:
          {
            net::packet_t packet {event.packet};

            auto type = *(std::uint16_t *) packet->data;
            std::string_view payload {(char *) packet->data + sizeof(type), packet->dataLength - sizeof(type)};

            call(type, session, payload, false);
          }
          break;
        case ENET_EVENT_TYPE_CONNECT:
          BOOST_LOG(info) << "CLIENT CONNECTED"sv;
          break;
        case ENET_EVENT_TYPE_DISCONNECT:
          BOOST_LOG(info) << "CLIENT DISCONNECTED"sv;
          // No more clients to send video data to ^_^
          if (session->state == session::state_e::RUNNING) {
            session::stop(*session);
          }
          break;
        case ENET_EVENT_TYPE_NONE:
          break;
      }
    }
  }

  namespace fec {
    /**
     * @brief Owning pointer for a Reed-Solomon encoder instance.
     */
    using rs_t = util::safe_ptr<reed_solomon, [](reed_solomon *rs) {
      reed_solomon_release(rs);
    }>;
  }  // namespace fec

  /**
   * @brief Combines two buffers and inserts new buffers at each slice boundary of the result.
   * @param insert_size The number of bytes to insert.
   * @param slice_size The number of bytes between insertions.
   * @param data1 The first data buffer.
   * @param data2 The second data buffer.
   *
   * @return Combined buffer with insert padding written at each slice boundary.
   */
  std::vector<uint8_t> concat_and_insert(uint64_t insert_size, uint64_t slice_size, const std::string_view &data1, const std::string_view &data2) {
    auto data_size = data1.size() + data2.size();
    auto pad = data_size % slice_size != 0;
    auto elements = data_size / slice_size + (pad ? 1 : 0);

    std::vector<uint8_t> result;
    result.resize(elements * insert_size + data_size);

    auto next = std::begin(data1);
    auto end = std::end(data1);
    for (auto x = 0; x < elements; ++x) {
      void *p = &result[x * (insert_size + slice_size)];

      // For the last iteration, only copy to the end of the data
      if (x == elements - 1) {
        slice_size = data_size - (x * slice_size);
      }

      // Test if this slice will extend into the next buffer
      if (next + slice_size > end) {
        // Copy the first portion from the first buffer
        auto copy_len = end - next;
        std::copy(next, end, (char *) p + insert_size);

        // Copy the remaining portion from the second buffer
        next = std::begin(data2);
        end = std::end(data2);
        std::copy(next, next + (slice_size - copy_len), (char *) p + copy_len + insert_size);
        next += slice_size - copy_len;
      } else {
        std::copy(next, next + slice_size, (char *) p + insert_size);
        next += slice_size;
      }
    }

    return result;
  }

  /**
   * @brief Replace a byte sequence in an encoded packet.
   *
   * @param original Original text value used when reporting a parsing failure.
   * @param old Byte sequence to replace in encoded packets.
   * @param _new Replacement byte sequence inserted into encoded packets.
   * @return Copy of the original buffer with each matching byte sequence replaced.
   */
  std::vector<uint8_t> replace(const std::string_view &original, const std::string_view &old, const std::string_view &_new) {
    std::vector<uint8_t> replaced;
    replaced.reserve(original.size() + _new.size() - old.size());

    auto begin = std::begin(original);
    auto end = std::end(original);
    auto next = std::search(begin, end, std::begin(old), std::end(old));

    std::copy(begin, next, std::back_inserter(replaced));
    if (next != end) {
      std::copy(std::begin(_new), std::end(_new), std::back_inserter(replaced));
      std::copy(next + old.size(), end, std::back_inserter(replaced));
    }

    return replaced;
  }

  /**
   * @brief Pass gamepad feedback data back to the client.
   * @param session The session object.
   * @param msg The message to pass.
   * @return 0 on success.
   */
  int send_feedback_msg(session_t *session, platf::gamepad_feedback_msg_t &msg) {
    if (!session->control.peer) {
      BOOST_LOG(warning) << "Couldn't send gamepad feedback data, still waiting for PING from Moonlight"sv;
      // Still waiting for PING from Moonlight
      return -1;
    }

    std::string payload;
    if (msg.type == platf::gamepad_feedback_e::rumble) {
      control_rumble_t plaintext;
      plaintext.header.type = packetTypes[IDX_RUMBLE_DATA];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rumble;

      plaintext.useless = 0xC0FFEE;
      plaintext.id = util::endian::little(msg.identity.id);
      plaintext.lowfreq = util::endian::little(data.lowfreq);
      plaintext.highfreq = util::endian::little(data.highfreq);

      BOOST_LOG(verbose) << "Rumble: "sv << msg.identity.id << " :: "sv << util::hex(data.lowfreq).to_string_view() << " :: "sv << util::hex(data.highfreq).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::rumble_triggers) {
      control_rumble_triggers_t plaintext;
      plaintext.header.type = packetTypes[IDX_RUMBLE_TRIGGER_DATA];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rumble_triggers;

      plaintext.id = util::endian::little(msg.identity.id);
      plaintext.left = util::endian::little(data.left_trigger);
      plaintext.right = util::endian::little(data.right_trigger);

      BOOST_LOG(verbose) << "Rumble triggers: "sv << msg.identity.id << " :: "sv << util::hex(data.left_trigger).to_string_view() << " :: "sv << util::hex(data.right_trigger).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_motion_event_state) {
      control_set_motion_event_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_MOTION_EVENT];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.motion_event_state;

      plaintext.id = util::endian::little(msg.identity.id);
      plaintext.reportrate = util::endian::little(data.report_rate);
      plaintext.type = data.motion_type;

      BOOST_LOG(verbose) << "Motion event state: "sv << msg.identity.id << " :: "sv << util::hex(data.report_rate).to_string_view() << " :: "sv << util::hex(data.motion_type).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_rgb_led) {
      control_set_rgb_led_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_RGB_LED];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rgb_led;

      plaintext.id = util::endian::little(msg.identity.id);
      plaintext.r = data.r;
      plaintext.g = data.g;
      plaintext.b = data.b;

      BOOST_LOG(verbose) << "RGB: "sv << msg.identity.id << " :: "sv << util::hex(data.r).to_string_view() << util::hex(data.g).to_string_view() << util::hex(data.b).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_adaptive_triggers) {
      control_adaptive_triggers_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_ADAPTIVE_TRIGGERS];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      plaintext.id = util::endian::little(msg.identity.id);
      plaintext.event_flags = msg.data.adaptive_triggers.event_flags;
      plaintext.type_left = msg.data.adaptive_triggers.type_left;
      std::ranges::copy(msg.data.adaptive_triggers.left, plaintext.left);
      plaintext.type_right = msg.data.adaptive_triggers.type_right;
      std::ranges::copy(msg.data.adaptive_triggers.right, plaintext.right);

      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else {
      BOOST_LOG(error) << "Unknown gamepad feedback message type"sv;
      return -1;
    }

    if (session->broadcast_ref->control_server.send(payload, session->control.peer)) {
      TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
      BOOST_LOG(warning) << "Couldn't send gamepad feedback to ["sv << addr << ':' << port << ']';

      return -1;
    }

    return 0;
  }

  /**
   * @brief Send the selected HDR mode to the connected client over the control channel.
   *
   * @param session Active streaming or pairing session for the request.
   * @param hdr_info HDR info.
   * @return 0 when the control message is queued; nonzero when no control peer is ready.
   */
  int send_hdr_mode(session_t *session, video::hdr_info_t hdr_info) {
    if (!session->control.peer) {
      BOOST_LOG(warning) << "Couldn't send HDR mode, still waiting for PING from Moonlight"sv;
      // Still waiting for PING from Moonlight
      return -1;
    }

    control_hdr_mode_t plaintext {};
    plaintext.header.type = packetTypes[IDX_HDR_MODE];
    plaintext.header.payloadLength = sizeof(control_hdr_mode_t) - sizeof(control_header_v2);

    plaintext.enabled = hdr_info->enabled;
    plaintext.metadata = hdr_info->metadata;

    std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
      encrypted_payload;

    auto payload = encode_control(session, util::view(plaintext), encrypted_payload);
    if (session->broadcast_ref->control_server.send(payload, session->control.peer)) {
      TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
      BOOST_LOG(warning) << "Couldn't send HDR mode to ["sv << addr << ':' << port << ']';

      return -1;
    }

    BOOST_LOG(debug) << "Sent HDR mode: " << hdr_info->enabled;
    return 0;
  }

  /**
   * @brief Run the broadcast control-channel worker thread.
   *
   * @param server RTSP server instance handling the request.
   */
  void controlBroadcastThread(control_server_t *server) {
    server->map(packetTypes[IDX_PERIODIC_PING], [](session_t *session, const std::string_view &payload) {
      BOOST_LOG(verbose) << "type [IDX_PERIODIC_PING]"sv;
    });

    server->map(packetTypes[IDX_START_A], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_START_A]"sv;
    });

    server->map(packetTypes[IDX_START_B], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_START_B]"sv;
    });

    server->map(packetTypes[IDX_LOSS_STATS], [&](session_t *session, const std::string_view &payload) {
      int32_t *stats = (int32_t *) payload.data();
      auto count = stats[0];
      std::chrono::milliseconds t {stats[1]};

      auto lastGoodFrame = stats[3];

      BOOST_LOG(verbose)
        << "type [IDX_LOSS_STATS]"sv << std::endl
        << "---begin stats---" << std::endl
        << "loss count since last report [" << count << ']' << std::endl
        << "time in milli since last report [" << t.count() << ']' << std::endl
        << "last good frame [" << lastGoodFrame << ']' << std::endl
        << "---end stats---";
    });

    server->map(packetTypes[IDX_REQUEST_IDR_FRAME], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_REQUEST_IDR_FRAME]"sv;

      session->video.idr_events->raise(true);
    });

    server->map(packetTypes[IDX_INVALIDATE_REF_FRAMES], [&](session_t *session, const std::string_view &payload) {
      auto frames = (std::int64_t *) payload.data();
      auto firstFrame = frames[0];
      auto lastFrame = frames[1];

      BOOST_LOG(debug)
        << "type [IDX_INVALIDATE_REF_FRAMES]"sv << std::endl
        << "firstFrame [" << firstFrame << ']' << std::endl
        << "lastFrame [" << lastFrame << ']';

      session->video.invalidate_ref_frames_events->raise(std::make_pair(firstFrame, lastFrame));
    });

    server->map(packetTypes[IDX_INPUT_DATA], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_INPUT_DATA]"sv;

      auto tagged_cipher_length = util::endian::big(*(int32_t *) payload.data());
      std::string_view tagged_cipher {payload.data() + sizeof(tagged_cipher_length), (size_t) tagged_cipher_length};

      std::vector<uint8_t> plaintext;

      auto &cipher = session->control.cipher;
      auto &iv = session->control.legacy_input_enc_iv;
      if (cipher.decrypt(tagged_cipher, plaintext, &iv)) {
        // something went wrong :(

        BOOST_LOG(error) << "Failed to verify tag"sv;

        session::stop(*session);
        return;
      }

      if (tagged_cipher_length >= 16 + iv.size()) {
        std::copy(payload.end() - 16, payload.end(), std::begin(iv));
      }

      input::passthrough(session->input, std::move(plaintext));
    });

    server->map(packetTypes[IDX_ENCRYPTED], [server](session_t *session, const std::string_view &payload) {
      BOOST_LOG(verbose) << "type [IDX_ENCRYPTED]"sv;

      auto header = (control_encrypted_p) (payload.data() - 2);

      auto length = util::endian::little(header->length);
      auto seq = util::endian::little(header->seq);

      if (length < (16 + 4 + 4)) {
        BOOST_LOG(warning) << "Control: Runt packet"sv;
        return;
      }

      auto tagged_cipher_length = length - 4;
      std::string_view tagged_cipher {(char *) header->payload(), (size_t) tagged_cipher_length};

      auto &cipher = session->control.cipher;
      auto &iv = session->control.incoming_iv;
      if (session->config.encryptionFlagsEnabled & SS_ENC_CONTROL_V2) {
        // We use the deterministic IV construction algorithm specified in NIST SP 800-38D
        // Section 8.2.1. The sequence number is our "invocation" field and the 'CC' in the
        // high bytes is the "fixed" field. Because each client provides their own unique
        // key, our values in the fixed field need only uniquely identify each independent
        // use of the client's key with AES-GCM in our code.
        //
        // The sequence number is 32 bits long which allows for 2^32 control stream messages
        // to be received from each client before the IV repeats.
        iv.resize(12);
        std::copy_n((uint8_t *) &seq, sizeof(seq), std::begin(iv));
        iv[10] = 'C';  // Client originated
        iv[11] = 'C';  // Control stream
      } else {
        // Nvidia's old style encryption uses a 16-byte IV
        iv.resize(16);

        iv[0] = (std::uint8_t) seq;
      }

      std::vector<uint8_t> plaintext;
      if (cipher.decrypt(tagged_cipher, plaintext, &iv)) {
        // something went wrong :(

        BOOST_LOG(error) << "Failed to verify tag"sv;

        session::stop(*session);
        return;
      }

      auto type = *(std::uint16_t *) plaintext.data();
      std::string_view next_payload {(char *) plaintext.data() + 4, plaintext.size() - 4};

      if (type == packetTypes[IDX_ENCRYPTED]) {
        BOOST_LOG(error) << "Bad packet type [IDX_ENCRYPTED] found"sv;
        session::stop(*session);
        return;
      }

      // IDX_INPUT_DATA callback will attempt to decrypt unencrypted data, therefore we need pass it directly
      if (type == packetTypes[IDX_INPUT_DATA]) {
        plaintext.erase(std::begin(plaintext), std::begin(plaintext) + 4);
        input::passthrough(session->input, std::move(plaintext));
      } else {
        server->call(type, session, next_payload, true);
      }
    });

    // This thread handles latency-sensitive control messages
    platf::set_thread_name("stream::controlBroadcast");
    platf::adjust_thread_priority(platf::thread_priority_e::critical);

    // Check for both the full shutdown event and the shutdown event for this
    // broadcast to ensure we can inform connected clients of our graceful
    // termination when we shut down.
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    while (!shutdown_event->peek() && !broadcast_shutdown_event->peek()) {
      bool has_session_awaiting_peer = false;

      {
        auto lg = server->_sessions.lock();

        auto now = std::chrono::steady_clock::now();

        KITTY_WHILE_LOOP(auto pos = std::begin(*server->_sessions), pos != std::end(*server->_sessions), {
          // Don't perform additional session processing if we're shutting down
          if (shutdown_event->peek() || broadcast_shutdown_event->peek()) {
            break;
          }

          auto session = *pos;

          if (now > session->pingTimeout) {
            auto address = session->control.peer ? platf::from_sockaddr((sockaddr *) &session->control.peer->address.address) : session->control.expected_peer_address;
            BOOST_LOG(info) << address << ": Ping Timeout"sv;
            session::stop(*session);
          }

          if (session->state.load(std::memory_order_acquire) == session::state_e::STOPPING) {
            pos = server->_sessions->erase(pos);

            if (session->control.peer) {
              {
                auto ptslg = server->_peer_to_session.lock();
                server->_peer_to_session->erase(session->control.peer);
              }

              enet_peer_disconnect_now(session->control.peer, 0);
            }

            session->controlEnd.raise(true);
            continue;
          }

          // Remember if we have a session that's waiting for a peer to connect to the
          // control stream. This ensures the clients are properly notified even when
          // the app terminates before they finish connecting.
          if (!session->control.peer) {
            has_session_awaiting_peer = true;
          } else {
            auto &feedback_queue = session->control.feedback_queue;
            while (feedback_queue->peek()) {
              auto feedback_msg = feedback_queue->pop();

              send_feedback_msg(session, *feedback_msg);
            }

            auto &hdr_queue = session->control.hdr_queue;
            while (session->control.peer && hdr_queue->peek()) {
              auto hdr_info = hdr_queue->pop();

              send_hdr_mode(session, std::move(hdr_info));
            }
          }

          ++pos;
        })
      }

      // Don't break until any pending sessions either expire or connect
      if (proc::proc.running() == 0 && !has_session_awaiting_peer) {
        BOOST_LOG(info) << "Process terminated"sv;
        break;
      }

      server->iterate(150ms);
    }

    // Let all remaining connections know the server is shutting down
    // reason: graceful termination
    std::uint32_t reason = 0x80030023;

    control_terminate_t plaintext;
    plaintext.header.type = packetTypes[IDX_TERMINATION];
    plaintext.header.payloadLength = sizeof(plaintext.ec);
    plaintext.ec = util::endian::big<uint32_t>(reason);

    std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
      encrypted_payload;

    auto lg = server->_sessions.lock();
    for (auto pos = std::begin(*server->_sessions); pos != std::end(*server->_sessions); ++pos) {
      auto session = *pos;

      // We may not have gotten far enough to have an ENet connection yet
      if (session->control.peer) {
        auto payload = encode_control(session, util::view(plaintext), encrypted_payload);

        if (server->send(payload, session->control.peer)) {
          TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
          BOOST_LOG(warning) << "Couldn't send termination code to ["sv << addr << ':' << port << ']';
        }
      }

      session->shutdown_event->raise(true);
      session->controlEnd.raise(true);
    }

    server->flush();
  }

  /**
   * @brief Receive thread data.
   *
   * @param ctx Native context object used by the operation or callback.
   */
  void recvThread(broadcast_ctx_t &ctx) {
    std::map<av_session_id_t, message_queue_t> peer_to_video_session;
    std::map<av_session_id_t, message_queue_t> peer_to_audio_session;

    auto &video_sock = ctx.video_sock;
    auto &audio_sock = ctx.audio_sock;

    auto &message_queue_queue = ctx.message_queue_queue;
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    auto &io = ctx.io_context;

    udp::endpoint peer;

    std::array<char, 2048> buf[2];
    std::function<void(const boost::system::error_code, size_t)> recv_func[2];

    platf::set_thread_name("stream::recv");

    auto populate_peer_to_session = [&]() {
      while (message_queue_queue->peek()) {
        auto message_queue_opt = message_queue_queue->pop();
        TUPLE_3D_REF(socket_type, session_id, message_queue, *message_queue_opt);

        switch (socket_type) {
          case socket_e::video:
            if (message_queue) {
              peer_to_video_session.emplace(session_id, message_queue);
            } else {
              peer_to_video_session.erase(session_id);
            }
            break;
          case socket_e::audio:
            if (message_queue) {
              peer_to_audio_session.emplace(session_id, message_queue);
            } else {
              peer_to_audio_session.erase(session_id);
            }
            break;
        }
      }
    };

    auto recv_func_init = [&](udp::socket &sock, int buf_elem, std::map<av_session_id_t, message_queue_t> &peer_to_session) {
      recv_func[buf_elem] = [&, buf_elem](const boost::system::error_code &ec, size_t bytes) {
        auto fg = util::fail_guard([&]() {
          sock.async_receive_from(asio::buffer(buf[buf_elem]), peer, 0, recv_func[buf_elem]);
        });

        auto type_str = buf_elem ? "AUDIO"sv : "VIDEO"sv;
        BOOST_LOG(verbose) << "Recv: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;

        populate_peer_to_session();

        // No data, yet no error
        if (ec == boost::system::errc::connection_refused || ec == boost::system::errc::connection_reset) {
          return;
        }

        if (ec || !bytes) {
          BOOST_LOG(error) << "Couldn't receive data from udp socket: "sv << ec.message();
          return;
        }

        if (bytes == 4) {
          // For legacy PING packets, find the matching session by address.
          auto it = peer_to_session.find(peer.address());
          if (it != std::end(peer_to_session)) {
            BOOST_LOG(debug) << "RAISE: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;
            it->second->raise(peer, std::string {buf[buf_elem].data(), bytes});
          }
        } else if (bytes >= sizeof(SS_PING)) {
          auto ping = (PSS_PING) buf[buf_elem].data();

          // For new PING packets that include a client identifier, search by payload.
          auto it = peer_to_session.find(std::string {ping->payload, sizeof(ping->payload)});
          if (it != std::end(peer_to_session)) {
            BOOST_LOG(debug) << "RAISE: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;
            it->second->raise(peer, std::string {buf[buf_elem].data(), bytes});
          }
        }
      };
    };

    recv_func_init(video_sock, 0, peer_to_video_session);
    recv_func_init(audio_sock, 1, peer_to_audio_session);

    video_sock.async_receive_from(asio::buffer(buf[0]), peer, 0, recv_func[0]);
    audio_sock.async_receive_from(asio::buffer(buf[1]), peer, 0, recv_func[1]);

    while (!broadcast_shutdown_event->peek()) {
      io.run();
    }
  }

  /**
   * @brief Run the broadcast video sender thread.
   *
   * @param sock Socket used to read or write the protocol message.
   * @param egress Per-session scheduler supplying fair encoded-frame leases.
   */
  void videoBroadcastThread(udp::socket &sock, video::egress_queue_t &egress) {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    auto video_epoch = std::chrono::steady_clock::now();

    // Video traffic is sent on this thread
    platf::set_thread_name("stream::videoBroadcast");
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    logging::min_max_avg_periodic_logger<double> frame_processing_latency_logger(debug, "Frame processing latency", "ms");
    logging::min_max_avg_periodic_logger<double> video_egress_age_logger(debug, "Video egress queue age", "ms");
    logging::min_max_avg_periodic_logger<std::size_t> video_egress_depth_logger(debug, "Video egress session depth", " frames");

    logging::time_delta_periodic_logger frame_send_batch_latency_logger(debug, "Network: each send_batch() latency");
    logging::time_delta_periodic_logger frame_fec_latency_logger(debug, "Network: each FEC block latency");
    logging::time_delta_periodic_logger frame_network_latency_logger(debug, "Network: frame's overall network latency");

    crypto::aes_t iv(12);

    auto timer = platf::create_high_precision_timer();
    if (!timer || !*timer) {
      BOOST_LOG(error) << "Failed to create timer, aborting video broadcast thread";
      return;
    }

    while (auto dequeued = egress.pop()) {
      auto &packet = dequeued->packet;
#ifdef _WIN32
      const auto telemetry_sender_dequeue_ns = platf::dxgi::fused_d3d11::telemetry_t::now_ns();
#endif
      if (shutdown_event->peek()) {
        break;
      }

#ifdef _WIN32
      if (packet->frame_timestamp) {
        const auto source_timestamp_ns = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(packet->frame_timestamp->time_since_epoch()).count()
        );
        (void) platf::dxgi::fused_d3d11::telemetry().record_sender_dequeue(
          static_cast<std::uint64_t>(packet->frame_index()),
          source_timestamp_ns,
          telemetry_sender_dequeue_ns
        );
      }
#endif

      video_egress_age_logger.collect_and_log(
        std::chrono::duration<double, std::milli> {dequeued->queue_age}.count()
      );
      video_egress_depth_logger.collect_and_log(dequeued->depth_after_dequeue);

      auto session = static_cast<session_t *>(dequeued->session);
      try {
        frame_network_latency_logger.first_point_now();

        auto lowseq = session->video.lowseq;

        std::string_view payload {(char *) packet->data(), packet->data_size()};
        std::vector<uint8_t> payload_with_replacements;

        // Apply replacements on the packet payload before performing any other operations.
        // We need to know the final frame size to calculate the last packet size, and we
        // must avoid matching replacements against the frame header or any other non-video
        // part of the payload.
        if (packet->is_idr() && packet->replacements) {
          for (auto &replacement : *packet->replacements) {
            auto frame_old = replacement.old;
            auto frame_new = replacement._new;

            payload_with_replacements = replace(payload, frame_old, frame_new);
            payload = {(char *) payload_with_replacements.data(), payload_with_replacements.size()};
          }
        }

        std::uint16_t frame_processing_latency {};
        if (packet->frame_timestamp) {
          auto duration_to_latency = [](const std::chrono::steady_clock::duration &duration) {
            const auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
            return (uint16_t) std::clamp<decltype(duration_us)>((duration_us + 50) / 100, 0, std::numeric_limits<uint16_t>::max());
          };

          frame_processing_latency = duration_to_latency(std::chrono::steady_clock::now() - *packet->frame_timestamp);
          frame_processing_latency_logger.collect_and_log(frame_processing_latency / 10.);
        }

        const auto recovery_critical = packet->is_idr() || packet->after_ref_frame_invalidation;
        const auto fecPercentage = stream_policy::maximum_fec_percentage(*session->config.optimization_policy);
        const auto blocksize = static_cast<std::size_t>(session->config.packetsize + MAX_RTP_HEADER_SIZE);
        const auto payload_blocksize = blocksize - video_packetizer::raw_packet_header_size;
        const auto frame_kind = packet->is_idr()                     ? video_packetizer::FrameKind::idr :
                                packet->after_ref_frame_invalidation ? video_packetizer::FrameKind::reference_recovery :
                                                                       video_packetizer::FrameKind::normal;
        const auto frame_header = video_packetizer::make_short_frame_header(
          frame_kind,
          frame_processing_latency,
          payload.size(),
          payload_blocksize
        );
        auto &packetizer = session->video.packetizer;
        const auto frame_header_bytes = std::span<const std::uint8_t> {frame_header};
        const auto zero_fec_plan = packetizer.plan_frame(
          frame_header.size(),
          payload.size(),
          video_packetizer::raw_packet_header_size,
          blocksize,
          0
        );
        const auto zero_fec_selection = stream_policy::select_frame_fec(
          *session->config.optimization_policy,
          recovery_critical,
          zero_fec_plan.packet_count,
          session->config.minRequiredFecPackets
        );
        const auto frame_plan = zero_fec_selection.percentage == 0 ?
                                  zero_fec_plan :
                                  packetizer.plan_frame(
                                    frame_header.size(),
                                    payload.size(),
                                    video_packetizer::raw_packet_header_size,
                                    blocksize,
                                    fecPercentage
                                  );
        const bool use_segmented_zero_fec =
          session->config.optimization_policy->mode == stream_policy::StreamOptimizationMode::latency &&
          session->config.optimization_policy->client_negotiated_mode &&
          !session->video.cipher &&
          zero_fec_selection.percentage == 0;
        std::span<std::uint8_t> interleaved_payload;
        std::vector<platf::buffer_descriptor_t> *segmented_payload_buffers {};
        if (use_segmented_zero_fec) {
          segmented_payload_buffers = &packetizer.prepare_segmented_frame(frame_header_bytes, payload, video_packetizer::raw_packet_header_size, blocksize);
        } else {
          interleaved_payload = packetizer.prepare_interleaved_frame(frame_header_bytes, payload, video_packetizer::raw_packet_header_size, blocksize);
        }

        const auto fec_blocks_needed = frame_plan.block_count;
        const bool skip_fec_for_frame = frame_plan.exceeded_fec_block_limit;
        if (skip_fec_for_frame) {
          BOOST_LOG(warning) << "Skipping FEC for abnormally large encoded frame"sv;
        }
        BOOST_LOG(verbose) << "Generating "sv << fec_blocks_needed << " FEC blocks"sv;

        const auto pacing_bitrate_bps = stream_policy::video_pacing_bitrate_bps(
          session->config.monitor.bitrate,
          *session->config.optimization_policy,
          session->config.video_path_budget_bps
        );
        const auto ratecontrol_packets_in_1ms = std::max<std::size_t>(
          1,
          pacing_bitrate_bps / 1'000U / blocksize / 8U
        );

        // Send less than 64K in a single batch.
        // On Windows, batches above 64K seem to bypass SO_SNDBUF regardless of its size,
        // appear in "Other I/O" and begin waiting for interrupts.
        // This gives inconsistent performance so we'd rather avoid it.
        size_t send_batch_size = 64 * 1024 / blocksize;
        // Also don't exceed 64 packets, which can happen when Moonlight requests
        // unusually small packet size.
        // Generic Segmentation Offload on Linux can't do more than 64.
        send_batch_size = std::min<size_t>(64, send_batch_size);

        // Don't ignore the last ratecontrol group of the previous frame
        auto ratecontrol_frame_start = stream_policy::begin_paced_frame(
          session->video.pacing,
          std::chrono::steady_clock::now()
        );

        size_t ratecontrol_frame_packets_sent = 0;
        size_t ratecontrol_group_packets_sent = 0;

        auto pace_before_batch = [&]() {
          // Do pacing within the frame. The first batch also accounts for the
          // final pacing group of the preceding frame.
          if (ratecontrol_group_packets_sent >= ratecontrol_packets_in_1ms || ratecontrol_frame_packets_sent == 0) {
            auto due = ratecontrol_frame_start +
                       std::chrono::duration_cast<std::chrono::nanoseconds>(1ms) *
                         ratecontrol_frame_packets_sent / ratecontrol_packets_in_1ms;
            auto now = std::chrono::steady_clock::now();
            const auto packet_pacing = session->config.optimization_policy->packet_pacing;
            if (packet_pacing != stream_policy::PacketPacingMode::immediate && now < due) {
              timer->sleep_for(due - now);
            }
            ratecontrol_group_packets_sent = 0;
          }
        };

        for (std::size_t block_index = 0; block_index < fec_blocks_needed; ++block_index) {
          const auto &block = frame_plan.blocks[block_index];
          const auto packets = block.packet_count;
          const auto frame_fec = skip_fec_for_frame ?
                                   stream_policy::FrameFecSelection {0, 0} :
                                   stream_policy::select_frame_fec(
                                     *session->config.optimization_policy,
                                     recovery_critical,
                                     packets,
                                     session->config.minRequiredFecPackets
                                   );

          // RTP video timestamps use a 90 KHz clock and the frame timestamp from capture.
          bool frame_is_dupe = false;
          if (!packet->frame_timestamp) {
            packet->frame_timestamp = stream_policy::duplicate_frame_timestamp(session->video.pacing);
            frame_is_dupe = true;
          }
          using rtp_tick = std::chrono::duration<uint32_t, std::ratio<1, 90000>>;
          const uint32_t timestamp = std::chrono::round<rtp_tick>(*packet->frame_timestamp - video_epoch).count();
          auto peer_address = session->video.peer.address();
          std::size_t sent_shards {};
          std::size_t advertised_fec_percentage {};

          if (use_segmented_zero_fec) {
            if (frame_fec.percentage != 0 || segmented_payload_buffers == nullptr) {
              throw std::logic_error("segmented video path requires zero FEC");
            }

            std::size_t next_packet_to_send {};
            while (next_packet_to_send < packets) {
              const auto current_batch_size = std::min(send_batch_size, packets - next_packet_to_send);
              const auto frame_packet_offset = block.packet_offset + next_packet_to_send;
              (void) packetizer.prepare_segmented_headers(frame_packet_offset, current_batch_size, video_packetizer::raw_packet_header_size);
              for (std::size_t batch_index = 0; batch_index < current_batch_size; ++batch_index) {
                const auto packet_index = next_packet_to_send + batch_index;
                auto *header = packetizer.segmented_header(
                  frame_packet_offset + batch_index,
                  video_packetizer::raw_packet_header_size
                );
                const auto header_bytes = std::span<std::uint8_t> {header, video_packetizer::raw_packet_header_size};
                const auto fields = video_packetizer::PacketHeaderFields {
                  static_cast<std::uint32_t>(packet->frame_index()),
                  static_cast<std::uint32_t>(lowseq) + static_cast<std::uint32_t>(packet_index),
                  static_cast<std::uint16_t>(lowseq + packet_index),
                  timestamp,
                  packet_index,
                  packets,
                  0,
                  block_index,
                  fec_blocks_needed,
                  packet_index == 0,
                  packet_index + 1 == packets,
                };
                video_packetizer::serialize_data_packet_header(header_bytes, fields);
              }

              if (!packetizer.first_batch_ready()) {
                packetizer.mark_first_batch_ready();
              }
              pace_before_batch();
              auto batch_info = platf::batched_send_info_t {
                reinterpret_cast<const char *>(packetizer.segmented_header(0, video_packetizer::raw_packet_header_size)),
                video_packetizer::raw_packet_header_size,
                *segmented_payload_buffers,
                payload_blocksize,
                frame_packet_offset,
                current_batch_size,
                (uintptr_t) sock.native_handle(),
                peer_address,
                session->video.peer.port(),
                session->localAddress,
              };

              frame_send_batch_latency_logger.first_point_now();
              if (!platf::send_batch(batch_info)) {
                BOOST_LOG(verbose) << "Falling back to unbatched send"sv;
                for (std::size_t batch_index = 0; batch_index < current_batch_size; ++batch_index) {
                  const auto frame_packet_index = frame_packet_offset + batch_index;
                  auto send_info = platf::send_info_t {
                    reinterpret_cast<const char *>(packetizer.segmented_header(frame_packet_index, video_packetizer::raw_packet_header_size)),
                    video_packetizer::raw_packet_header_size,
                    packetizer.segmented_payload(frame_packet_index, payload_blocksize),
                    payload_blocksize,
                    (uintptr_t) sock.native_handle(),
                    peer_address,
                    session->video.peer.port(),
                    session->localAddress,
                  };
                  platf::send(send_info);
                }
              }
              frame_send_batch_latency_logger.second_point_now_and_log();
              ratecontrol_group_packets_sent += current_batch_size;
              ratecontrol_frame_packets_sent += current_batch_size;
              next_packet_to_send += current_batch_size;
            }
            sent_shards = packets;
          } else {
            auto current_payload = interleaved_payload.subspan(block.byte_offset, block.byte_size);
            for (std::size_t packet_index = 0; packet_index < packets; ++packet_index) {
              const auto header = std::span<std::uint8_t> {
                current_payload.data() + packet_index * blocksize,
                video_packetizer::raw_packet_header_size,
              };
              video_packetizer::prepare_data_packet_header(
                header,
                video_packetizer::PacketHeaderFields {
                  static_cast<std::uint32_t>(packet->frame_index()),
                  static_cast<std::uint32_t>(lowseq) + static_cast<std::uint32_t>(packet_index),
                  static_cast<std::uint16_t>(lowseq + packet_index),
                  timestamp,
                  packet_index,
                  packets,
                  frame_fec.percentage,
                  block_index,
                  fec_blocks_needed,
                  packet_index == 0,
                  packet_index + 1 == packets,
                }
              );
            }

            frame_fec_latency_logger.first_point_now();
            auto shards = packetizer.encode_block(
              current_payload,
              blocksize,
              frame_fec.percentage,
              frame_fec.minimum_fec_packets,
              session->video.cipher ? video_packetizer::encrypted_packet_prefix_size : 0
            );
            frame_fec_latency_logger.second_point_now_and_log();
            auto batch_info = platf::batched_send_info_t {
              shards.prefix(0),
              shards.prefix_size,
              *shards.payload_buffers,
              shards.block_size,
              0,
              0,
              (uintptr_t) sock.native_handle(),
              peer_address,
              session->video.peer.port(),
              session->localAddress,
            };

            std::size_t next_shard_to_send {};
            for (std::size_t shard_index = 0; shard_index < shards.size(); ++shard_index) {
              auto *packet_bytes = reinterpret_cast<std::uint8_t *>(shards.data(shard_index));
              video_packetizer::finalize_packet_header(
                std::span<std::uint8_t> {packet_bytes, video_packetizer::raw_packet_header_size},
                video_packetizer::PacketHeaderFields {
                  static_cast<std::uint32_t>(packet->frame_index()),
                  static_cast<std::uint32_t>(lowseq) + static_cast<std::uint32_t>(shard_index),
                  static_cast<std::uint16_t>(lowseq + shard_index),
                  timestamp,
                  shard_index,
                  shards.data_shards,
                  static_cast<int>(shards.percentage),
                  block_index,
                  fec_blocks_needed,
                  false,
                  false,
                }
              );

              if (session->video.cipher) {
                video_packetizer::encrypt_packet(
                  *session->video.cipher,
                  std::span<std::uint8_t> {packet_bytes, blocksize},
                  static_cast<std::uint32_t>(packet->frame_index()),
                  session->video.gcm_iv_counter,
                  iv,
                  std::span<std::uint8_t> {
                    reinterpret_cast<std::uint8_t *>(shards.prefix(shard_index)),
                    video_packetizer::encrypted_packet_prefix_size,
                  }
                );
              }

              if (shard_index - next_shard_to_send + 1 >= send_batch_size || shard_index + 1 == shards.size()) {
                pace_before_batch();
                const auto current_batch_size = shard_index - next_shard_to_send + 1;
                batch_info.block_offset = next_shard_to_send;
                batch_info.block_count = current_batch_size;
                frame_send_batch_latency_logger.first_point_now();
                if (!platf::send_batch(batch_info)) {
                  BOOST_LOG(verbose) << "Falling back to unbatched send"sv;
                  for (std::size_t batch_index = 0; batch_index < current_batch_size; ++batch_index) {
                    auto send_info = platf::send_info_t {
                      shards.prefix(next_shard_to_send + batch_index),
                      shards.prefix_size,
                      shards.data(next_shard_to_send + batch_index),
                      shards.block_size,
                      (uintptr_t) sock.native_handle(),
                      peer_address,
                      session->video.peer.port(),
                      session->localAddress,
                    };
                    platf::send(send_info);
                  }
                }
                frame_send_batch_latency_logger.second_point_now_and_log();
                ratecontrol_group_packets_sent += current_batch_size;
                ratecontrol_frame_packets_sent += current_batch_size;
                next_shard_to_send = shard_index + 1;
              }
            }
            sent_shards = shards.size();
            advertised_fec_percentage = shards.percentage;
          }

          stream_policy::complete_paced_frame(
            session->video.pacing,
            ratecontrol_frame_start,
            std::chrono::duration_cast<std::chrono::nanoseconds>(1ms) *
              ratecontrol_frame_packets_sent / ratecontrol_packets_in_1ms
          );
          frame_network_latency_logger.second_point_now_and_log();
          BOOST_LOG(verbose) << "Sent Frame seq ["sv << packet->frame_index() << "] pts ["sv << timestamp
                             << "] shards ["sv << sent_shards << "/"sv << advertised_fec_percentage << "%]"sv
                             << (frame_is_dupe ? " Dupe" : "")
                             << (packet->is_idr() ? " Key" : "")
                             << (packet->after_ref_frame_invalidation ? " RFI" : "");
          lowseq += sent_shards;
        }

        session->video.lowseq = lowseq;
      } catch (const std::exception &e) {
        BOOST_LOG(error) << "Broadcast video dropped frame and requested recovery: "sv << e.what();
        session->video.idr_events->raise(true);
      } catch (...) {
        BOOST_LOG(error) << "Broadcast video dropped frame after an unknown packetization failure and requested recovery"sv;
        session->video.idr_events->raise(true);
      }
    }

    shutdown_event->raise(true);
  }

  /**
   * @brief Run the broadcast audio sender thread.
   *
   * @param sock Socket used to read or write the protocol message.
   */
  void audioBroadcastThread(udp::socket &sock, legacy_audio_packet_queue_t &packets) {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    audio_packet_t audio_packet;
    fec::rs_t rs {reed_solomon_new(RTPA_DATA_SHARDS, RTPA_FEC_SHARDS)};
    crypto::aes_t iv(16);

    // For unknown reasons, the RS parity matrix computed by our RS implementation
    // doesn't match the one Nvidia uses for audio data. I'm not exactly sure why,
    // but we can simply replace it with the matrix generated by OpenFEC which
    // works correctly. This is possible because the data and FEC shard count is
    // constant and known in advance.
    const unsigned char parity[] = {0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c};
    memcpy(rs.get()->p, parity, sizeof(parity));

    audio_packet.rtp.header = 0x80;
    audio_packet.rtp.packetType = 97;
    audio_packet.rtp.ssrc = 0;

    // Audio traffic is sent on this thread
    platf::set_thread_name("stream::audioBroadcast");
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    while (auto routed_packet = packets.pop()) {
      if (shutdown_event->peek()) {
        break;
      }

      auto session = routed_packet->session.lock();
      if (!session || session->state.load(std::memory_order_acquire) != session::state_e::RUNNING) {
        continue;
      }
      auto &packet_data = routed_packet->packet.payload;

      auto sequenceNumber = session->audio.sequenceNumber;
      auto timestamp = session->audio.timestamp;

      *(std::uint32_t *) iv.data() = util::endian::big<std::uint32_t>(session->audio.avRiKeyId + sequenceNumber);

      auto &shards_p = session->audio.shards_p;

      auto bytes = encode_audio(session->config.encryptionFlagsEnabled & SS_ENC_AUDIO, packet_data, shards_p[sequenceNumber % RTPA_DATA_SHARDS], iv, session->audio.cipher);
      if (bytes < 0) {
        BOOST_LOG(error) << "Couldn't encode audio packet"sv;
        break;
      }

      BOOST_LOG(verbose) << "Audio [seq "sv << sequenceNumber << ", pts "sv << timestamp << "] ::  send..."sv;

      audio_packet.rtp.sequenceNumber = util::endian::big(sequenceNumber);
      audio_packet.rtp.timestamp = util::endian::big(timestamp);

      session->audio.sequenceNumber++;
      session->audio.timestamp += session->config.audio.packetDuration;

      auto peer_address = session->audio.peer.address();
      try {
        auto send_info = platf::send_info_t {
          (const char *) &audio_packet,
          sizeof(audio_packet),
          (const char *) shards_p[sequenceNumber % RTPA_DATA_SHARDS],
          (size_t) bytes,
          (uintptr_t) sock.native_handle(),
          peer_address,
          session->audio.peer.port(),
          session->localAddress,
        };
        platf::send(send_info);

        auto &fec_packet = session->audio.fec_packet;
        // initialize the FEC header at the beginning of the FEC block
        if (sequenceNumber % RTPA_DATA_SHARDS == 0) {
          fec_packet.fecHeader.baseSequenceNumber = util::endian::big(sequenceNumber);
          fec_packet.fecHeader.baseTimestamp = util::endian::big(timestamp);
        }

        // generate parity shards at the end of the FEC block
        if ((sequenceNumber + 1) % RTPA_DATA_SHARDS == 0) {
          reed_solomon_encode(rs.get(), shards_p.begin(), RTPA_TOTAL_SHARDS, bytes);

          for (auto x = 0; x < RTPA_FEC_SHARDS; ++x) {
            fec_packet.rtp.sequenceNumber = util::endian::big<std::uint16_t>(sequenceNumber + x + 1);
            fec_packet.fecHeader.fecShardIndex = x;

            auto send_info = platf::send_info_t {
              (const char *) &fec_packet,
              sizeof(fec_packet),
              (const char *) shards_p[RTPA_DATA_SHARDS + x],
              (size_t) bytes,
              (uintptr_t) sock.native_handle(),
              peer_address,
              session->audio.peer.port(),
              session->localAddress,
            };
            platf::send(send_info);
            BOOST_LOG(verbose) << "Audio FEC ["sv << (sequenceNumber & ~(RTPA_DATA_SHARDS - 1)) << ' ' << x << "] ::  send..."sv;
          }
        }
      } catch (const std::exception &e) {
        BOOST_LOG(error) << "Broadcast audio failed "sv << e.what();
        std::this_thread::sleep_for(100ms);
      }
    }

    shutdown_event->raise(true);
  }

  /**
   * @brief Construct the deterministic microphone GCM nonce for one datagram.
   *
   * @param prefix Four-byte session nonce prefix derived by HKDF.
   * @param sequence Monotonic packet sequence.
   * @return Four-byte prefix followed by the eight-byte big-endian sequence.
   */
  static crypto::aes_256_gcm_t::nonce_t microphone_nonce(
    const std::array<std::uint8_t, 4> &prefix,
    std::uint64_t sequence
  ) {
    crypto::aes_256_gcm_t::nonce_t nonce {};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    for (std::size_t index = 0; index < sizeof(sequence); ++index) {
      nonce[prefix.size() + index] = static_cast<std::uint8_t>(sequence >> ((sizeof(sequence) - index - 1) * 8));
    }
    return nonce;
  }

  /**
   * @brief Allocate the next nonzero driver generation for a microphone session.
   *
   * @param session Active stream session.
   * @return Generation unique across launch sessions and resets.
   */
  static std::uint64_t next_microphone_generation(session_t &session) {
    if (session.microphone.generation == 0) {
      session.microphone.generation = (static_cast<std::uint64_t>(session.launch_session_id) << 32U) | 1U;
    } else {
      ++session.microphone.generation;
    }
    return session.microphone.generation;
  }

  /**
   * @brief Authenticate and process reverse microphone datagrams for one A/V session.
   *
   * Failures remain isolated to microphone input and never stop the enclosing
   * GameStream session.
   *
   * @param session Active stream session.
   */
  static void clientMicrophoneThread(session_t *session) {
    platf::set_thread_name("session::client-microphone");

    auto finish = util::fail_guard([&]() {
      if (session->microphone.receiver) {
        session->microphone.receiver->stop();
      }
      session::release_client_microphone(session->launch_session_id);
    });

    try {
      while (!session->shutdown_event->peek() && !session->microphone.ended) {
        const auto datagram = session->microphone.datagrams->pop(5ms);
        const auto now = client_microphone::clock_t::now();
        if (!datagram) {
          session->microphone.receiver->poll(now);
          continue;
        }

        const auto packet = client_microphone::protocol::parse(datagram->bytes);
        if (!packet || packet->session_id != session->microphone.session_id ||
            !session->microphone.replay.may_accept(packet->packet_sequence)) {
          continue;
        }

        crypto::aes_t plaintext;
        const auto nonce = microphone_nonce(session->microphone.nonce_prefix, packet->packet_sequence);
        if (!session->microphone.cipher->decrypt(
              packet->ciphertext,
              packet->authenticated_header,
              nonce,
              packet->authentication_tag,
              plaintext
            )) {
          continue;
        }

        const auto hello = packet->type == client_microphone::protocol::packet_type_t::hello;
        if ((hello && (packet->packet_sequence != 0 || session->microphone.endpoints.claimed())) ||
            !session->microphone.endpoints.accept_authenticated(datagram->peer, hello)) {
          continue;
        }

        const auto ordered_control =
          packet->type == client_microphone::protocol::packet_type_t::reset ||
          packet->type == client_microphone::protocol::packet_type_t::end;
        if ((ordered_control && !session->microphone.replay.would_advance(packet->packet_sequence)) ||
            (packet->type == client_microphone::protocol::packet_type_t::audio &&
             session->microphone.reset_barrier_active &&
             packet->packet_sequence < session->microphone.reset_sequence_barrier)) {
          continue;
        }

        session->microphone.replay.commit(packet->packet_sequence);

        switch (packet->type) {
          case client_microphone::protocol::packet_type_t::hello:
            if (!session->microphone.receiver->reset(next_microphone_generation(*session), now)) {
              session->microphone.ended = true;
            }
            break;

          case client_microphone::protocol::packet_type_t::audio:
            if (session->microphone.generation == 0 || !session->microphone.receiver->active()) {
              break;
            }
            session->microphone.receiver->submit(
              {
                session->microphone.generation,
                packet->packet_sequence,
                packet->timestamp_48khz,
                (packet->flags & client_microphone::protocol::flag_silence) != 0 ?
                  client_microphone::packet_kind_e::silence :
                  client_microphone::packet_kind_e::opus,
                std::move(plaintext),
              },
              now
            );
            break;

          case client_microphone::protocol::packet_type_t::reset:
            session->microphone.reset_sequence_barrier = packet->packet_sequence;
            session->microphone.reset_barrier_active = true;
            if (session->microphone.generation != 0 &&
                !session->microphone.receiver->reset(next_microphone_generation(*session), now)) {
              session->microphone.ended = true;
            }
            break;

          case client_microphone::protocol::packet_type_t::end:
            session->microphone.receiver->stop();
            session->microphone.ended = true;
            break;
        }

        session->microphone.receiver->poll(now);
      }
    } catch (const std::exception &exception) {
      BOOST_LOG(error) << "Client microphone disabled for this session: "sv << exception.what();
    }
  }

  /**
   * @brief Route microphone UDP datagrams to sessions by their full 16-byte identifier.
   *
   * Framing is validated before lookup, while all authentication and endpoint
   * state changes remain in the owning session thread.
   *
   * @param ctx Shared broadcast context owning the UDP socket and route map.
   */
  static void clientMicrophoneRouterThread(broadcast_ctx_t &ctx) {
    platf::set_thread_name("stream::client-microphone-router");
    std::array<std::uint8_t, client_microphone::protocol::maximum_datagram_size> buffer {};

    while (ctx.microphone_bound.load(std::memory_order_acquire)) {
      udp::endpoint peer;
      boost::system::error_code error;
      const auto size = ctx.microphone_sock.receive_from(asio::buffer(buffer), peer, 0, error);
      if (error) {
        if (error == asio::error::operation_aborted || error == asio::error::bad_descriptor) {
          break;
        }
        continue;
      }

      const auto bytes = std::span<const std::uint8_t> {buffer.data(), size};
      const auto packet = client_microphone::protocol::parse(bytes);
      if (!packet) {
        continue;
      }

      std::shared_ptr<session_t> session;
      {
        auto routes = ctx.microphone_routes.lock();
        const auto route = ctx.microphone_routes->find(client_microphone_route_key(packet->session_id));
        if (route == ctx.microphone_routes->end()) {
          continue;
        }
        session = route->second.lock();
        if (!session) {
          ctx.microphone_routes->erase(route);
          continue;
        }
      }

      if (session->microphone.datagrams) {
        session->microphone.datagrams->raise(
          microphone_datagram_t {{bytes.begin(), bytes.end()}, std::move(peer)}
        );
      }
    }
  }

  /**
   * @brief Register one session-ID route in the shared microphone UDP router.
   *
   * @param ctx Shared broadcast context.
   * @param session Session retained weakly by the route.
   */
  static void register_client_microphone_route(
    broadcast_ctx_t &ctx,
    const std::shared_ptr<session_t> &session
  ) {
    auto routes = ctx.microphone_routes.lock();
    ctx.microphone_routes->insert_or_assign(
      client_microphone_route_key(session->microphone.session_id),
      std::weak_ptr<session_t> {session}
    );
  }

  /**
   * @brief Remove one session-ID route before session destruction.
   *
   * @param ctx Shared broadcast context.
   * @param session_id Exact microphone route identifier.
   */
  static void unregister_client_microphone_route(
    broadcast_ctx_t &ctx,
    const std::array<std::uint8_t, 16> &session_id
  ) {
    auto routes = ctx.microphone_routes.lock();
    ctx.microphone_routes->erase(client_microphone_route_key(session_id));
  }

  /**
   * @brief Bind the GameStream UDP and control sockets used for a streaming session.
   */
  int start_broadcast(broadcast_ctx_t &ctx) {
    if (!ctx.video_egress.reset()) {
      BOOST_LOG(error) << "Cannot restart video egress while a session is still registered"sv;
      return -1;
    }

    auto address_family = net::af_from_enum_string(config::sunshine.address_family);
    auto protocol = address_family == net::IPV4 ? udp::v4() : udp::v6();
    auto control_port = net::map_port(CONTROL_PORT);
    auto video_port = net::map_port(VIDEO_STREAM_PORT);
    auto audio_port = net::map_port(AUDIO_STREAM_PORT);
    auto microphone_port = net::map_port(MICROPHONE_STREAM_PORT);

    if (ctx.control_server.bind(address_family, control_port)) {
      BOOST_LOG(error) << "Couldn't bind Control server to port ["sv << control_port << "], likely another process already bound to the port"sv;

      return -1;
    }

    boost::system::error_code ec;
    ctx.video_sock.open(protocol, ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't open socket for Video server: "sv << ec.message();

      return -1;
    }

    // Set video socket send buffer size (SO_SENDBUF) to 1MB
    try {
      ctx.video_sock.set_option(boost::asio::socket_base::send_buffer_size(1024 * 1024));
    } catch (...) {
      BOOST_LOG(error) << "Failed to set video socket send buffer size (SO_SENDBUF)";
    }

    auto bind_addr_str = net::get_bind_address(address_family);
    const auto bind_addr = boost::asio::ip::make_address(bind_addr_str, ec);
    if (ec) {
      BOOST_LOG(fatal) << "Invalid bind address: "sv << bind_addr_str << " - " << ec.message();
      return -1;
    }

    ctx.video_sock.bind(udp::endpoint(bind_addr, video_port), ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't bind Video server to port ["sv << video_port << "]: "sv << ec.message();

      return -1;
    }

    ctx.audio_sock.open(protocol, ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't open socket for Audio server: "sv << ec.message();

      return -1;
    }

    ctx.audio_sock.bind(udp::endpoint(bind_addr, audio_port), ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't bind Audio server to port ["sv << audio_port << "]: "sv << ec.message();

      return -1;
    }

    if (config::audio.client_microphone && client_microphone_available()) {
      ctx.microphone_sock.open(protocol, ec);
      if (!ec) {
        ctx.microphone_sock.bind(udp::endpoint(bind_addr, microphone_port), ec);
      }

      if (ec) {
        BOOST_LOG(error) << "Client microphone unavailable because UDP port ["sv << microphone_port
                         << "] could not be bound: "sv << ec.message();
        boost::system::error_code close_error;
        ctx.microphone_sock.close(close_error);
      } else {
        ctx.microphone_bound.store(true, std::memory_order_release);
        ctx.microphone_thread = std::jthread {clientMicrophoneRouterThread, std::ref(ctx)};
      }
    }

    ctx.message_queue_queue = std::make_shared<message_queue_queue_t::element_type>(30);

    ctx.video_thread = std::jthread {videoBroadcastThread, std::ref(ctx.video_sock), std::ref(ctx.video_egress)};
    ctx.audio_thread = std::jthread {audioBroadcastThread, std::ref(ctx.audio_sock), std::ref(*ctx.audio_packets)};
    ctx.control_thread = std::jthread {controlBroadcastThread, &ctx.control_server};

    ctx.recv_thread = std::jthread {recvThread, std::ref(ctx)};

    return 0;
  }

  /**
   * @brief Stop broadcast processing.
   */
  void end_broadcast(broadcast_ctx_t &ctx) {
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    broadcast_shutdown_event->raise(true);

    // Minimize delay stopping video/audio threads
    ctx.video_egress.stop();
    ctx.audio_packets->close();

    ctx.message_queue_queue->stop();
    ctx.io_context.stop();

    ctx.video_sock.close();
    ctx.audio_sock.close();
    if (ctx.microphone_bound.exchange(false, std::memory_order_acq_rel)) {
      boost::system::error_code error;
      ctx.microphone_sock.close(error);
    }

    BOOST_LOG(debug) << "Waiting for main listening thread to end..."sv;
    ctx.recv_thread.join();
    BOOST_LOG(debug) << "Waiting for main video thread to end..."sv;
    ctx.video_thread.join();
    BOOST_LOG(debug) << "Waiting for main audio thread to end..."sv;
    ctx.audio_thread.join();
    BOOST_LOG(debug) << "Waiting for main control thread to end..."sv;
    ctx.control_thread.join();
    if (ctx.microphone_thread.joinable()) {
      BOOST_LOG(debug) << "Waiting for client microphone router thread to end..."sv;
      ctx.microphone_thread.join();
    }
    BOOST_LOG(debug) << "All broadcasting threads ended"sv;

    broadcast_shutdown_event->reset();
  }

  /**
   * @brief Receive ping data.
   *
   * @param session Active streaming or pairing session for the request.
   * @param ref Reference frame metadata used by the encoder.
   * @param type Protocol, message, or resource type selector.
   * @param expected_payload Expected payload.
   * @param peer Remote endpoint associated with the socket.
   * @param timeout Maximum time to wait for the operation.
   * @return Network operation status.
   */
  int recv_ping(session_t *session, decltype(broadcast)::ptr_t ref, socket_e type, std::string_view expected_payload, udp::endpoint &peer, std::chrono::milliseconds timeout) {
    auto messages = std::make_shared<message_queue_t::element_type>(30);
    av_session_id_t session_id = std::string {expected_payload};

    // Only allow matches on the peer address for legacy clients
    if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1)) {
      ref->message_queue_queue->raise(type, peer.address(), messages);
    }
    ref->message_queue_queue->raise(type, session_id, messages);

    auto fg = util::fail_guard([&]() {
      messages->stop();

      // remove message queue from session
      if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1)) {
        ref->message_queue_queue->raise(type, peer.address(), nullptr);
      }
      ref->message_queue_queue->raise(type, session_id, nullptr);
    });

    auto start_time = std::chrono::steady_clock::now();
    auto current_time = start_time;

    while (current_time - start_time < config::stream.ping_timeout) {
      auto delta_time = current_time - start_time;

      auto msg_opt = messages->pop(config::stream.ping_timeout - delta_time);
      if (!msg_opt) {
        break;
      }

      TUPLE_2D_REF(recv_peer, msg, *msg_opt);
      if (msg.find(expected_payload) != std::string::npos) {
        // Match the new PING payload format
        BOOST_LOG(debug) << "Received ping [v2] from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
      } else if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1) && msg == "PING"sv) {
        // Match the legacy fixed PING payload only if the new type is not supported
        BOOST_LOG(debug) << "Received ping [v1] from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
      } else {
        BOOST_LOG(debug) << "Received non-ping from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
        current_time = std::chrono::steady_clock::now();
        continue;
      }

      // Update connection details.
      peer = recv_peer;
      return 0;
    }

    BOOST_LOG(error) << "Initial Ping Timeout"sv;
    return -1;
  }

  /**
   * @brief Run the session video capture and encode thread.
   *
   * @param session Active streaming or pairing session for the request.
   */
  void videoThread(session_t *session) {
    platf::set_thread_name("session::video");
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    auto ref = broadcast.ref();
    auto ping_error = recv_ping(session, ref, socket_e::video, session->video.ping_payload, session->video.peer, config::stream.ping_timeout);
    if (ping_error < 0) {
      return;
    }

    // Enable local prioritization and QoS tagging on video traffic if requested by the client
    auto address = session->video.peer.address();
    session->video.qos = platf::enable_socket_qos(ref->video_sock.native_handle(), address, session->video.peer.port(), platf::qos_data_type_e::video, session->config.videoQosType != 0);

    const bool explicit_latency =
      session->config.optimization_policy->mode == stream_policy::StreamOptimizationMode::latency &&
      session->config.optimization_policy->client_negotiated_mode;
    const auto egress_behavior = explicit_latency ?
                                   video::egress_queue_t::behavior_e::latency :
                                   video::egress_queue_t::behavior_e::fifo;
    const video::egress_queue_t::registration_policy_t egress_policy {
      explicit_latency ? 1U : ref->video_egress.capacity_per_session(),
      explicit_latency ? video::capture_frame_interval(session->config.monitor) : std::chrono::nanoseconds::zero(),
    };
    const auto registered = ref->video_egress.register_session(
      session,
      egress_behavior,
      egress_policy,
      [session](const video::egress_queue_t::recovery_request_t &request) {
        BOOST_LOG(warning) << "Video egress pressure dropped "sv << request.dropped_frames
                           << " frame(s) for session "sv << session->launch_session_id
                           << ", depth="sv << request.depth_after_drop
                           << ", requesting RFI/IDR for encoded frames "sv
                           << request.first_frame << '-' << request.last_frame;
        session->video.invalidate_ref_frames_events->raise(
          std::make_pair(request.first_frame, request.last_frame)
        );
      }
    );
    if (!registered) {
      BOOST_LOG(error) << "Could not register session with the video egress scheduler"sv;
      return;
    }
    auto unregister_egress = util::fail_guard([&]() {
      const auto telemetry = ref->video_egress.unregister_session(session);
      if (!telemetry) {
        BOOST_LOG(error) << "Video egress session registration disappeared before capture ended"sv;
        return;
      }

      BOOST_LOG(info) << "Video egress session "sv << session->launch_session_id
                      << " telemetry: queued="sv << telemetry->queued_frames
                      << " dequeued="sv << telemetry->dequeued_frames
                      << " dropped="sv << telemetry->dropped_frames
                      << " overflow="sv << telemetry->overflow_events
                      << " age_expirations="sv << telemetry->age_expiration_events
                      << " expired="sv << telemetry->expired_frames
                      << " gated="sv << telemetry->gated_drops
                      << " recovery_requests="sv << telemetry->recovery_requests
                      << " peak_depth="sv << telemetry->peak_depth
                      << " capacity="sv << telemetry->configured_capacity
                      << " deadline_ms="sv
                      << std::chrono::duration<double, std::milli> {telemetry->configured_max_queue_age}.count()
                      << " max_age_ms="sv
                      << std::chrono::duration<double, std::milli> {telemetry->max_queue_age}.count();
    });

    const stream_policy::ScopedPolicyBinding policy_binding {*session->config.optimization_policy};
    BOOST_LOG(debug) << "Start capturing Video"sv;
    video::capture(session->mail, session->config.monitor, session, ref->video_egress);
  }

  /**
   * @brief Run the session audio capture and encode thread.
   *
   * @param session Active streaming or pairing session for the request.
   */
  void audioThread(session_t *session) {
    platf::set_thread_name("session::audio");
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    auto ref = broadcast.ref();
    auto error = recv_ping(session, ref, socket_e::audio, session->audio.ping_payload, session->audio.peer, config::stream.ping_timeout);
    if (error < 0) {
      return;
    }

    // Enable local prioritization and QoS tagging on audio traffic if requested by the client
    auto address = session->audio.peer.address();
    session->audio.qos = platf::enable_socket_qos(ref->audio_sock.native_handle(), address, session->audio.peer.port(), platf::qos_data_type_e::audio, session->config.audioQosType != 0);

    BOOST_LOG(debug) << "Start capturing Audio"sv;
    audio::capture(session->mail, session->config.audio, session->audio.destination);
  }

  namespace session {
    std::atomic_uint running_sessions;  ///< Running sessions.
    std::atomic_uint32_t client_microphone_owner;  ///< Launch session holding the single virtual microphone writer slot.

    bool claim_client_microphone(std::uint32_t launch_session_id) {
      auto expected = std::uint32_t {0};
      return client_microphone_owner.compare_exchange_strong(expected, launch_session_id) || expected == launch_session_id;
    }

    void release_client_microphone(std::uint32_t launch_session_id) {
      auto expected = launch_session_id;
      client_microphone_owner.compare_exchange_strong(expected, 0);
    }

    /**
     * @brief Platform handle returned from stream setup.
     */
    state_e state(session_t &session) {
      return session.state.load(std::memory_order_relaxed);
    }

    /**
     * @brief Return the paired client certificate for this session.
     */
    const std::string &client_cert(session_t &session) {
      return session.client_cert;
    }

    /**
     * @brief Stop the active streaming session and prevent new packets from being queued.
     */
    void stop(session_t &session) {
      while_starting_do_nothing(session.state);
      auto expected = state_e::RUNNING;
      auto already_stopping = !session.state.compare_exchange_strong(expected, state_e::STOPPING);
      if (already_stopping) {
        return;
      }

      if (session.audio.destination) {
        session.audio.destination->close();
      }
      input::begin_close(session.input);
      session.shutdown_event->raise(true);
    }

    /**
     * @brief Wait for worker threads owned by the session to exit.
     */
    void join(session_t &session) {
      // Current Nvidia drivers have a bug where NVENC can deadlock the encoder thread with hardware-accelerated
      // GPU scheduling enabled. If this happens, we will terminate ourselves and the service can restart.
      // The alternative is that Sunshine can never start another session until it's manually restarted.
      auto task = []() {
        BOOST_LOG(fatal) << "Hang detected! Session failed to terminate in 10 seconds."sv;
        logging::log_flush();
        lifetime::debug_trap();
      };
      auto force_kill = task_pool.pushDelayed(task, 10s).task_id;
      auto fg = util::fail_guard([&force_kill]() {
        // Cancel the kill task if we manage to return from this function
        task_pool.cancel(force_kill);
      });

      if (session.config.client_microphone) {
        if (session.broadcast_ref) {
          unregister_client_microphone_route(*session.broadcast_ref.get(), session.microphone.session_id);
        }
        if (session.microphone.datagrams) {
          session.microphone.datagrams->stop();
        }
        if (session.microphoneThread.joinable()) {
          BOOST_LOG(debug) << "Waiting for client microphone to end..."sv;
          session.microphoneThread.join();
        }
        if (session.microphone.receiver) {
          session.microphone.receiver->stop();
        }
        release_client_microphone(session.launch_session_id);
      }

      BOOST_LOG(debug) << "Waiting for video to end..."sv;
      session.videoThread.join();
      BOOST_LOG(debug) << "Waiting for audio to end..."sv;
      session.audioThread.join();
      session.audio.destination.reset();
      input::begin_close(session.input);
      BOOST_LOG(debug) << "Waiting for control to end..."sv;
      session.controlEnd.view();
      // Reset input on session stop to avoid stuck repeated keys
      BOOST_LOG(debug) << "Resetting Input..."sv;
      input::reset(session.input);

#ifdef _WIN32
      if (!cleanup_virtual_display(session.config)) {
        BOOST_LOG(error) << "Failed to restore Lumen virtual-display topology for session "sv << session.launch_session_id;
      }
#endif

      // If this is the last session, invoke the platform callbacks
      if (--running_sessions == 0) {
        bool revert_display_config {config::video.dd.config_revert_on_disconnect};
        if (proc::proc.running()) {
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
          system_tray::update_tray_pausing(proc::proc.get_last_run_app_name());
#endif
        } else {
          // We have no app running and also no clients anymore.
          revert_display_config = true;
        }

        if (revert_display_config) {
          display_device::revert_configuration();
        }

        platf::streaming_will_stop();
      }

      BOOST_LOG(debug) << "Session ended"sv;
    }

    /**
     * @brief Start the audio, video, and control workers for a streaming session.
     */
    int start(const std::shared_ptr<session_t> &session_ptr, const std::string &addr_string) {
      auto &session = *session_ptr;
      session.input = input::alloc(session.mail);

      session.broadcast_ref = broadcast.ref();
      if (!session.broadcast_ref) {
        return -1;
      }
      session.audio.destination = std::make_shared<legacy_audio_packet_destination>(
        session_ptr,
        session.broadcast_ref->audio_packets
      );

      if (session.config.client_microphone &&
          (!session.broadcast_ref->microphone_bound.load(std::memory_order_acquire) ||
           !session.microphone.cipher || !session.microphone.receiver || !session.microphone.datagrams)) {
        BOOST_LOG(error) << "Client microphone negotiation failed because its UDP listener or driver is unavailable"sv;
        release_client_microphone(session.launch_session_id);
        return -1;
      }

      session.control.expected_peer_address = addr_string;
      BOOST_LOG(debug) << "Expecting incoming session connections from "sv << addr_string;

      // Insert this session into the session list
      {
        auto lg = session.broadcast_ref->control_server._sessions.lock();
        session.broadcast_ref->control_server._sessions->push_back(&session);
      }

      auto addr = boost::asio::ip::make_address(addr_string);
      session.video.peer.address(addr);
      session.video.peer.port(0);

      session.audio.peer.address(addr);
      session.audio.peer.port(0);

      session.pingTimeout = std::chrono::steady_clock::now() + config::stream.ping_timeout;

      if (session.config.client_microphone) {
        register_client_microphone_route(*session.broadcast_ref.get(), session_ptr);
        session.microphoneThread = std::jthread {clientMicrophoneThread, &session};
      }

      session.audioThread = std::jthread {audioThread, &session};
      session.videoThread = std::jthread {videoThread, &session};

      session.state.store(state_e::RUNNING, std::memory_order_relaxed);

      // If this is the first session, invoke the platform callbacks
      if (++running_sessions == 1) {
        platf::streaming_will_start();
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
        system_tray::update_tray_playing(proc::proc.get_last_run_app_name());
#endif
      }

      return 0;
    }

    /**
     * @brief Allocate and initialize platform input state for a stream.
     */
    std::shared_ptr<session_t> alloc(config_t &config, rtsp_stream::launch_session_t &launch_session) {
      if (!config.optimization_policy) {
        BOOST_LOG(error) << "Cannot allocate stream session without an explicitly resolved optimization policy"sv;
        return nullptr;
      }

      auto session = std::make_shared<session_t>();

      auto mail = std::make_shared<safe::mail_raw_t>();

      session->shutdown_event = mail->event<bool>(mail::shutdown);
      session->launch_session_id = launch_session.id;
      session->client_cert = launch_session.client_cert;

      session->config = config;
      session->config.monitor.optimization_policy = session->config.optimization_policy;
      session->config.monitor.client_protocol = session->config.client_protocol;

      if (session->config.client_microphone) {
        session->microphone.session_id = launch_session.client_microphone_session_id;
        session->microphone.salt = launch_session.client_microphone_salt;
        constexpr auto key_info = "lumen/client-microphone/client-to-host/v1"sv;
        constexpr auto derived_size = crypto::aes_256_gcm_t::key_size + 4;
        const auto derived = crypto::hkdf_sha256(
          launch_session.gcm_key,
          session->microphone.salt,
          key_info,
          derived_size
        );

        if (!derived) {
          BOOST_LOG(error) << "Unable to derive client microphone session key"sv;
          session->config.client_microphone = false;
        } else {
          crypto::aes_256_gcm_t::key_t key {};
          std::copy_n(derived->begin(), key.size(), key.begin());
          std::copy_n(derived->begin() + key.size(), session->microphone.nonce_prefix.size(), session->microphone.nonce_prefix.begin());
          session->microphone.cipher.emplace(key);
          session->microphone.datagrams = std::make_shared<safe::queue_t<microphone_datagram_t>>(64);

#ifdef _WIN32
          try {
            session->microphone.sink = platf::win_audio::make_virtual_microphone();
            session->microphone.receiver = std::make_unique<client_microphone::receiver_t>(
              std::make_unique<client_microphone::opus_decoder_t>(),
              *session->microphone.sink
            );
          } catch (const std::exception &exception) {
            BOOST_LOG(error) << "Unable to initialize client microphone: "sv << exception.what();
            session->microphone.receiver.reset();
            session->microphone.sink.reset();
            session->config.client_microphone = false;
          }
#else
          session->config.client_microphone = false;
#endif
        }
      }
      if (!session->config.client_microphone) {
        release_client_microphone(session->launch_session_id);
      }

      session->control.connect_data = launch_session.control_connect_data;
      session->control.feedback_queue = mail->queue<platf::gamepad_feedback_msg_t>(mail::gamepad_feedback);
      session->control.hdr_queue = mail->event<video::hdr_info_t>(mail::hdr);
      session->control.legacy_input_enc_iv = launch_session.iv;
      session->control.cipher = crypto::cipher::gcm_t {
        launch_session.gcm_key,
        false
      };

      session->video.idr_events = mail->event<bool>(mail::idr);
      session->video.invalidate_ref_frames_events = mail->event<std::pair<int64_t, int64_t>>(mail::invalidate_ref_frames);
      session->video.lowseq = 0;
      session->video.pacing = stream_policy::initialize_pacing(std::chrono::steady_clock::now());
      session->video.ping_payload = launch_session.av_ping_payload;
      if (config.encryptionFlagsEnabled & SS_ENC_VIDEO) {
        BOOST_LOG(info) << "Video encryption enabled"sv;
        session->video.cipher = crypto::cipher::gcm_t {
          launch_session.gcm_key,
          false
        };
        session->video.gcm_iv_counter = 0;
      }

      constexpr auto max_block_size = crypto::cipher::round_to_pkcs7_padded(2048);

      util::buffer_t<char> shards {RTPA_TOTAL_SHARDS * max_block_size};
      util::buffer_t<uint8_t *> shards_p {RTPA_TOTAL_SHARDS};

      for (auto x = 0; x < RTPA_TOTAL_SHARDS; ++x) {
        shards_p[x] = (uint8_t *) &shards[x * max_block_size];
      }

      // Audio FEC spans multiple audio packets,
      // therefore its session specific
      session->audio.shards = std::move(shards);
      session->audio.shards_p = std::move(shards_p);

      session->audio.fec_packet.rtp.header = 0x80;
      session->audio.fec_packet.rtp.packetType = 127;
      session->audio.fec_packet.rtp.timestamp = 0;
      session->audio.fec_packet.rtp.ssrc = 0;

      session->audio.fec_packet.fecHeader.payloadType = 97;
      session->audio.fec_packet.fecHeader.ssrc = 0;

      session->audio.cipher = crypto::cipher::cbc_t {
        launch_session.gcm_key,
        true
      };

      session->audio.ping_payload = launch_session.av_ping_payload;
      session->audio.avRiKeyId = util::endian::big(*(std::uint32_t *) launch_session.iv.data());
      session->audio.sequenceNumber = 0;
      session->audio.timestamp = 0;

      session->control.peer = nullptr;
      session->state.store(state_e::STOPPED, std::memory_order_relaxed);

      session->mail = std::move(mail);

      return session;
    }

#ifdef SUNSHINE_TESTS
    video::config_t video_config_for_test(const std::shared_ptr<session_t> &session) {
      return session ? session->config.monitor : video::config_t {};
    }
#endif
  }  // namespace session

#if defined(LUMEN_EXPERIMENTAL_MSQUIC) || defined(SUNSHINE_TESTS)
  namespace {
    namespace v3_media = lumen::protocol_v3::media;
    namespace v3_runtime = lumen::protocol_v3::runtime;

    template<class Integer>
    Integer v3_read_be(const std::span<const std::uint8_t> bytes, const std::size_t offset) {
      Integer value {};
      for (std::size_t index = 0; index < sizeof(Integer); ++index) {
        value = static_cast<Integer>((value << 8U) | bytes[offset + index]);
      }
      return value;
    }

    template<class Packet>
    std::vector<std::uint8_t> v3_packet_bytes(const Packet &packet) {
      const auto *begin = reinterpret_cast<const std::uint8_t *>(&packet);
      return {begin, begin + sizeof(Packet)};
    }

    std::uint64_t v3_microseconds(const std::chrono::steady_clock::time_point value) {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                          value.time_since_epoch()
      )
                                          .count());
    }

    void v3_netfloat(const float value, std::uint8_t (&output)[4]) {
      static_assert(sizeof(value) == sizeof(output));
      std::memcpy(output, &value, sizeof(value));
    }

    bool v3_feedback_is_current(
      const platf::gamepad_feedback_msg_t &message,
      const std::uint32_t input_generation,
      const std::uint32_t controller_generation
    ) noexcept {
      return message.identity.input_generation != 0 &&
             message.identity.controller_generation != 0 &&
             message.identity.input_generation == input_generation &&
             message.identity.controller_generation == controller_generation;
    }

    void configure_v3_audio(
      audio::config_t &output,
      const v3_media::NegotiatedMediaConfig &selection
    ) {
      output.packetDuration = static_cast<int>(
        selection.audio.frame_samples * 1'000U / selection.audio.sample_rate
      );
      output.channels = selection.audio.channels;
      output.mask = selection.audio.channels == 2 ? 0x3 :
                    selection.audio.channels == 6 ? 0x3f :
                                                    0x63f;
      output.bitrate = static_cast<int>(selection.audio.bitrate_bps);
      output.flags.reset();
      output.flags[audio::config_t::HOST_AUDIO] = selection.host_audio;
      output.flags[audio::config_t::CONTINUOUS_AUDIO] = true;
      output.flags[audio::config_t::CUSTOM_SURROUND_PARAMS] = true;
      output.customStreamParams.channelCount = selection.audio.channels;
      output.customStreamParams.streams = selection.audio.streams;
      output.customStreamParams.coupledStreams = selection.audio.coupled_streams;
      std::ranges::copy(selection.audio.mapping, output.customStreamParams.mapping);
    }

    /**
     * @brief Per-v3-session adapter owning its bounded encoded-audio queue.
     */
    class v3_audio_packet_destination final: public audio::AudioPacketDestination {
    public:
      [[nodiscard]] enqueue_result_e enqueue(audio::packet_t packet) override {
        return packets_.enqueue(std::move(packet));
      }

      void close() noexcept override {
        packets_.close();
      }

      [[nodiscard]] std::optional<audio::packet_t> pop() {
        return packets_.pop();
      }

    private:
      audio_packet_queue_t<audio::packet_t> packets_;
    };

    /**
     * @brief Submit one encoded packet through the shared production v3 audio drain.
     * @param pipeline Bound per-session media pipeline.
     * @param packet Encoded packet popped from the private v3 destination.
     * @param capture_time_microseconds Exact capture timestamp for the wire record.
     * @return SessionPipeline publication result.
     */
    v3_media::PublishResult publish_v3_audio_packet(
      v3_media::SessionPipeline &pipeline,
      const audio::packet_t &packet,
      const std::uint64_t capture_time_microseconds
    ) {
      return pipeline.submit_audio({
        .capture_time_microseconds = capture_time_microseconds,
        .first_sample_position = packet.sample_position,
        .opus = {std::begin(packet.payload), packet.payload.size()},
        .discontinuity = packet.discontinuity,
      });
    }

    class native_v3_session_resources final:
        public v3_runtime::SessionResources,
        private v3_media::InputSink,
        private v3_media::MicrophoneSink,
        private v3_media::VideoFeedbackSink {
    public:
      native_v3_session_resources(
        v3_media::NegotiatedMediaConfig selection,
        const std::uint64_t connection_id,
        v3_media::TransportSink &transport,
        std::function<void()> terminal_failure
      ):
          selection_ {std::move(selection)},
          session_owner_id_ {connection_id},
          terminal_failure_ {std::move(terminal_failure)},
          mail_ {std::make_shared<safe::mail_raw_t>()},
          input_ {input::alloc(mail_)},
          audio_destination_ {std::make_shared<v3_audio_packet_destination>()},
          feedback_packets_ {mail_->queue<platf::gamepad_feedback_msg_t>(mail::gamepad_feedback)},
          video_egress_ {selection_.profile == lumen::protocol_v3::quic_server::Profile::latency ? 1U : 2U},
          transport_ {transport},
          current_input_generation_ {selection_.input_generation} {
  #ifdef _WIN32
        auto virtual_display_cleanup = util::fail_guard([this]() noexcept {
          if (!cleanup_virtual_display(stream_config_)) {
            BOOST_LOG(error) << "Protocol-v3 constructor unwind could not restore Lumen virtual-display topology"sv;
          }
        });
  #endif
        if (!terminal_failure_ || !input_) {
          throw std::runtime_error {"protocol-v3 native resource allocation"};
        }
        if (selection_.fidelity == 3 &&
            !video::current_nvenc_lossless_capability(selection_.codec_id - 1)) {
          throw std::runtime_error {"protocol-v3 NVENC lossless proof unavailable"};
        }
        if (lumen::protocol_v3::start_mode::admit(lumen::protocol_v3::start_mode::Mode {
              selection_.width,
              selection_.height,
              selection_.refresh_numerator,
              selection_.refresh_denominator,
              selection_.codec_id,
              selection_.bit_depth,
              selection_.chroma_layout,
              selection_.transfer,
              selection_.codec_flags,
              selection_.fidelity,
            }) != lumen::protocol_v3::start_mode::AdmissionError::none) {
          throw std::runtime_error {"protocol-v3 canonical mode admission rejected resources"};
        }
        const auto behavior = selection_.profile == lumen::protocol_v3::quic_server::Profile::latency ?
                                video::egress_queue_t::behavior_e::latency :
                                video::egress_queue_t::behavior_e::fifo;
        const auto latency_deadline = std::chrono::nanoseconds {
          static_cast<std::int64_t>(selection_.refresh_denominator) * 1'000'000'000LL /
          selection_.refresh_numerator
        };
        const video::egress_queue_t::registration_policy_t egress_policy {
          behavior == video::egress_queue_t::behavior_e::latency ? 1U : video_egress_.capacity_per_session(),
          behavior == video::egress_queue_t::behavior_e::latency ? latency_deadline : std::chrono::nanoseconds::zero(),
        };
        if (!video_egress_.register_session(this, behavior, egress_policy, [this](const auto &) {
              mail_->event<bool>(mail::idr)->raise(true);
            })) {
          throw std::runtime_error {"protocol-v3 video egress registration"};
        }
        configure_stream();
        auto &input_sink = static_cast<v3_media::InputSink &>(*this);
        auto &microphone_sink = static_cast<v3_media::MicrophoneSink &>(*this);
        auto &feedback_sink = static_cast<v3_media::VideoFeedbackSink &>(*this);
        pipeline_ = std::make_unique<v3_media::SessionPipeline>(
          selection_,
          transport_,
          input_sink,
          microphone_sink,
          feedback_sink
        );
        if (!pipeline_->bind_connection(connection_id)) {
          throw std::runtime_error {"protocol-v3 native transport binding"};
        }
        const stream_policy::ScopedPolicyBinding binding {*stream_config_.optimization_policy};
        auto codec_initialization = video::codec_initialization(stream_config_.monitor);
        if (!codec_initialization || codec_initialization->empty()) {
          throw std::runtime_error {"protocol-v3 codec initialization unavailable"};
        }
        codec_initialization_ = std::move(*codec_initialization);
  #ifdef _WIN32
        virtual_display_cleanup.disable();
  #endif
      }

      ~native_v3_session_resources() override {
        stop();
      }

      const v3_media::NegotiatedMediaConfig &effective_media_config() const noexcept override {
        return selection_;
      }

      std::span<const std::uint8_t> video_codec_initialization() const noexcept override {
        return codec_initialization_;
      }

      bool reset_input(
        const std::span<const std::uint8_t> state_block,
        const std::uint32_t next_generation
      ) override {
        if (next_generation == 0 || !validate_state(state_block)) {
          return false;
        }
        revoke_input_authority();
        pending_input_generation_.store(next_generation, std::memory_order_release);
        input::reset(input_);
        input_ = input::alloc(mail_);
        if (!input_) {
          pending_input_generation_.store(0, std::memory_order_release);
          report_terminal_failure_async();
          return false;
        }
        input_causality_.reset();
        prior_input_initialized_ = false;
        prior_controller_mask_ = 0;
        arrived_controller_mask_ = 0;
        controller_states_.fill(controller_state_t {});
        for (auto &generation : controller_generation_counters_) generation.store(0);
        touch_points_.clear();
        struct reset_completion_t {
          enum class state_e { pending, completed, timed_out };
          std::mutex mutex;
          std::promise<bool> result;
          state_e state {state_e::pending};
        };
        auto completion = std::make_shared<reset_completion_t>();
        auto applied_result = completion->result.get_future();
        const auto submitted = input::passthrough_state(
          input_,
          [this, state = std::vector<std::uint8_t> {state_block.begin(), state_block.end()}](
            const input::ordered_injector_t &injector
          ) {
            return apply_state(state, injector);
          },
          false,
          [this, next_generation, completion](const bool operation_success) {
            bool success = operation_success;
            {
              std::lock_guard lock {completion->mutex};
              if (completion->state == reset_completion_t::state_e::timed_out) {
                success = false;
              }
              if (success) {
                current_input_generation_.store(next_generation, std::memory_order_release);
                input_authority_active_.store(true, std::memory_order_release);
                pending_input_generation_.store(0, std::memory_order_release);
                input_authority_changed_.notify_all();
              } else {
                revoke_input_authority();
              }
              try {
                completion->result.set_value(success);
              } catch (...) {
              }
              if (completion->state != reset_completion_t::state_e::timed_out) {
                completion->state = reset_completion_t::state_e::completed;
              }
            }
            if (!success) {
              report_terminal_failure();
            }
          }
        );
        if (!submitted) {
          revoke_input_authority();
          report_terminal_failure_async();
          return false;
        }
        if (applied_result.wait_for(250ms) != std::future_status::ready) {
          bool timed_out = false;
          {
            std::lock_guard lock {completion->mutex};
            if (completion->state == reset_completion_t::state_e::pending) {
              completion->state = reset_completion_t::state_e::timed_out;
              timed_out = true;
            }
          }
          if (!timed_out) {
            return applied_result.get();
          }
          revoke_input_authority();
          report_terminal_failure_async();
          return false;
        }
        return applied_result.get();
      }

      bool apply_text(const lumen::protocol_v3::control_session::cbor::Value::Map &fields) override {
        const auto text = std::ranges::find_if(fields, [](const auto &entry) {
          return std::holds_alternative<std::string>(entry.second.storage);
        });
        if (text == fields.end()) {
          return false;
        }
        const auto &value = std::get<std::string>(text->second.storage);
        for (std::size_t offset = 0; offset < value.size();) {
          NV_UNICODE_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(UTF8_TEXT_EVENT_MAGIC);
          const auto count = std::min<std::size_t>(sizeof(packet.text), value.size() - offset);
          std::copy_n(value.data() + static_cast<std::ptrdiff_t>(offset), count, packet.text);
          if (!inject(packet)) {
            return false;
          }
          offset += count;
        }
        return true;
      }

      v3_media::ReceiveResult datagram(
        const lumen::protocol_v3::quic_server::DatagramRecord &record
      ) override {
        return pipeline_->receive(record);
      }

      bool start_media() override {
        std::call_once(start_once_, [this] {
          try {
            start_microphone();
            video_sender_ = std::jthread {[this] {
              consume_video();
            }};
            audio_sender_ = std::jthread {[this] {
              consume_audio();
            }};
            feedback_sender_ = std::jthread {[this] {
              consume_controller_feedback();
            }};
            video_capture_ = std::jthread {[this] {
              try {
                const stream_policy::ScopedPolicyBinding binding {*stream_config_.optimization_policy};
                video::capture(mail_, stream_config_.monitor, this, video_egress_);
              } catch (...) {
              }
              report_terminal_failure();
            }};
            audio_capture_ = std::jthread {[this] {
              try {
                audio::capture(mail_, stream_config_.audio, audio_destination_);
              } catch (...) {
              }
              report_terminal_failure();
            }};
            media_started_ = true;
          } catch (...) {
            explicit_stop_.store(true, std::memory_order_release);
            media_started_ = false;
          }
        });
        if (!media_started_) {
          stop();
        }
        return media_started_;
      }

      void detach_connection() noexcept override {
        pipeline_->detach_connection();
        revoke_input_authority();
        input::begin_close(input_);
        input::reset(input_);
        if (microphone_receiver_) {
          microphone_receiver_->stop();
        }
        prior_input_initialized_ = false;
        prior_controller_mask_ = 0;
        arrived_controller_mask_ = 0;
        controller_states_.fill(controller_state_t {});
        touch_points_.clear();
      }

      bool attach_connection(const std::uint64_t connection_id) override {
        if (connection_id == 0 || !pipeline_->bind_connection(connection_id)) {
          return false;
        }
        try {
          input_ = input::alloc(mail_);
          if (!input_) {
            return false;
          }
          if (microphone_receiver_ && !microphone_receiver_->reset(
                                        selection_.microphone_generation,
                                        client_microphone::clock_t::now()
                                      )) {
            input::begin_close(input_);
            input::reset(input_);
            pipeline_->detach_connection();
            return false;
          }
          mail_->event<bool>(mail::idr)->raise(true);
          return true;
        } catch (...) {
          pipeline_->detach_connection();
          return false;
        }
      }

      void stop() noexcept override {
        std::call_once(stop_once_, [this] {
          explicit_stop_.store(true, std::memory_order_release);
          revoke_input_authority();
          if (pipeline_) {
            pipeline_->stop();
          }
          input::begin_close(input_);
          input::reset(input_);
          mail_->event<bool>(mail::shutdown)->raise(true);
          audio_destination_->close();
          feedback_packets_->stop();
          video_egress_.stop();
          if (video_capture_.joinable()) {
            video_capture_.join();
          }
          if (audio_capture_.joinable()) {
            audio_capture_.join();
          }
          if (video_sender_.joinable()) {
            video_sender_.join();
          }
          if (audio_sender_.joinable()) {
            audio_sender_.join();
          }
          if (feedback_sender_.joinable()) {
            feedback_sender_.join();
          }
          if (microphone_receiver_) {
            microphone_receiver_->stop();
          }
          microphone_receiver_.reset();
          microphone_sink_.reset();
          if (pipeline_) {
            const auto telemetry = pipeline_->snapshot();
            BOOST_LOG(info) << "Protocol-v3 media telemetry: feedback="sv << telemetry.feedback_packets
                            << " deadline_samples="sv << telemetry.deadline_samples
                            << " deadline_misses="sv << telemetry.deadline_misses
                            << " consecutive_deadline_misses="sv << telemetry.consecutive_deadline_misses
                            << " latest_deadline_miss_us="sv << telemetry.latest_deadline_miss_microseconds
                            << " peak_deadline_miss_us="sv << telemetry.peak_deadline_miss_microseconds;
          }
  #ifdef _WIN32
          if (!cleanup_virtual_display(stream_config_)) {
            BOOST_LOG(error) << "Protocol-v3 failed to restore Lumen virtual-display topology"sv;
          }
  #endif
        });
      }

    private:
      void configure_stream() {
        const auto requested_mode = selection_.profile == lumen::protocol_v3::quic_server::Profile::latency ?
                                      stream_policy::StreamOptimizationMode::latency :
                                      stream_policy::StreamOptimizationMode::quality;
        stream_config_.optimization_policy = std::make_shared<const stream_policy::EffectiveStreamPolicy>(
          stream_policy::resolve_policy(
            requested_mode,
            requested_mode,
            config::video.nv,
            0,
            stream_policy::AdvancedOverrides {},
            selection_.fidelity == 3 ?
              stream_policy::StreamFidelityRequest::codec_lossless_required :
            selection_.fidelity == 2 ?
              stream_policy::StreamFidelityRequest::visually_lossless_allowed :
              stream_policy::StreamFidelityRequest::unspecified
          )
        );
        stream_config_.client_protocol = stream_policy::ClientProtocol::umbra_v3;
        stream_config_.packetsize = selection_.semantic_datagram_bytes;
        stream_config_.minRequiredFecPackets = 0;
        stream_config_.mlFeatureFlags = 0;
        stream_config_.controlProtocolType = 0;
        stream_config_.audioQosType = 0;
        stream_config_.videoQosType = 0;
        stream_config_.video_path_budget_bps = static_cast<std::uint64_t>(selection_.video_bitrate_kbps) * 1'000U;
        stream_config_.encryptionFlagsEnabled = 0;
        stream_config_.client_microphone = selection_.microphone_enabled;
        stream_config_.monitor.width = static_cast<int>(selection_.width);
        stream_config_.monitor.height = static_cast<int>(selection_.height);
        const auto refresh_whole = selection_.refresh_numerator / selection_.refresh_denominator;
        const auto refresh_remainder = selection_.refresh_numerator % selection_.refresh_denominator;
        stream_config_.monitor.framerate = static_cast<int>(
          refresh_whole + (refresh_remainder * 2U >= selection_.refresh_denominator ? 1U : 0U)
        );
        stream_config_.monitor.framerateX100 = 0;
        stream_config_.monitor.refreshNumerator = static_cast<int>(selection_.refresh_numerator);
        stream_config_.monitor.refreshDenominator = static_cast<int>(selection_.refresh_denominator);
        stream_config_.monitor.bitrate = static_cast<int>(selection_.video_bitrate_kbps);
        stream_config_.monitor.slicesPerFrame = 1;
        stream_config_.monitor.numRefFrames = 0;
        stream_config_.monitor.encoderCscMode = selection_.matrix_code == 9 ?
                                                  (4 | selection_.range) :
                                                selection_.matrix_code == 1 ?
                                                  (2 | selection_.range) :
                                                  selection_.range;
        stream_config_.monitor.videoFormat = selection_.codec_id - 1;
        stream_config_.monitor.dynamicRange = selection_.bit_depth == 10 ? 1 : 0;
        stream_config_.monitor.chromaSamplingType = selection_.chroma_layout == 2 ? 1 : 0;
        stream_config_.monitor.enableIntraRefresh = 0;
        stream_config_.monitor.protocolV3Colorimetry = true;
        stream_config_.monitor.colorPrimaries = selection_.primaries;
        stream_config_.monitor.colorTransfer = selection_.transfer == 2 ? 16 :
                                                 selection_.transfer == 3 ? 18 :
                                                                            1;
        stream_config_.monitor.colorMatrix = selection_.matrix_code;
        stream_config_.monitor.colorRange = selection_.range;
        stream_config_.monitor.output_name = config::video.output_name;
        stream_config_.monitor.optimization_policy = stream_config_.optimization_policy;
        stream_config_.monitor.client_protocol = stream_policy::ClientProtocol::umbra_v3;
        stream_config_.monitor.capture_input_watermark = [this]() {
          const auto watermark = input_causality_.capture();
          return std::make_pair(watermark.state_sequence, watermark.edge_id);
        };
        configure_v3_audio(stream_config_.audio, selection_);

  #ifdef _WIN32
        const platf::virtual_display::mode_t requested_display_mode {
          selection_.width,
          selection_.height,
          {selection_.refresh_numerator, selection_.refresh_denominator},
          selection_.transfer == 1 ?
            platf::virtual_display::dynamic_range_e::sdr :
            platf::virtual_display::dynamic_range_e::hdr10,
          selection_.bit_depth,
        };
        auto display_limits = platf::virtual_display::mode_limits_t {};
        display_limits.supports_hdr10 = selection_.transfer == 2 || selection_.transfer == 3;
        display_limits.supports_10bit = selection_.bit_depth == 10;
        if (selection_.codec_id == 1) {
          display_limits.maximum_width = 4096;
          display_limits.maximum_height = 4096;
          display_limits.maximum_pixels = 4096ULL * 4096ULL;
        }
        const auto configured_activation_policy = []() {
          switch (config::video.dd.virtual_display_policy) {
            case config::video_t::dd_t::virtual_display_policy_e::optional:
              return platf::virtual_display::activation_policy_e::optional;
            case config::video_t::dd_t::virtual_display_policy_e::required:
              return platf::virtual_display::activation_policy_e::required;
            case config::video_t::dd_t::virtual_display_policy_e::disabled:
            default:
              return platf::virtual_display::activation_policy_e::disabled;
          }
        }();
        const auto activation_policy = platf::virtual_display::modern_activation_policy(
          configured_activation_policy
        );
        auto prepared = platf::virtual_display::prepare_system_stream_session(
          activation_policy,
          {
            session_owner_id_,
            requested_display_mode,
            selection_.profile == lumen::protocol_v3::quic_server::Profile::latency ?
              platf::virtual_display::delivery_policy_e::latency :
              platf::virtual_display::delivery_policy_e::quality,
            platf::virtual_display::direct_surface_fidelity(),
          },
          display_limits,
          stream_config_.monitor.output_name
        );
        if (prepared.outcome == platf::virtual_display::session_prepare_e::rejected) {
          throw std::runtime_error {"protocol-v3 virtual-display policy rejection"};
        }
        stream_config_.monitor.output_name = std::move(prepared.capture_name);
        stream_config_.virtual_display_lease = std::move(prepared.lease);
        if (prepared.outcome == platf::virtual_display::session_prepare_e::virtual_display &&
            prepared.selection) {
          stream_config_.monitor.virtual_display_active = true;
          stream_config_.monitor.virtual_display_direct_required = true;
          stream_config_.monitor.virtual_display_frame_source =
            platf::virtual_display::make_system_frame_source(*prepared.selection, 250ms);
          if (!stream_config_.monitor.virtual_display_frame_source) {
            if (!cleanup_virtual_display(stream_config_)) {
              throw std::runtime_error {"protocol-v3 VDD direct-frame open and rollback failed"};
            }
            throw std::runtime_error {"protocol-v3 VDD direct-frame boundary unavailable"};
          }
        }
  #endif
        selection_.static_hdr_metadata.reset();
        if (selection_.transfer == 2) {
  #ifdef _WIN32
          if (!stream_config_.monitor.virtual_display_frame_source) {
            throw std::runtime_error {"protocol-v3 PQ requires ABI5 direct-frame metadata"};
          }
          const auto &color = stream_config_.monitor.virtual_display_frame_source->resources().initial_color_metadata;
          if (color.hdr_metadata_type == platf::virtual_display::hdr_metadata_type_e::none) {
            throw std::runtime_error {"protocol-v3 PQ ABI5 metadata unavailable"};
          }
          const auto &source = color.hdr10_metadata;
          v3_media::StaticHDRMetadata metadata;
          metadata.display_primaries = {
            source.red_primary[0], source.red_primary[1],
            source.green_primary[0], source.green_primary[1],
            source.blue_primary[0], source.blue_primary[1],
          };
          metadata.white_point = source.white_point;
          metadata.maximum_mastering_luminance =
            static_cast<std::uint32_t>(source.maximum_mastering_luminance) * 10'000U;
          metadata.minimum_mastering_luminance = source.minimum_mastering_luminance;
          metadata.maximum_content_light_level = source.maximum_content_light_level;
          metadata.maximum_frame_average_light_level = source.maximum_frame_average_light_level;
          selection_.static_hdr_metadata = metadata;
  #else
          throw std::runtime_error {"protocol-v3 PQ ABI5 metadata unavailable"};
  #endif
        } else if (selection_.transfer != 1 && selection_.transfer != 3) {
          throw std::runtime_error {"protocol-v3 unsupported effective transfer"};
        }
        stream_config_.monitor.hasStaticHDRMetadata = selection_.static_hdr_metadata.has_value();
        if (selection_.static_hdr_metadata) {
          const auto &metadata = *selection_.static_hdr_metadata;
          stream_config_.monitor.staticHDRDisplayPrimaries = metadata.display_primaries;
          stream_config_.monitor.staticHDRWhitePoint = metadata.white_point;
          stream_config_.monitor.staticHDRMaximumMasteringLuminance = metadata.maximum_mastering_luminance;
          stream_config_.monitor.staticHDRMinimumMasteringLuminance = metadata.minimum_mastering_luminance;
          stream_config_.monitor.staticHDRMaximumContentLightLevel = metadata.maximum_content_light_level;
          stream_config_.monitor.staticHDRMaximumFrameAverageLightLevel = metadata.maximum_frame_average_light_level;
        }
      }

      void start_microphone() {
        if (!selection_.microphone_enabled) {
          return;
        }
  #ifdef _WIN32
        microphone_sink_ = platf::win_audio::make_virtual_microphone();
        microphone_receiver_ = std::make_unique<client_microphone::receiver_t>(
          std::make_unique<client_microphone::opus_decoder_t>(),
          *microphone_sink_
        );
        if (!microphone_receiver_->reset(selection_.microphone_generation, client_microphone::clock_t::now())) {
          throw std::runtime_error {"protocol-v3 virtual microphone start"};
        }
  #else
        throw std::runtime_error {"protocol-v3 virtual microphone unavailable"};
  #endif
      }

      void consume_video() {
        while (auto lease = video_egress_.pop()) {
          auto packet = std::shared_ptr<video::packet_raw_t> {std::move(lease->packet)};
          if (!packet) {
            continue;
          }
          const auto completed = std::chrono::steady_clock::now();
          const auto captured = packet->frame_timestamp.value_or(completed);
          const auto delta = std::chrono::duration_cast<std::chrono::microseconds>(completed - captured).count();
          const auto submit_delta = packet->encoder_submit_timestamp ?
                                      std::optional<std::uint32_t> {static_cast<std::uint32_t>(
                                        std::clamp<std::int64_t>(
                                          std::chrono::duration_cast<std::chrono::microseconds>(
                                            *packet->encoder_submit_timestamp - captured
                                          )
                                            .count(),
                                          0,
                                          UINT32_MAX
                                        )
                                      )} :
                                      std::nullopt;
          const input::detail::causal_watermark_value_t captured_watermark {
            packet->applied_input_state_sequence,
            packet->applied_input_edge_id,
          };
          const auto result = pipeline_->submit_video({
            .frame_id = static_cast<std::uint64_t>(packet->frame_index()),
            .capture_time_microseconds = v3_microseconds(captured),
            .encoder_submit_delta_microseconds = submit_delta,
            .encoder_complete_delta_microseconds = static_cast<std::uint32_t>(std::clamp<std::int64_t>(delta, 0, UINT32_MAX)),
            .applied_input_state_sequence = captured_watermark.state_sequence,
            .applied_input_edge_id = captured_watermark.edge_id,
            .storage = packet,
            .bytes = {packet->data(), packet->data_size()},
            .request_recovery = [session_mail = mail_]() {
              session_mail->event<bool>(mail::idr)->raise(true);
            },
            .key_frame = packet->is_idr(),
            .discardable = false,
            .static_hdr_metadata = selection_.static_hdr_metadata.has_value(),
          });
          if (result != v3_media::PublishResult::accepted) {
            mail_->event<bool>(mail::idr)->raise(true);
            if (result == v3_media::PublishResult::invalid ||
                result == v3_media::PublishResult::stopped) {
              report_terminal_failure();
              return;
            }
          } else {
            const auto frame_id = static_cast<std::uint64_t>(packet->frame_index());
            if (!input_causality_.mark_captured(frame_id, captured_watermark)) {
              report_terminal_failure();
              return;
            }
            const auto acknowledgement = pipeline_->submit_input_acknowledgement({
              .host_receive_time_microseconds = v3_microseconds(completed),
              .applied_state_sequence = captured_watermark.state_sequence,
              .applied_edge_id = captured_watermark.edge_id,
              .received_edge_bitmap = 0,
              .captured_frame_id = frame_id,
            });
            if (acknowledgement != v3_media::PublishResult::accepted &&
                acknowledgement != v3_media::PublishResult::detached) {
              report_terminal_failure();
              return;
            }
          }
        }
      }

      void consume_audio() {
        while (const auto packet = audio_destination_->pop()) {
          const auto result = publish_v3_audio_packet(
            *pipeline_,
            *packet,
            v3_microseconds(std::chrono::steady_clock::now())
          );
          if (result == v3_media::PublishResult::detached) {
            continue;
          }
          if (result != v3_media::PublishResult::accepted) {
            report_terminal_failure();
            break;
          }
        }
      }

      /** @brief Forward the production virtual-controller output queue over authenticated v3. */
      void consume_controller_feedback() {
        while (const auto packet = feedback_packets_->pop()) {
          if (packet->identity.id >= current_controller_generations_.size()) {
            BOOST_LOG(error) << "Protocol-v3 platform emitted an invalid controller identifier"sv;
            continue;
          }
          if (!await_input_authority(packet->identity.input_generation)) {
            continue;
          }
          const auto input_generation = current_input_generation_.load(std::memory_order_acquire);
          const auto controller_generation =
            current_controller_generations_[packet->identity.id].load(std::memory_order_acquire);
          if (!v3_feedback_is_current(*packet, input_generation, controller_generation)) {
            continue;
          }
          v3_media::ControllerFeedback feedback {
            .input_generation = packet->identity.input_generation,
            .controller_generation = packet->identity.controller_generation,
            .controller_id = static_cast<std::uint8_t>(packet->identity.id),
          };
          switch (packet->type) {
            case platf::gamepad_feedback_e::rumble:
              feedback.command = 1;
              feedback.low_frequency = packet->data.rumble.lowfreq;
              feedback.high_frequency = packet->data.rumble.highfreq;
              break;
            case platf::gamepad_feedback_e::rumble_triggers:
              feedback.command = 2;
              feedback.low_frequency = packet->data.rumble_triggers.left_trigger;
              feedback.high_frequency = packet->data.rumble_triggers.right_trigger;
              break;
            case platf::gamepad_feedback_e::set_motion_event_state:
              feedback.command = 3;
              feedback.motion_type = packet->data.motion_event_state.motion_type;
              feedback.report_rate_hz = packet->data.motion_event_state.report_rate;
              break;
            case platf::gamepad_feedback_e::set_rgb_led:
              feedback.command = 4;
              feedback.red = packet->data.rgb_led.r;
              feedback.green = packet->data.rgb_led.g;
              feedback.blue = packet->data.rgb_led.b;
              break;
            case platf::gamepad_feedback_e::set_adaptive_triggers:
              feedback.command = 5;
              feedback.adaptive_flags = packet->data.adaptive_triggers.event_flags;
              feedback.adaptive_left_type = packet->data.adaptive_triggers.type_left;
              feedback.adaptive_right_type = packet->data.adaptive_triggers.type_right;
              feedback.adaptive_left = packet->data.adaptive_triggers.left;
              feedback.adaptive_right = packet->data.adaptive_triggers.right;
              break;
          }
          const auto result = pipeline_->submit_controller_feedback(feedback);
          if (result == v3_media::PublishResult::invalid ||
              result == v3_media::PublishResult::path_too_small) {
            BOOST_LOG(error) << "Protocol-v3 rejected platform controller feedback"sv;
          }
        }
      }

      bool submit(const v3_media::InputBatch &batch) override {
        if (!input_authority_active_.load(std::memory_order_acquire) ||
            !validate_state(batch.state_block) || batch.edge_records.size() % 32 != 0) {
          return false;
        }
        auto applied_edge = input_causality_.queued_edge();
        std::vector<std::uint8_t> pending_edges;
        for (std::size_t offset = 0; offset < batch.edge_records.size(); offset += 32) {
          const auto edge = batch.edge_records.subspan(offset, 32);
          const auto edge_id = v3_read_be<std::uint64_t>(edge, 0);
          if (edge_id <= applied_edge) {
            continue;
          }
          if (edge_id != applied_edge + 1 || !validate_edge(edge)) {
            return false;
          }
          pending_edges.insert(pending_edges.end(), edge.begin(), edge.end());
          applied_edge = edge_id;
        }
        if (!input_causality_.reserve(batch.state_sequence, applied_edge)) {
          return false;
        }
        const auto supersedable = pending_edges.empty();
        return input::passthrough_state(
          input_,
          [this,
           state = std::vector<std::uint8_t> {batch.state_block.begin(), batch.state_block.end()},
           edges = std::move(pending_edges)](const input::ordered_injector_t &injector) {
            for (std::size_t offset = 0; offset < edges.size(); offset += 32) {
              const auto edge = std::span<const std::uint8_t> {edges.data() + offset, 32};
              if (edge[16] == 4 && !apply_edge(edge, injector)) {
                return false;
              }
            }
            if (!apply_state(state, edges, injector)) {
              return false;
            }
            for (std::size_t offset = 0; offset < edges.size(); offset += 32) {
              const auto edge = std::span<const std::uint8_t> {edges.data() + offset, 32};
              if (edge[16] != 4 && !apply_edge(edge, injector)) {
                return false;
              }
            }
            return true;
          },
          supersedable,
          [this, state_sequence = batch.state_sequence, applied_edge](const bool applied) {
            if (!applied) {
              revoke_input_authority();
              report_terminal_failure();
              return;
            }
            if (!input_causality_.mark_applied(state_sequence, applied_edge)) {
              report_terminal_failure();
              return;
            }
            const input::detail::causal_watermark_value_t watermark {state_sequence, applied_edge};
            const auto acknowledgement = pipeline_->submit_input_acknowledgement({
              .host_receive_time_microseconds = v3_microseconds(std::chrono::steady_clock::now()),
              .applied_state_sequence = state_sequence,
              .applied_edge_id = applied_edge,
              .received_edge_bitmap = 0,
              .captured_frame_id = input_causality_.captured_frame(watermark),
            });
            if (acknowledgement != v3_media::PublishResult::accepted &&
                acknowledgement != v3_media::PublishResult::detached) {
              report_terminal_failure();
            }
          }
        );
      }

      void reset() noexcept override {
        input::reset(input_);
        prior_input_initialized_ = false;
        prior_controller_mask_ = 0;
        arrived_controller_mask_ = 0;
        controller_states_.fill(controller_state_t {});
        touch_points_.clear();
      }

      bool submit(const v3_media::MicrophonePacket &packet) override {
        if (!microphone_receiver_) {
          return false;
        }
        const auto now = client_microphone::clock_t::now();
        if ((packet.flags & 0x04U) != 0) {
          microphone_receiver_->stop();
          return true;
        }
        if ((packet.flags & 0x02U) != 0 &&
            !microphone_receiver_->reset(packet.generation, now)) {
          return false;
        }
        client_microphone::packet_t native {
          .generation = packet.generation,
          .sequence = packet.first_sample_position / selection_.microphone.frame_samples,
          .timestamp = static_cast<std::uint32_t>(packet.first_sample_position),
          .kind = (packet.flags & 0x01U) != 0 ?
                    client_microphone::packet_kind_e::silence :
                    client_microphone::packet_kind_e::opus,
          .payload = {packet.opus.begin(), packet.opus.end()},
        };
        if (microphone_receiver_->submit(std::move(native), now) != client_microphone::submit_result_e::accepted) {
          return false;
        }
        microphone_receiver_->poll(now + client_microphone::JITTER_WINDOW);
        return true;
      }

      void submit(const v3_media::VideoFeedback &feedback) override {
        if (feedback.action == 5) {
          mail_->event<std::pair<int64_t, int64_t>>(mail::invalidate_ref_frames)->raise(std::pair<int64_t, int64_t> {
            static_cast<std::int64_t>(feedback.last_decoded_frame_id),
            static_cast<std::int64_t>(feedback.affected_frame_id),
          });
        } else if (feedback.action >= 2 && feedback.action <= 4) {
          mail_->event<bool>(mail::idr)->raise(true);
        }
      }

      /** @brief Queue one standalone input packet on the production ordered dispatcher. */
      template<class Packet>
      bool inject(const Packet &packet) {
        return input::passthrough(input_, v3_packet_bytes(packet));
      }

      struct controller_state_t {
        std::uint8_t type {};
        std::uint16_t capabilities {};
        std::uint32_t supported_buttons {};
        std::uint64_t buttons {};
        std::uint16_t left_trigger {};
        std::uint16_t right_trigger {};
        std::int16_t left_x {};
        std::int16_t left_y {};
        std::int16_t right_x {};
        std::int16_t right_y {};
      };

      struct touch_point_t {
        std::optional<std::uint8_t> controller;
        std::uint8_t touchpad {};
        std::uint32_t pointer {};
        float x {};
        float y {};
        float pressure {};
      };

      static float v3_q16_16(const std::span<const std::uint8_t> bytes, const std::size_t offset) {
        return static_cast<float>(static_cast<std::int32_t>(v3_read_be<std::uint32_t>(bytes, offset))) /
               65'536.0f;
      }

      static touch_point_t v3_touch_point(
        const std::uint32_t encoded_pointer,
        const float x,
        const float y,
        const float pressure
      ) {
        const auto encoded_controller = static_cast<std::uint8_t>(encoded_pointer >> 24U);
        if (encoded_controller >= 1 && encoded_controller <= 16) {
          return {
            .controller = static_cast<std::uint8_t>(encoded_controller - 1),
            .touchpad = static_cast<std::uint8_t>((encoded_pointer >> 16U) & 0xffU),
            .pointer = encoded_pointer & 0xffffU,
            .x = x,
            .y = y,
            .pressure = pressure,
          };
        }
        return {.pointer = encoded_pointer, .x = x, .y = y, .pressure = pressure};
      }

      template<class Inject>
      bool inject_controller_arrival(
        const std::uint8_t controller,
        const std::uint8_t type,
        const std::uint16_t capabilities,
        const std::uint32_t supported_buttons,
        const Inject &inject
      ) {
        if (controller >= controller_states_.size() || type < 1 || type > 5 ||
            (capabilities & ~std::uint16_t {0x01ff}) != 0 ||
            (supported_buttons & ~std::uint32_t {0x003fffff}) != 0) {
          return false;
        }
        const auto prior_generation =
          controller_generation_counters_[controller].load(std::memory_order_acquire);
        if (prior_generation == UINT32_MAX) {
          return false;
        }
        const auto controller_generation = prior_generation + 1;
        controller_generation_counters_[controller].store(
          controller_generation,
          std::memory_order_release
        );
        current_controller_generations_[controller].store(
          controller_generation,
          std::memory_order_release
        );
        const auto pending_input_generation =
          pending_input_generation_.load(std::memory_order_acquire);
        const auto input_generation = pending_input_generation != 0 ?
                                        pending_input_generation :
                                        current_input_generation_.load(std::memory_order_acquire);
        if (!input::set_gamepad_feedback_identity(
              input_.get(),
              controller,
              input_generation,
              controller_generation
            )) {
          current_controller_generations_[controller].store(0, std::memory_order_release);
          return false;
        }
        SS_CONTROLLER_ARRIVAL_PACKET packet {};
        packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
        packet.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_ARRIVAL_MAGIC);
        packet.controllerNumber = controller;
        packet.type = type;
        packet.capabilities = util::endian::little(capabilities);
        packet.supportedButtonFlags = util::endian::little(supported_buttons);
        if (!inject(packet)) {
          current_controller_generations_[controller].store(0, std::memory_order_release);
          return false;
        }
        arrived_controller_mask_ |= static_cast<std::uint16_t>(1U << controller);
        return true;
      }

      template<class Inject>
      bool inject_controller_state(
        const std::uint8_t controller,
        const std::uint16_t active_mask,
        const controller_state_t &state,
        const Inject &inject
      ) const {
        NV_MULTI_CONTROLLER_PACKET packet {};
        packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
        packet.header.magic = util::endian::little<std::uint32_t>(MULTI_CONTROLLER_MAGIC_GEN5);
        packet.headerB = util::endian::little<std::int16_t>(MC_HEADER_B);
        packet.controllerNumber = util::endian::little<std::int16_t>(controller);
        packet.activeGamepadMask = util::endian::little<std::int16_t>(active_mask);
        packet.midB = util::endian::little<std::int16_t>(MC_MID_B);
        packet.buttonFlags = util::endian::little<std::int16_t>(static_cast<std::int16_t>(state.buttons));
        packet.leftTrigger = static_cast<std::uint8_t>(state.left_trigger >> 8U);
        packet.rightTrigger = static_cast<std::uint8_t>(state.right_trigger >> 8U);
        packet.leftStickX = util::endian::little(state.left_x);
        packet.leftStickY = util::endian::little(state.left_y);
        packet.rightStickX = util::endian::little(state.right_x);
        packet.rightStickY = util::endian::little(state.right_y);
        packet.tailA = util::endian::little<std::int16_t>(MC_TAIL_A);
        packet.buttonFlags2 = util::endian::little<std::int16_t>(static_cast<std::int16_t>(state.buttons >> 16U));
        packet.tailB = util::endian::little<std::int16_t>(MC_TAIL_B);
        return inject(packet);
      }

      bool validate_state(const std::span<const std::uint8_t> state) const {
        return !lumen::protocol_common::input_state::validate(state);
      }

      bool validate_edge(const std::span<const std::uint8_t> edge) const {
        if (edge.size() != 32) {
          return false;
        }
        const auto kind = edge[16];
        const auto device = edge[17];
        const auto code = v3_read_be<std::uint16_t>(edge, 18);
        const auto value = static_cast<std::int32_t>(v3_read_be<std::uint32_t>(edge, 20));
        const auto auxiliary = v3_read_be<std::uint32_t>(edge, 24);
        if (v3_read_be<std::uint32_t>(edge, 28) != 0) {
          return false;
        }
        if (kind == 1) return device == 0 && code <= 255 && (value == 0 || value == 1) && auxiliary == 0;
        if (kind == 2) return device == 0 && code >= 1 && code <= 5 && (value == 0 || value == 1) && auxiliary == 0;
        if (kind == 3) return device < 16 && code < 32 && (value == 0 || value == 1) && auxiliary == 0;
        if (kind == 4) {
          return device < 16 && code <= 0x01ff && value >= 1 && value <= 5 &&
                 (auxiliary & ~std::uint32_t {0x003fffff}) == 0;
        }
        return device == 0 && (kind == 5 || kind == 6) && (code == 2 || code == 4 || code == 5);
      }

      bool apply_state(
        const std::span<const std::uint8_t> state,
        const input::ordered_injector_t &ordered_injector
      ) {
        return apply_state(state, {}, ordered_injector);
      }

      bool apply_state(
        const std::span<const std::uint8_t> state,
        const std::span<const std::uint8_t> edges,
        const input::ordered_injector_t &ordered_injector
      ) {
        if (!validate_state(state)) {
          return false;
        }
        const auto inject = [&ordered_injector]<class Packet>(const Packet &packet) {
          return ordered_injector(v3_packet_bytes(packet));
        };
        const auto flags = v3_read_be<std::uint32_t>(state, 0);
        const auto relative = (flags & 0x03U) == 2;
        const auto absolute = (flags & 0x03U) == 1;
        const auto x = static_cast<std::int64_t>(v3_read_be<std::uint64_t>(state, 8));
        const auto y = static_cast<std::int64_t>(v3_read_be<std::uint64_t>(state, 16));
        const auto wheel = static_cast<std::int64_t>(v3_read_be<std::uint64_t>(state, 24));
        const auto horizontal = static_cast<std::int64_t>(v3_read_be<std::uint64_t>(state, 32));
        const auto controller_count = state[84];
        const auto touch_count = state[85];
        if (!prior_input_initialized_) {
          const auto mouse_buttons = v3_read_be<std::uint32_t>(state, 4);
          for (std::uint16_t button = 1; button <= 5; ++button) {
            if ((mouse_buttons & (1U << (button - 1))) == 0) {
              continue;
            }
            NV_MOUSE_BUTTON_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5);
            packet.button = static_cast<std::uint8_t>(button);
            if (!inject(packet)) {
              return false;
            }
          }
          for (std::uint16_t key = 0; key < 256; ++key) {
            if ((state[48 + key / 8] & (1U << (key % 8))) == 0) {
              continue;
            }
            NV_KEYBOARD_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(KEY_DOWN_EVENT_MAGIC);
            packet.keyCode = util::endian::little<std::int16_t>(static_cast<std::int16_t>(key | 0x8000U));
            if (!inject(packet)) {
              return false;
            }
          }
        }
        if (prior_input_initialized_) {
          if (relative && (x != prior_relative_x_ || y != prior_relative_y_)) {
            NV_REL_MOUSE_MOVE_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(MOUSE_MOVE_REL_MAGIC_GEN5);
            packet.deltaX = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
              std::clamp<std::int64_t>(x - prior_relative_x_, INT16_MIN, INT16_MAX)
            ));
            packet.deltaY = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
              std::clamp<std::int64_t>(y - prior_relative_y_, INT16_MIN, INT16_MAX)
            ));
            if (!inject(packet)) {
              return false;
            }
          }
          if (wheel != prior_wheel_) {
            NV_SCROLL_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SCROLL_MAGIC_GEN5);
            packet.scrollAmt1 = packet.scrollAmt2 = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
              std::clamp<std::int64_t>(wheel - prior_wheel_, INT16_MIN, INT16_MAX)
            ));
            if (!inject(packet)) {
              return false;
            }
          }
          if (horizontal != prior_horizontal_wheel_) {
            SS_HSCROLL_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_HSCROLL_MAGIC);
            packet.scrollAmount = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
              std::clamp<std::int64_t>(horizontal - prior_horizontal_wheel_, INT16_MIN, INT16_MAX)
            ));
            if (!inject(packet)) {
              return false;
            }
          }
        }
        if (absolute) {
          NV_ABS_MOUSE_MOVE_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(MOUSE_MOVE_ABS_MAGIC);
          packet.x = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
            v3_read_be<std::uint32_t>(state, 40) >> 17U
          ));
          packet.y = util::endian::big<std::int16_t>(static_cast<std::int16_t>(
            v3_read_be<std::uint32_t>(state, 44) >> 17U
          ));
          packet.width = util::endian::big<std::int16_t>(INT16_MAX);
          packet.height = util::endian::big<std::int16_t>(INT16_MAX);
          if (!inject(packet)) {
            return false;
          }
        }
        const auto active_mask = static_cast<std::uint16_t>(v3_read_be<std::uint32_t>(state, 80));
        for (std::size_t index = 0; index < controller_count; ++index) {
          const auto offset = 112U + index * 64U;
          const auto controller = state[offset];
          if (controller >= 16) {
            return false;
          }
          auto &controller_state = controller_states_[controller];
          const controller_state_t parsed_controller {
            .type = state[offset + 1],
            .capabilities = v3_read_be<std::uint16_t>(state, offset + 2),
            .supported_buttons = v3_read_be<std::uint32_t>(state, offset + 52),
            .buttons = v3_read_be<std::uint64_t>(state, offset + 4),
            .left_trigger = v3_read_be<std::uint16_t>(state, offset + 12),
            .right_trigger = v3_read_be<std::uint16_t>(state, offset + 14),
            .left_x = static_cast<std::int16_t>(v3_read_be<std::uint16_t>(state, offset + 16)),
            .left_y = static_cast<std::int16_t>(v3_read_be<std::uint16_t>(state, offset + 18)),
            .right_x = static_cast<std::int16_t>(v3_read_be<std::uint16_t>(state, offset + 20)),
            .right_y = static_cast<std::int16_t>(v3_read_be<std::uint16_t>(state, offset + 22)),
          };
          if ((arrived_controller_mask_ & (1U << controller)) != 0 &&
              (controller_state.type != parsed_controller.type ||
               controller_state.capabilities != parsed_controller.capabilities ||
               controller_state.supported_buttons != parsed_controller.supported_buttons)) {
            return false;
          }
          controller_state = parsed_controller;
          if ((arrived_controller_mask_ & (1U << controller)) == 0 &&
              !inject_controller_arrival(
                controller,
                controller_state.type,
                controller_state.capabilities,
                controller_state.supported_buttons,
                inject
              )) {
            return false;
          }
          if (!inject_controller_state(controller, active_mask, controller_state, inject)) {
            return false;
          }
          if ((controller_state.capabilities & 0x20U) != 0) {
            SS_CONTROLLER_MOTION_PACKET motion {};
            motion.header.size = util::endian::big<std::uint32_t>(sizeof(motion) - sizeof(std::uint32_t));
            motion.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_MOTION_MAGIC);
            motion.controllerNumber = controller;
            motion.motionType = LI_MOTION_TYPE_GYRO;
            v3_netfloat(v3_q16_16(state, offset + 24), motion.x);
            v3_netfloat(v3_q16_16(state, offset + 28), motion.y);
            v3_netfloat(v3_q16_16(state, offset + 32), motion.z);
            if (!inject(motion)) return false;
          }
          if ((controller_state.capabilities & 0x10U) != 0) {
            SS_CONTROLLER_MOTION_PACKET motion {};
            motion.header.size = util::endian::big<std::uint32_t>(sizeof(motion) - sizeof(std::uint32_t));
            motion.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_MOTION_MAGIC);
            motion.controllerNumber = controller;
            motion.motionType = LI_MOTION_TYPE_ACCEL;
            v3_netfloat(v3_q16_16(state, offset + 36), motion.x);
            v3_netfloat(v3_q16_16(state, offset + 40), motion.y);
            v3_netfloat(v3_q16_16(state, offset + 44), motion.z);
            if (!inject(motion)) return false;
          }
          const auto battery = v3_read_be<std::uint16_t>(state, offset + 48);
          if ((controller_state.capabilities & 0x40U) != 0 && battery != UINT16_MAX) {
            SS_CONTROLLER_BATTERY_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_BATTERY_MAGIC);
            packet.controllerNumber = controller;
            packet.batteryState = state[offset + 50];
            packet.batteryPercentage = static_cast<std::uint8_t>(std::min<std::uint16_t>(battery / 100U, 100U));
            if (!inject(packet)) return false;
          }
        }
        for (std::uint8_t controller = 0; controller < 16; ++controller) {
          if ((prior_controller_mask_ & (1U << controller)) == 0 ||
              (active_mask & (1U << controller)) != 0) {
            continue;
          }
          NV_MULTI_CONTROLLER_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(MULTI_CONTROLLER_MAGIC_GEN5);
          packet.headerB = util::endian::little<std::int16_t>(MC_HEADER_B);
          packet.controllerNumber = util::endian::little<std::int16_t>(controller);
          packet.activeGamepadMask = util::endian::little<std::int16_t>(active_mask);
          packet.midB = util::endian::little<std::int16_t>(MC_MID_B);
          packet.tailA = util::endian::little<std::int16_t>(MC_TAIL_A);
          packet.tailB = util::endian::little<std::int16_t>(MC_TAIL_B);
          if (!inject(packet)) {
            return false;
          }
          arrived_controller_mask_ &= static_cast<std::uint16_t>(~(1U << controller));
          current_controller_generations_[controller].store(0, std::memory_order_release);
          controller_states_[controller] = {};
        }
        prior_controller_mask_ = active_mask;
        const auto touch_base = 112U + static_cast<std::size_t>(controller_count) * 64U;
        for (std::size_t index = 0; index < touch_count; ++index) {
          const auto offset = touch_base + index * 32U;
          const auto scale = static_cast<double>(UINT32_MAX);
          const auto pointer_id = v3_read_be<std::uint32_t>(state, offset);
          const auto touch_x = static_cast<float>(v3_read_be<std::uint32_t>(state, offset + 8) / scale);
          const auto touch_y = static_cast<float>(v3_read_be<std::uint32_t>(state, offset + 12) / scale);
          const auto pressure = static_cast<float>(v3_read_be<std::uint16_t>(state, offset + 6)) / UINT16_MAX;
          const auto point = v3_touch_point(pointer_id, touch_x, touch_y, pressure);
          const auto has_down_edge = [&]() {
            for (std::size_t edge_offset = 0; edge_offset < edges.size(); edge_offset += 32) {
              const auto edge = edges.subspan(edge_offset, 32);
              if (edge[16] == 5 && v3_read_be<std::uint16_t>(edge, 18) == 2 &&
                  v3_read_be<std::uint32_t>(edge, 24) == pointer_id) {
                return true;
              }
            }
            return false;
          }();
          if (has_down_edge && !touch_points_.contains(pointer_id)) {
            touch_points_[pointer_id] = point;
            continue;
          }
          const auto event_type = touch_points_.contains(pointer_id) ? LI_TOUCH_EVENT_MOVE : LI_TOUCH_EVENT_DOWN;
          if (point.controller) {
            const auto controller = *point.controller;
            const auto capabilities = controller_states_[controller].capabilities;
            if ((arrived_controller_mask_ & (1U << controller)) == 0 ||
                (capabilities & 0x08U) == 0 || point.touchpad > 1 ||
                (point.touchpad == 1 && (capabilities & 0x100U) == 0)) {
              return false;
            }
            SS_CONTROLLER_TOUCH_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_TOUCH_MAGIC);
            packet.controllerNumber = controller;
            packet.eventType = event_type;
            packet.touchpadIndex = point.touchpad;
            packet.pointerId = util::endian::little(point.pointer);
            v3_netfloat(point.x, packet.x);
            v3_netfloat(point.y, packet.y);
            v3_netfloat(point.pressure, packet.pressure);
            if (!inject(packet)) return false;
          } else {
            SS_TOUCH_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_TOUCH_MAGIC);
            packet.eventType = event_type;
            packet.pointerId = util::endian::little(point.pointer);
            packet.rotation = LI_ROT_UNKNOWN;
            v3_netfloat(point.x, packet.x);
            v3_netfloat(point.y, packet.y);
            v3_netfloat(point.pressure, packet.pressureOrDistance);
            if (!inject(packet)) return false;
          }
          touch_points_[pointer_id] = point;
        }
        prior_relative_x_ = x;
        prior_relative_y_ = y;
        prior_wheel_ = wheel;
        prior_horizontal_wheel_ = horizontal;
        prior_input_initialized_ = true;
        return true;
      }

      bool apply_edge(
        const std::span<const std::uint8_t> edge,
        const input::ordered_injector_t &ordered_injector
      ) {
        if (!validate_edge(edge)) {
          return false;
        }
        const auto inject = [&ordered_injector]<class Packet>(const Packet &packet) {
          return ordered_injector(v3_packet_bytes(packet));
        };
        const auto kind = edge[16];
        const auto device = edge[17];
        const auto code = v3_read_be<std::uint16_t>(edge, 18);
        const auto value = static_cast<std::int32_t>(v3_read_be<std::uint32_t>(edge, 20));
        if (kind == 1) {
          NV_KEYBOARD_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(
            value != 0 ? KEY_DOWN_EVENT_MAGIC : KEY_UP_EVENT_MAGIC
          );
          packet.keyCode = util::endian::little<std::int16_t>(static_cast<std::int16_t>(code | 0x8000U));
          if (!inject(packet)) {
            return false;
          }
          return true;
        }
        if (kind == 2 && code >= 1 && code <= 5) {
          NV_MOUSE_BUTTON_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(
            value != 0 ? MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5 : MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5
          );
          packet.button = static_cast<std::uint8_t>(code);
          if (!inject(packet)) {
            return false;
          }
          return true;
        }
        if (kind == 3) {
          if ((prior_controller_mask_ & (1U << device)) == 0 ||
              (arrived_controller_mask_ & (1U << device)) == 0) {
            return false;
          }
          auto &state = controller_states_[device];
          const auto mask = std::uint64_t {1} << code;
          state.buttons = value != 0 ? state.buttons | mask : state.buttons & ~mask;
          return inject_controller_state(device, prior_controller_mask_, state, inject);
        }
        if (kind == 4) {
          if ((arrived_controller_mask_ & (1U << device)) != 0) {
            const auto &state = controller_states_[device];
            return state.type == static_cast<std::uint8_t>(value) &&
                   state.capabilities == code &&
                   state.supported_buttons == v3_read_be<std::uint32_t>(edge, 24);
          }
          if (!inject_controller_arrival(
                device,
                static_cast<std::uint8_t>(value),
                code,
                v3_read_be<std::uint32_t>(edge, 24),
                inject
              )) {
            return false;
          }
          controller_states_[device].type = static_cast<std::uint8_t>(value);
          controller_states_[device].capabilities = code;
          controller_states_[device].supported_buttons = v3_read_be<std::uint32_t>(edge, 24);
          return true;
        }
        if (kind == 5 && (code == 2 || code == 4 || code == 5)) {
          const auto pointer_id = v3_read_be<std::uint32_t>(edge, 24);
          const auto point = touch_points_.find(pointer_id);
          if (point == touch_points_.end()) {
            return false;
          }
          const auto event_type = code == 2 ? LI_TOUCH_EVENT_DOWN :
                                  code == 4 ? LI_TOUCH_EVENT_UP :
                                              LI_TOUCH_EVENT_CANCEL;
          const auto &touch = point->second;
          if (touch.controller) {
            SS_CONTROLLER_TOUCH_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_TOUCH_MAGIC);
            packet.controllerNumber = *touch.controller;
            packet.eventType = event_type;
            packet.touchpadIndex = touch.touchpad;
            packet.pointerId = util::endian::little(touch.pointer);
            v3_netfloat(touch.x, packet.x);
            v3_netfloat(touch.y, packet.y);
            v3_netfloat(touch.pressure, packet.pressure);
            if (!inject(packet)) return false;
          } else {
            SS_TOUCH_PACKET packet {};
            packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
            packet.header.magic = util::endian::little<std::uint32_t>(SS_TOUCH_MAGIC);
            packet.eventType = event_type;
            packet.pointerId = util::endian::little(touch.pointer);
            packet.rotation = LI_ROT_UNKNOWN;
            v3_netfloat(touch.x, packet.x);
            v3_netfloat(touch.y, packet.y);
            v3_netfloat(touch.pressure, packet.pressureOrDistance);
            if (!inject(packet)) return false;
          }
          if (code == 4 || code == 5) {
            touch_points_.erase(pointer_id);
          }
          return true;
        }
        if (kind == 6 && (code == 2 || code == 4 || code == 5)) {
          SS_PEN_PACKET packet {};
          packet.header.size = util::endian::big<std::uint32_t>(sizeof(packet) - sizeof(std::uint32_t));
          packet.header.magic = util::endian::little<std::uint32_t>(SS_PEN_MAGIC);
          packet.eventType = static_cast<std::uint8_t>(code);
          packet.toolType = LI_TOOL_TYPE_PEN;
          if (!inject(packet)) {
            return false;
          }
          return true;
        }
        return false;
      }

      void report_terminal_failure() noexcept {
        if (!claim_terminal_failure()) {
          return;
        }
        try {
          terminal_failure_();
        } catch (...) {
        }
      }

      void report_terminal_failure_async() noexcept {
        if (!claim_terminal_failure()) {
          return;
        }
        auto callback = terminal_failure_;
        try {
          std::thread([callback]() mutable noexcept {
            try {
              callback();
            } catch (...) {
            }
          }).detach();
        } catch (...) {
          try {
            callback();
          } catch (...) {
          }
        }
      }

      bool claim_terminal_failure() noexcept {
        if (explicit_stop_.load(std::memory_order_acquire)) {
          return false;
        }
        bool expected = false;
        return failure_reported_.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
      }

      void revoke_input_authority() noexcept {
        input_authority_active_.store(false, std::memory_order_release);
        current_input_generation_.store(0, std::memory_order_release);
        pending_input_generation_.store(0, std::memory_order_release);
        for (auto &generation : current_controller_generations_) {
          generation.store(0, std::memory_order_release);
        }
        input_authority_changed_.notify_all();
      }

      bool await_input_authority(const std::uint32_t generation) noexcept {
        if (generation == 0) {
          return false;
        }
        auto current = current_input_generation_.load(std::memory_order_acquire);
        if (input_authority_active_.load(std::memory_order_acquire) && current == generation) {
          return true;
        }
        std::unique_lock lock {input_authority_mutex_};
        input_authority_changed_.wait_for(lock, 300ms, [this, generation]() {
          return explicit_stop_.load(std::memory_order_acquire) ||
                 current_input_generation_.load(std::memory_order_acquire) == generation ||
                 pending_input_generation_.load(std::memory_order_acquire) != generation;
        });
        current = current_input_generation_.load(std::memory_order_acquire);
        return input_authority_active_.load(std::memory_order_acquire) && current == generation;
      }

      v3_media::NegotiatedMediaConfig selection_;
      [[maybe_unused]] std::uint64_t session_owner_id_ {};  ///< Nonzero exact owner for VDD and runtime resources.
      std::function<void()> terminal_failure_;
      std::vector<std::uint8_t> codec_initialization_;
      safe::mail_t mail_;
      std::shared_ptr<input::input_t> input_;
      std::shared_ptr<v3_audio_packet_destination> audio_destination_;
      safe::mail_raw_t::queue_t<platf::gamepad_feedback_msg_t> feedback_packets_;
      video::egress_queue_t video_egress_;
      v3_media::TransportSink &transport_;  ///< Live QUIC sink used after platform media activation.
      std::unique_ptr<v3_media::SessionPipeline> pipeline_;  ///< Constructed only after ABI5 resolves PQ metadata.
      config_t stream_config_ {};
      std::jthread video_capture_;
      std::jthread audio_capture_;
      std::jthread video_sender_;
      std::jthread audio_sender_;
      std::jthread feedback_sender_;
      std::once_flag stop_once_;
      std::once_flag start_once_;
      bool media_started_ {};
      std::atomic_bool explicit_stop_ {};
      std::atomic_bool failure_reported_ {};
      input::detail::causal_watermark_t input_causality_;  ///< Queued, injected, and captured input causality.
      bool prior_input_initialized_ {};
      std::int64_t prior_relative_x_ {};
      std::int64_t prior_relative_y_ {};
      std::int64_t prior_wheel_ {};
      std::int64_t prior_horizontal_wheel_ {};
      std::uint16_t prior_controller_mask_ {};
      std::uint16_t arrived_controller_mask_ {};
      std::atomic_uint32_t current_input_generation_ {};
      std::atomic_uint32_t pending_input_generation_ {};
      std::atomic_bool input_authority_active_ {true};
      std::mutex input_authority_mutex_;
      std::condition_variable input_authority_changed_;
      std::array<std::atomic_uint32_t, 16> controller_generation_counters_ {};
      std::array<std::atomic_uint32_t, 16> current_controller_generations_ {};
      std::array<controller_state_t, 16> controller_states_ {};
      std::unordered_map<std::uint32_t, touch_point_t> touch_points_;
      std::unique_ptr<client_microphone::sink_t> microphone_sink_;
      std::unique_ptr<client_microphone::receiver_t> microphone_receiver_;
    };

    class native_v3_session_resource_factory final: public v3_runtime::SessionResourceFactory {
    public:
      explicit native_v3_session_resource_factory(v3_media::TransportSink &transport):
          transport_ {transport} {
      }

      std::expected<std::unique_ptr<v3_runtime::SessionResources>, std::uint8_t> create(
        const v3_media::NegotiatedMediaConfig &config,
        const std::uint64_t connection_id,
        std::function<void()> terminal_failure
      ) override {
        try {
          return std::make_unique<native_v3_session_resources>(
            config,
            connection_id,
            transport_,
            std::move(terminal_failure)
          );
        } catch (...) {
          return std::unexpected(std::uint8_t {8});
        }
      }

    private:
      v3_media::TransportSink &transport_;
    };
  }  // namespace

  void configure_protocol_v3_audio(
    audio::config_t &output,
    const lumen::protocol_v3::media::NegotiatedMediaConfig &selection
  ) {
    configure_v3_audio(output, selection);
  }

#ifdef SUNSHINE_TESTS
  audio_packet_queue_probe_t audio_packet_queue_probe_for_test() {
    const auto packet = [](const std::uint8_t tag) {
      audio::buffer_t payload {1};
      payload[0] = tag;
      return audio::packet_t {.payload = std::move(payload)};
    };
    const auto tag = [](const audio::packet_t &packet) {
      return packet.payload.size() == 0 ? std::uint8_t {} : packet.payload[0];
    };

    audio_packet_queue_probe_t result {};
    audio_packet_queue_t<audio::packet_t> queue {1};
    result.first_enqueue = queue.enqueue(packet(0x11));
    result.full_enqueue = queue.enqueue(packet(0x22));
    if (result.first_enqueue == audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = queue.pop();
      result.first_pop_present = popped.has_value();
      if (popped) {
        result.first_pop_tag = tag(*popped);
      }
    }
    result.refill_enqueue = queue.enqueue(packet(0x33));
    queue.close();
    queue.close();
    result.pop_after_repeated_close_present = queue.pop().has_value();
    result.enqueue_after_repeated_close = queue.enqueue(packet(0x44));

    auto blocked_queue = std::make_shared<audio_packet_queue_t<audio::packet_t>>(1);
    auto started = std::make_shared<std::promise<void>>();
    auto popped = std::make_shared<std::promise<std::optional<audio::packet_t>>>();
    auto started_future = started->get_future();
    auto popped_future = popped->get_future();
    std::thread waiter {[blocked_queue, started, popped]() {
      started->set_value();
      popped->set_value(blocked_queue->pop());
    }};
    waiter.detach();
    started_future.wait();
    result.waiter_blocked_before_close =
      popped_future.wait_for(20ms) == std::future_status::timeout;
    blocked_queue->close();
    result.waiter_ready_after_close =
      popped_future.wait_for(1s) == std::future_status::ready;
    if (result.waiter_ready_after_close) {
      result.waiter_pop_present = popped_future.get().has_value();
    }
    return result;
  }

  audio_destination_isolation_probe_t audio_destination_isolation_probe_for_test() {
    const auto packet = [](const std::uint8_t tag) {
      audio::buffer_t payload {1};
      payload[0] = tag;
      return audio::packet_t {.payload = std::move(payload)};
    };
    const auto tag = [](const audio::packet_t &packet) {
      return packet.payload.size() == 0 ? std::uint8_t {} : packet.payload[0];
    };

    audio_destination_isolation_probe_t result {};
    auto legacy_queue = std::make_shared<legacy_audio_packet_queue_t>(1);
    auto first_session = std::make_shared<session_t>();
    auto second_session = std::make_shared<session_t>();
    const auto owner_id = [&first_session, &second_session](const std::weak_ptr<session_t> &session) {
      const auto owner = session.lock();
      if (owner.get() == first_session.get()) {
        return std::uint8_t {1};
      }
      if (owner.get() == second_session.get()) {
        return std::uint8_t {2};
      }
      return std::uint8_t {};
    };
    legacy_audio_packet_destination first_legacy {first_session, legacy_queue};
    legacy_audio_packet_destination second_legacy {second_session, legacy_queue};

    result.legacy_first_enqueue = first_legacy.enqueue(packet(0xa1));
    result.legacy_second_while_full = second_legacy.enqueue(packet(0xb1));
    if (result.legacy_first_enqueue == audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = legacy_queue->pop();
      if (popped) {
        result.legacy_first_pop_owner = owner_id(popped->session);
        result.legacy_first_pop_tag = tag(popped->packet);
      }
    }
    result.legacy_second_after_pop = second_legacy.enqueue(packet(0xb2));
    if (result.legacy_second_after_pop == audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = legacy_queue->pop();
      if (popped) {
        result.legacy_second_pop_owner = owner_id(popped->session);
        result.legacy_second_pop_tag = tag(popped->packet);
      }
    }
    first_legacy.close();
    first_legacy.close();
    result.legacy_first_after_close = first_legacy.enqueue(packet(0xa2));
    result.legacy_second_after_first_close = second_legacy.enqueue(packet(0xb3));
    if (result.legacy_second_after_first_close ==
        audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = legacy_queue->pop();
      if (popped) {
        result.legacy_second_after_close_owner = owner_id(popped->session);
        result.legacy_second_after_close_tag = tag(popped->packet);
      }
    }
    second_session.reset();
    result.legacy_second_after_owner_expiry = second_legacy.enqueue(packet(0xb4));

    v3_audio_packet_destination first_v3;
    v3_audio_packet_destination second_v3;
    for (std::uint32_t index = 0; index < 32; ++index) {
      if (first_v3.enqueue(packet(static_cast<std::uint8_t>(0x40U + index))) !=
          audio::AudioPacketDestination::enqueue_result_e::enqueued) {
        break;
      }
      ++result.v3_first_enqueued_count;
    }
    result.v3_first_over_capacity = first_v3.enqueue(packet(0xee));
    result.v3_second_enqueue = second_v3.enqueue(packet(0xb1));
    if (result.v3_first_enqueued_count != 0) {
      const auto popped = first_v3.pop();
      if (popped) {
        result.v3_first_pop_tag = tag(*popped);
      }
    }
    if (result.v3_second_enqueue == audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = second_v3.pop();
      if (popped) {
        result.v3_second_pop_tag = tag(*popped);
      }
    }
    first_v3.close();
    first_v3.close();
    result.v3_first_pop_after_close_present = first_v3.pop().has_value();
    result.v3_first_after_repeated_close = first_v3.enqueue(packet(0xef));
    result.v3_second_after_first_close = second_v3.enqueue(packet(0xb2));
    if (result.v3_second_after_first_close ==
        audio::AudioPacketDestination::enqueue_result_e::enqueued) {
      const auto popped = second_v3.pop();
      if (popped) {
        result.v3_second_after_close_tag = tag(*popped);
      }
    }
    return result;
  }

  protocol_v3_audio_fixture_probe_t protocol_v3_audio_fixture_probe_for_test(
    const lumen::protocol_v3::media::NegotiatedMediaConfig &selection,
    lumen::protocol_v3::runtime::QuicTransportSink &transport,
    const std::uint64_t connection_id,
    const std::uint64_t capture_time_microseconds
  ) {
    struct input_sink_t final: v3_media::InputSink {
      bool submit(const v3_media::InputBatch &) override {
        return true;
      }

      void reset() noexcept override {
      }
    } input_sink;

    struct microphone_sink_t final: v3_media::MicrophoneSink {
      bool submit(const v3_media::MicrophonePacket &) override {
        return true;
      }

      void stop() noexcept override {
      }
    } microphone_sink;

    struct feedback_sink_t final: v3_media::VideoFeedbackSink {
      void submit(const v3_media::VideoFeedback &) override {
      }
    } feedback_sink;

    protocol_v3_audio_fixture_probe_t result {
      .publish_result = v3_media::PublishResult::stopped,
    };
    v3_media::SessionPipeline pipeline {
      selection,
      transport,
      input_sink,
      microphone_sink,
      feedback_sink,
    };
    if (!pipeline.bind_connection(connection_id)) {
      return result;
    }

    auto mail = std::make_shared<safe::mail_raw_t>();
    auto destination = std::make_shared<v3_audio_packet_destination>();
    auto shutdown = mail->event<bool>(mail::shutdown);
    std::atomic_bool drained {};
    std::jthread consumer {[&]() {
      if (const auto packet = destination->pop()) {
        result.first_sample_position = packet->sample_position;
        result.opus_bytes = packet->payload.size();
        result.discontinuity = packet->discontinuity;
        result.publish_result = publish_v3_audio_packet(
          pipeline,
          *packet,
          capture_time_microseconds
        );
        result.capture_completed = true;
        drained.store(true, std::memory_order_release);
      }
      shutdown->raise(true);
    }};
    std::jthread watchdog {[&](const std::stop_token token) {
      for (auto elapsed = 0ms; elapsed < 3s && !token.stop_requested() && !drained.load(std::memory_order_acquire); elapsed += 10ms) {
        std::this_thread::sleep_for(10ms);
      }
      if (!token.stop_requested() && !drained.load(std::memory_order_acquire)) {
        shutdown->raise(true);
        destination->close();
      }
    }};

    audio::config_t capture_config {};
    configure_v3_audio(capture_config, selection);
    audio::capture(mail, capture_config, destination);
    watchdog.request_stop();
    if (watchdog.joinable()) {
      watchdog.join();
    }
    destination->close();
    if (consumer.joinable()) {
      consumer.join();
    }

    pipeline.stop();
    return result;
  }

  bool protocol_v3_feedback_is_current_for_test(
    const platf::gamepad_feedback_msg_t &message,
    const std::uint32_t input_generation,
    const std::uint32_t controller_generation
  ) noexcept {
    return v3_feedback_is_current(message, input_generation, controller_generation);
  }
#endif

  std::unique_ptr<lumen::protocol_v3::runtime::SessionResourceFactory>
    make_protocol_v3_session_resource_factory(
      lumen::protocol_v3::media::TransportSink &transport
    ) {
    return std::make_unique<native_v3_session_resource_factory>(transport);
  }
#endif
}  // namespace stream
