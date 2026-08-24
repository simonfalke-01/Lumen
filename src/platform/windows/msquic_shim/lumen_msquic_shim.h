/**
 * @file src/platform/windows/msquic_shim/lumen_msquic_shim.h
 * @brief Stable C ABI between MinGW Lumen and the MSVC-built MsQuic adapter.
 */

#ifndef LUMEN_MSQUIC_SHIM_H
#define LUMEN_MSQUIC_SHIM_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  #define LUMEN_MSQUIC_CALL __cdecl
  #if defined(LUMEN_MSQUIC_SHIM_BUILD)
    #define LUMEN_MSQUIC_EXPORT __declspec(dllexport)
  #else
    #define LUMEN_MSQUIC_EXPORT __declspec(dllimport)
  #endif
#else
  #define LUMEN_MSQUIC_CALL
  #define LUMEN_MSQUIC_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LUMEN_MSQUIC_SHIM_ABI_VERSION 2u

  typedef uintptr_t lumen_msquic_handle;
  typedef struct lumen_msquic_shim lumen_msquic_shim;

  typedef enum lumen_msquic_status {
    LUMEN_MSQUIC_SUCCESS = 0,
    LUMEN_MSQUIC_PENDING = 1,
    LUMEN_MSQUIC_OUT_OF_MEMORY = 2,
    LUMEN_MSQUIC_INVALID_STATE = 3,
    LUMEN_MSQUIC_NOT_SUPPORTED = 4,
    LUMEN_MSQUIC_ABORTED = 5,
    LUMEN_MSQUIC_TRANSPORT_ERROR = 6,
  } lumen_msquic_status;

  typedef struct lumen_msquic_buffer {
    const uint8_t *data;
    size_t size;
  } lumen_msquic_buffer;

  typedef enum lumen_msquic_listener_event_kind {
    LUMEN_MSQUIC_LISTENER_NEW_CONNECTION = 0,
    LUMEN_MSQUIC_LISTENER_STOP_COMPLETE = 1,
  } lumen_msquic_listener_event_kind;

  typedef struct lumen_msquic_listener_event {
    lumen_msquic_listener_event_kind kind;
    lumen_msquic_handle connection;
    uint16_t remote_address_family;
    uint8_t remote_address[16];
  } lumen_msquic_listener_event;

  typedef enum lumen_msquic_connection_event_kind {
    LUMEN_MSQUIC_CONNECTION_CONNECTED = 0,
    LUMEN_MSQUIC_CONNECTION_DATAGRAM_STATE = 1,
    LUMEN_MSQUIC_CONNECTION_DATAGRAM_RECEIVED = 2,
    LUMEN_MSQUIC_CONNECTION_DATAGRAM_SEND_COMPLETE = 3,
    LUMEN_MSQUIC_CONNECTION_PEER_STREAM = 4,
    LUMEN_MSQUIC_CONNECTION_SHUTDOWN_TRANSPORT = 5,
    LUMEN_MSQUIC_CONNECTION_SHUTDOWN_PEER = 6,
    LUMEN_MSQUIC_CONNECTION_SHUTDOWN_COMPLETE = 7,
  } lumen_msquic_connection_event_kind;

  typedef struct lumen_msquic_connection_event {
    lumen_msquic_connection_event_kind kind;
    lumen_msquic_handle stream;
    uint64_t stream_id;
    uint64_t send_token;
    uint64_t error;
    const uint8_t *bytes;
    size_t byte_count;
    uint16_t maximum_datagram_bytes;
    uint8_t datagram_enabled;
    uint8_t resumed;
    uint8_t canceled;
    uint8_t peer_stream_unidirectional;
  } lumen_msquic_connection_event;

  typedef enum lumen_msquic_stream_event_kind {
    LUMEN_MSQUIC_STREAM_RECEIVE = 0,
    LUMEN_MSQUIC_STREAM_SEND_COMPLETE = 1,
    LUMEN_MSQUIC_STREAM_WRITABLE = 2,
    LUMEN_MSQUIC_STREAM_START_COMPLETE = 3,
    LUMEN_MSQUIC_STREAM_PEER_SEND_SHUTDOWN = 4,
    LUMEN_MSQUIC_STREAM_PEER_SEND_ABORTED = 5,
    LUMEN_MSQUIC_STREAM_PEER_RECEIVE_ABORTED = 6,
    LUMEN_MSQUIC_STREAM_SEND_SHUTDOWN_COMPLETE = 7,
    LUMEN_MSQUIC_STREAM_SHUTDOWN_COMPLETE = 8,
  } lumen_msquic_stream_event_kind;

  typedef struct lumen_msquic_stream_event {
    lumen_msquic_stream_event_kind kind;
    const lumen_msquic_buffer *buffers;
    size_t buffer_count;
    uint64_t total_buffer_bytes;
    uint64_t send_token;
    uint64_t error;
    uint8_t canceled;
  } lumen_msquic_stream_event;

  typedef struct lumen_msquic_statistics {
    uint32_t valid_fields;
    uint64_t smoothed_rtt_microseconds;
    uint64_t minimum_rtt_microseconds;
    uint64_t congestion_window_bytes;
    uint64_t bytes_in_flight;
    uint64_t packets_lost;
  } lumen_msquic_statistics;

#define LUMEN_MSQUIC_STAT_VALID_RTT 0x01u
#define LUMEN_MSQUIC_STAT_VALID_CONGESTION_WINDOW 0x02u
#define LUMEN_MSQUIC_STAT_VALID_BYTES_IN_FLIGHT 0x04u
#define LUMEN_MSQUIC_STAT_VALID_PACKETS_LOST 0x08u

  typedef lumen_msquic_status(LUMEN_MSQUIC_CALL *lumen_msquic_listener_callback)(
    void *context,
    const lumen_msquic_listener_event *event
  );
  typedef lumen_msquic_status(LUMEN_MSQUIC_CALL *lumen_msquic_connection_callback)(
    void *context,
    const lumen_msquic_connection_event *event
  );
  typedef lumen_msquic_status(LUMEN_MSQUIC_CALL *lumen_msquic_stream_callback)(
    void *context,
    const lumen_msquic_stream_event *event
  );

  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_open(
    uint32_t requested_abi,
    lumen_msquic_shim **shim
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_close(lumen_msquic_shim *shim);
  LUMEN_MSQUIC_EXPORT int LUMEN_MSQUIC_CALL lumen_msquic_is_schannel(lumen_msquic_shim *shim);
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_registration_open(
    lumen_msquic_shim *shim,
    const char *name,
    lumen_msquic_handle *registration
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_registration_close(
    lumen_msquic_shim *shim,
    lumen_msquic_handle registration
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_open(
    lumen_msquic_shim *shim,
    lumen_msquic_handle registration,
    const uint8_t *alpn,
    size_t alpn_length,
    uint16_t peer_bidi,
    uint16_t peer_unidi,
    uint64_t handshake_timeout_ms,
    uint64_t initial_idle_timeout_ms,
    lumen_msquic_handle *configuration
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_load_pkcs12(
    lumen_msquic_shim *shim,
    lumen_msquic_handle configuration,
    const uint8_t *pkcs12,
    size_t pkcs12_size,
    const char *password
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_leaf_spki_sha256(
    lumen_msquic_shim *shim,
    lumen_msquic_handle configuration,
    uint8_t output[32]
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_configuration_close(
    lumen_msquic_shim *shim,
    lumen_msquic_handle configuration
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_listener_open(
    lumen_msquic_shim *shim,
    lumen_msquic_handle registration,
    lumen_msquic_listener_callback callback,
    void *context,
    lumen_msquic_handle *listener
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_listener_start(
    lumen_msquic_shim *shim,
    lumen_msquic_handle listener,
    const uint8_t *alpn,
    size_t alpn_length,
    uint16_t port
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_listener_stop(
    lumen_msquic_shim *shim,
    lumen_msquic_handle listener
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_listener_close(
    lumen_msquic_shim *shim,
    lumen_msquic_handle listener
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_callback(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    lumen_msquic_connection_callback callback,
    void *context
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_configuration(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    lumen_msquic_handle configuration
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_idle_timeout(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    uint64_t timeout_ms
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_connection_shutdown(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    uint64_t error
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_connection_close(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_open_unidirectional(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    lumen_msquic_stream_callback callback,
    void *context,
    lumen_msquic_handle *stream
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_start(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_set_callback(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream,
    lumen_msquic_stream_callback callback,
    void *context
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_send(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream,
    const lumen_msquic_buffer *buffers,
    size_t buffer_count,
    uint64_t send_token,
    uint8_t urgent,
    uint8_t fin
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_set_priority(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream,
    uint16_t priority
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_stream_receive_complete(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream,
    uint64_t bytes
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_stream_shutdown(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream,
    uint64_t error
  );
  LUMEN_MSQUIC_EXPORT void LUMEN_MSQUIC_CALL lumen_msquic_stream_close(
    lumen_msquic_shim *shim,
    lumen_msquic_handle stream
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_datagram_send(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    const lumen_msquic_buffer *buffers,
    size_t buffer_count,
    uint64_t send_token,
    uint8_t urgent,
    uint8_t cancel_on_blocked
  );
  LUMEN_MSQUIC_EXPORT lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_statistics(
    lumen_msquic_shim *shim,
    lumen_msquic_handle connection,
    lumen_msquic_statistics *statistics
  );

#ifdef __cplusplus
}
#endif

#endif
