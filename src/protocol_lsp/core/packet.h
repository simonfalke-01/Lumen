/**
 * @file src/protocol_lsp/core/packet.h
 * @brief Portable packet classification and bounded packet-storage primitives.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace lumen::lsp {
  /** @brief Classification assigned from the first byte of an RFC 7983 datagram. */
  enum class packet_class : std::uint8_t {
    invalid,  ///< Byte range is not assigned to a protocol carried by the LSP socket.
    stun,  ///< RFC 7983 STUN range; reserved and rejected by LSP version 1.
    zrtp,  ///< RFC 7983 ZRTP range; reserved and rejected by LSP version 1.
    dtls,  ///< DTLS record range.
    turn_channel,  ///< RFC 7983 TURN ChannelData range; reserved and rejected by LSP version 1.
    rtp_or_rtcp,  ///< RTP or RTCP range, protected as SRTP or SRTCP by LSP.
  };

  /**
   * @brief Classify a complete UDP datagram according to RFC 7983 first-byte ranges.
   *
   * @param datagram Datagram bytes.
   * @return The classified protocol range, or `packet_class::invalid` for an empty or unassigned datagram.
   */
  [[nodiscard]] constexpr packet_class classify_packet(const std::span<const std::uint8_t> datagram) noexcept {
    if (datagram.empty()) {
      return packet_class::invalid;
    }
    const auto first = datagram.front();
    if (first <= 3U) {
      return packet_class::stun;
    }
    if (first >= 16U && first <= 19U) {
      return packet_class::zrtp;
    }
    if (first >= 20U && first <= 63U) {
      return packet_class::dtls;
    }
    if (first >= 64U && first <= 79U) {
      return packet_class::turn_channel;
    }
    if (first >= 128U && first <= 191U) {
      return packet_class::rtp_or_rtcp;
    }
    return packet_class::invalid;
  }

  /**
   * @brief Fixed-capacity, contiguous packet storage suitable for in-place protocol processing.
   *
   * @tparam Capacity Maximum packet bytes.
   */
  template<std::size_t Capacity>
  class packet_slab {
  public:
    static_assert(Capacity > 0, "packet slabs require nonzero capacity");

    /** @brief Maximum number of bytes retained by this slab. */
    static constexpr std::size_t capacity = Capacity;

    /**
     * @brief Return the number of initialized packet bytes.
     *
     * @return Current packet size.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

    /**
     * @brief Return whether no packet bytes are initialized.
     *
     * @return `true` when the slab is empty.
     */
    [[nodiscard]] constexpr bool empty() const noexcept {
      return size_ == 0;
    }

    /**
     * @brief Resize the initialized packet region without allocating.
     *
     * Newly exposed bytes are zero-initialized.
     *
     * @param new_size Requested initialized size.
     * @return `true` when the requested size fits.
     */
    constexpr bool resize(const std::size_t new_size) noexcept {
      if (new_size > Capacity) {
        return false;
      }
      for (auto index = size_; index < new_size; ++index) {
        storage_[index] = 0;
      }
      size_ = new_size;
      return true;
    }

    /**
     * @brief Replace the packet with the supplied bytes.
     *
     * @param bytes Source bytes.
     * @return `true` when all source bytes fit.
     */
    constexpr bool assign(const std::span<const std::uint8_t> bytes) noexcept {
      if (bytes.size() > Capacity) {
        return false;
      }
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        storage_[index] = bytes[index];
      }
      size_ = bytes.size();
      return true;
    }

    /**
     * @brief Append bytes to the initialized packet region.
     *
     * @param bytes Source bytes.
     * @return `true` when all source bytes fit.
     */
    constexpr bool append(const std::span<const std::uint8_t> bytes) noexcept {
      if (bytes.size() > Capacity - size_) {
        return false;
      }
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        storage_[size_ + index] = bytes[index];
      }
      size_ += bytes.size();
      return true;
    }

    /** @brief Discard all initialized bytes without modifying capacity. */
    constexpr void clear() noexcept {
      size_ = 0;
    }

    /**
     * @brief Return initialized mutable packet bytes.
     *
     * @return Mutable span over the current packet.
     */
    [[nodiscard]] constexpr std::span<std::uint8_t> bytes() noexcept {
      return {storage_.data(), size_};
    }

    /**
     * @brief Return initialized immutable packet bytes.
     *
     * @return Immutable span over the current packet.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> bytes() const noexcept {
      return {storage_.data(), size_};
    }

    /**
     * @brief Return writable unused capacity.
     *
     * Call `resize()` after populating the returned region to publish the new bytes.
     *
     * @return Mutable span over the unused tail.
     */
    [[nodiscard]] constexpr std::span<std::uint8_t> writable_tail() noexcept {
      return {storage_.data() + size_, Capacity - size_};
    }

  private:
    std::array<std::uint8_t, Capacity> storage_ {};  ///< Inline packet bytes.
    std::size_t size_ = 0;  ///< Number of initialized bytes.
  };

  /**
   * @brief Fixed-capacity FIFO queue with no dynamic allocation.
   *
   * The queue is intentionally synchronization-free and is expected to be owned by one worker
   * or wrapped by the platform's chosen single-producer/single-consumer synchronization.
   *
   * @tparam Value Stored value type.
   * @tparam Capacity Maximum number of values.
   */
  template<class Value, std::size_t Capacity>
  class bounded_queue {
  public:
    static_assert(Capacity > 0, "bounded queues require nonzero capacity");
    static_assert(std::is_default_constructible_v<Value>, "bounded queue values must be default constructible");

    /**
     * @brief Return the number of queued values.
     *
     * @return Current queue size.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

    /**
     * @brief Return whether the queue is empty.
     *
     * @return `true` when no values are queued.
     */
    [[nodiscard]] constexpr bool empty() const noexcept {
      return size_ == 0;
    }

    /**
     * @brief Return whether the queue is at capacity.
     *
     * @return `true` when another value cannot be accepted.
     */
    [[nodiscard]] constexpr bool full() const noexcept {
      return size_ == Capacity;
    }

    /**
     * @brief Copy a value onto the queue.
     *
     * @param value Value to enqueue.
     * @return `true` when the value was accepted.
     */
    constexpr bool try_push(const Value &value) noexcept(std::is_nothrow_copy_assignable_v<Value>) {
      if (full()) {
        return false;
      }
      values_[tail_] = value;
      advance_tail();
      return true;
    }

    /**
     * @brief Move a value onto the queue.
     *
     * @param value Value to enqueue.
     * @return `true` when the value was accepted.
     */
    constexpr bool try_push(Value &&value) noexcept(std::is_nothrow_move_assignable_v<Value>) {
      if (full()) {
        return false;
      }
      values_[tail_] = std::move(value);
      advance_tail();
      return true;
    }

    /**
     * @brief Move the oldest value out of the queue.
     *
     * @param output Destination for the oldest value.
     * @return `true` when a value was available.
     */
    constexpr bool try_pop(Value &output) noexcept(std::is_nothrow_move_assignable_v<Value>) {
      if (empty()) {
        return false;
      }
      output = std::move(values_[head_]);
      head_ = (head_ + 1U) % Capacity;
      --size_;
      return true;
    }

    /**
     * @brief Return the oldest queued value without removing it.
     *
     * @return Pointer to the oldest value, or `nullptr` when empty.
     */
    [[nodiscard]] constexpr Value *front() noexcept {
      return empty() ? nullptr : &values_[head_];
    }

    /**
     * @brief Return the oldest queued value without removing it.
     *
     * @return Pointer to the oldest value, or `nullptr` when empty.
     */
    [[nodiscard]] constexpr const Value *front() const noexcept {
      return empty() ? nullptr : &values_[head_];
    }

    /** @brief Discard all queued values. */
    constexpr void clear() noexcept {
      head_ = 0;
      tail_ = 0;
      size_ = 0;
    }

  private:
    /** @brief Publish one value written at the current tail. */
    constexpr void advance_tail() noexcept {
      tail_ = (tail_ + 1U) % Capacity;
      ++size_;
    }

    std::array<Value, Capacity> values_ {};  ///< Inline queue storage.
    std::size_t head_ = 0;  ///< Index of the oldest value.
    std::size_t tail_ = 0;  ///< Index at which the next value is written.
    std::size_t size_ = 0;  ///< Number of queued values.
  };
}  // namespace lumen::lsp
