/**
 * @file src/protocol_lsp/security/wolfssl_process.h
 * @brief Process-wide wolfSSL initialization for LSP crypto users.
 */

#pragma once

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

namespace lumen::lsp {
  /**
   * @brief Initialize wolfSSL and wolfCrypt once before any process-local crypto object is created.
   *
   * The guard is constructed before the first LSP crypto object and registered for cleanup at
   * process exit, after subsequently constructed providers and sessions have been destroyed.
   *
   * @return True when wolfSSL process initialization succeeded.
   */
  [[nodiscard]] inline bool initialize_wolfssl_process() noexcept {
    class ProcessGuard {
    public:
      ProcessGuard() noexcept:
          initialized_ {wolfSSL_Init() == WOLFSSL_SUCCESS} {
      }

      ~ProcessGuard() {
        if (initialized_) {
          wolfSSL_Cleanup();
        }
      }

      /** @brief Process guards are unique and cannot be copied. */
      ProcessGuard(const ProcessGuard &) = delete;

      /** @brief Process guards are unique and cannot be assigned. */
      ProcessGuard &operator=(const ProcessGuard &) = delete;

      /**
       * @brief Report whether process initialization succeeded.
       *
       * @return True when wolfSSL and wolfCrypt globals are ready.
       */
      [[nodiscard]] bool initialized() const noexcept {
        return initialized_;
      }

    private:
      bool initialized_ {};  ///< Whether process-exit cleanup is required.
    };

    static ProcessGuard process_guard;
    return process_guard.initialized();
  }
}  // namespace lumen::lsp
