/**
 * @file src/platform/windows/clipboard.cpp
 * @brief Windows clipboard bridge for LSP clipboard sharing.
 *
 * Lumen runs as SYSTEM, which cannot reliably read clipboard data owned by
 * user applications, so every clipboard access happens in `lumen-clipboard.exe`
 * started with the interactive user's token. This bridge owns that helper and
 * exchanges length-prefixed clipboard bundles with it over pipes.
 */
// standard includes
#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// platform includes
#include <Windows.h>
#include <userenv.h>

// local includes
#include "src/logging.h"
#include "src/platform/common.h"

using namespace std::literals;

namespace platf {
  HANDLE retrieve_users_token(bool elevated);

  namespace {
    constexpr std::size_t maximum_bundle_bytes = 16U * 1'024U * 1'024U;

    /** @brief Return the helper path next to the running Lumen executable. */
    std::wstring helper_path() {
      std::array<wchar_t, MAX_PATH> module {};
      const auto length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
      std::wstring path {module.data(), length};
      const auto separator = path.find_last_of(L"\\/");
      path.resize(separator == std::wstring::npos ? 0 : separator + 1U);
      return path + L"tools\\lumen-clipboard.exe";
    }

    bool read_exact(const HANDLE pipe, std::uint8_t *data, const std::size_t size) {
      std::size_t offset = 0;
      while (offset < size) {
        DWORD read = 0;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(size - offset, 1U << 20U));
        if (!ReadFile(pipe, data + offset, chunk, &read, nullptr) || read == 0) {
          return false;
        }
        offset += read;
      }
      return true;
    }

    bool write_exact(const HANDLE pipe, const std::uint8_t *data, const std::size_t size) {
      std::size_t offset = 0;
      while (offset < size) {
        DWORD written = 0;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(size - offset, 1U << 20U));
        if (!WriteFile(pipe, data + offset, chunk, &written, nullptr) || written == 0) {
          return false;
        }
        offset += written;
      }
      return true;
    }

    class windows_clipboard_t: public clipboard_t {
    public:
      ~windows_clipboard_t() override {
        {
          std::scoped_lock lock(mutex_);
          stopping_ = true;
        }
        write_condition_.notify_all();
        if (writer_.joinable()) {
          writer_.join();
        }
        // Closing the helper's stdin ends its message loop.
        close(stdin_write_);
        if (process_ != nullptr && WaitForSingleObject(process_, 2'000) == WAIT_TIMEOUT) {
          TerminateProcess(process_, 0);
          WaitForSingleObject(process_, 2'000);
        }
        if (reader_.joinable()) {
          reader_.join();
        }
        close(stdout_read_);
        close(process_);
      }

      /** @brief Start the helper in the interactive user's session. */
      bool start() {
        const auto token = retrieve_users_token(false);
        if (token == nullptr) {
          BOOST_LOG(warning) << "Clipboard sharing unavailable: no interactive user session"sv;
          return false;
        }
        HANDLE child_stdin = nullptr;
        HANDLE child_stdout = nullptr;
        SECURITY_ATTRIBUTES inheritable {.nLength = sizeof(SECURITY_ATTRIBUTES), .bInheritHandle = TRUE};
        bool started = false;
        LPVOID environment = nullptr;
        std::vector<std::uint8_t> attribute_storage;
        do {
          if (!CreatePipe(&child_stdin, &stdin_write_, &inheritable, 0) ||
              !SetHandleInformation(stdin_write_, HANDLE_FLAG_INHERIT, 0) ||
              !CreatePipe(&stdout_read_, &child_stdout, &inheritable, 0) ||
              !SetHandleInformation(stdout_read_, HANDLE_FLAG_INHERIT, 0)) {
            BOOST_LOG(warning) << "Clipboard sharing unavailable: helper pipes failed ["sv << GetLastError() << ']';
            break;
          }
          // Only the two pipe ends may cross from SYSTEM into the user's process.
          SIZE_T attribute_size = 0;
          InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
          attribute_storage.resize(attribute_size);
          auto *attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
          std::array<HANDLE, 2> inherited {child_stdin, child_stdout};
          if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size)) {
            BOOST_LOG(warning) << "Clipboard sharing unavailable: helper attributes failed ["sv << GetLastError() << ']';
            break;
          }
          if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited), nullptr, nullptr)) {
            BOOST_LOG(warning) << "Clipboard sharing unavailable: helper handle list failed ["sv << GetLastError() << ']';
            DeleteProcThreadAttributeList(attributes);
            break;
          }
          STARTUPINFOEXW startup {};
          startup.StartupInfo.cb = sizeof(startup);
          startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
          startup.StartupInfo.hStdInput = child_stdin;
          startup.StartupInfo.hStdOutput = child_stdout;
          startup.StartupInfo.hStdError = nullptr;
          startup.StartupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
          startup.lpAttributeList = attributes;
          if (!CreateEnvironmentBlock(&environment, token, FALSE)) {
            environment = nullptr;
          }
          const auto path = helper_path();
          std::wstring command = L"\"" + path + L"\"";
          PROCESS_INFORMATION process {};
          const auto created = CreateProcessAsUserW(
            token,
            path.c_str(),
            command.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment,
            nullptr,
            &startup.StartupInfo,
            &process
          );
          const auto error = GetLastError();
          DeleteProcThreadAttributeList(attributes);
          if (!created) {
            BOOST_LOG(warning) << "Clipboard sharing unavailable: helper launch failed ["sv << error << ']';
            break;
          }
          CloseHandle(process.hThread);
          process_ = process.hProcess;
          started = true;
        } while (false);
        if (environment != nullptr) {
          DestroyEnvironmentBlock(environment);
        }
        close(child_stdin);
        close(child_stdout);
        CloseHandle(token);
        if (!started) {
          return false;
        }
        BOOST_LOG(info) << "Clipboard sharing: started the user-session clipboard helper"sv;
        reader_ = std::thread([this]() {
          read_loop();
        });
        writer_ = std::thread([this]() {
          write_loop();
        });
        return true;
      }

      void set_content(std::vector<std::uint8_t> bundle) override {
        {
          std::scoped_lock lock(mutex_);
          pending_write_ = std::move(bundle);
        }
        write_condition_.notify_all();
      }

      std::optional<std::vector<std::uint8_t>> take_change() override {
        std::scoped_lock lock(mutex_);
        return std::exchange(change_, std::nullopt);
      }

      [[nodiscard]] bool running() const noexcept override {
        std::scoped_lock lock(mutex_);
        return !helper_exited_;
      }

    private:
      static void close(HANDLE &handle) noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
          CloseHandle(handle);
        }
        handle = nullptr;
      }

      void read_loop() {
        while (true) {
          std::uint8_t header[4];
          if (!read_exact(stdout_read_, header, sizeof(header))) {
            break;
          }
          const std::size_t size = std::size_t {header[0]} | (std::size_t {header[1]} << 8U) |
                                   (std::size_t {header[2]} << 16U) | (std::size_t {header[3]} << 24U);
          if (size == 0 || size > maximum_bundle_bytes) {
            BOOST_LOG(warning) << "Clipboard sharing: helper sent an invalid frame of "sv << size << " bytes"sv;
            break;
          }
          std::vector<std::uint8_t> bundle(size);
          if (!read_exact(stdout_read_, bundle.data(), size)) {
            break;
          }
          BOOST_LOG(info) << "Clipboard sharing: host clipboard changed ("sv << size << " bytes)"sv;
          std::scoped_lock lock(mutex_);
          change_ = std::move(bundle);
        }
        std::scoped_lock lock(mutex_);
        helper_exited_ = true;
        if (!stopping_) {
          BOOST_LOG(warning) << "Clipboard sharing: the clipboard helper exited"sv;
        }
      }

      void write_loop() {
        while (true) {
          std::vector<std::uint8_t> bundle;
          {
            std::unique_lock lock(mutex_);
            write_condition_.wait(lock, [this]() {
              return stopping_ || pending_write_.has_value();
            });
            if (stopping_) {
              return;
            }
            bundle = std::move(*pending_write_);
            pending_write_.reset();
          }
          const auto size = static_cast<std::uint32_t>(bundle.size());
          const std::uint8_t header[4] = {
            static_cast<std::uint8_t>(size),
            static_cast<std::uint8_t>(size >> 8U),
            static_cast<std::uint8_t>(size >> 16U),
            static_cast<std::uint8_t>(size >> 24U),
          };
          if (!write_exact(stdin_write_, header, sizeof(header)) || !write_exact(stdin_write_, bundle.data(), bundle.size())) {
            BOOST_LOG(warning) << "Clipboard sharing: could not write to the clipboard helper ["sv << GetLastError() << ']';
            return;
          }
        }
      }

      mutable std::mutex mutex_;
      std::condition_variable write_condition_;
      bool stopping_ {};
      bool helper_exited_ {};
      std::optional<std::vector<std::uint8_t>> pending_write_;  ///< Newest client bundle awaiting the helper.
      std::optional<std::vector<std::uint8_t>> change_;  ///< Newest host bundle awaiting the LSP runtime.
      HANDLE process_ {};
      HANDLE stdin_write_ {};
      HANDLE stdout_read_ {};
      std::thread reader_;
      std::thread writer_;
    };
  }  // namespace

  std::unique_ptr<clipboard_t> clipboard() {
    auto bridge = std::make_unique<windows_clipboard_t>();
    if (!bridge->start()) {
      return nullptr;
    }
    return bridge;
  }
}  // namespace platf
