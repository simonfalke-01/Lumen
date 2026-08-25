/**
 * @file src/platform/macos/publish.cpp
 * @brief Definitions for publishing services on macOS.
 */
// standard includes
#include <thread>
#include <vector>

// platform includes
#include <dns_sd.h>

// local includes
#include "src/logging.h"
#include "src/network.h"
#include "src/nvhttp.h"
#include "src/platform/common.h"

using namespace std::literals;

namespace platf::publish {
  namespace {
    /** @brief Custom deleter intended to be used for `std::unique_ptr<DNSServiceRef>`. */
    struct ServiceRefDeleter {
      typedef DNSServiceRef pointer;  ///< Type of object to be deleted.

      void operator()(pointer serviceRef) {
        DNSServiceRefDeallocate(serviceRef);
        BOOST_LOG(info) << "Deregistered DNS service."sv;
      }
    };

    using service_ref_t = std::unique_ptr<DNSServiceRef, ServiceRefDeleter>;

    /** @brief Poll and own the configured legacy/modern DNS-SD registrations together. */
    class deinit_t: public ::platf::deinit_t {
    public:
      explicit deinit_t(std::vector<DNSServiceRef> service_refs) {
        std::vector<DNSServiceRef> raw_refs;
        raw_refs.reserve(service_refs.size());
        service_refs_.reserve(service_refs.size());
        for (const auto service_ref : service_refs) {
          raw_refs.push_back(service_ref);
          service_refs_.emplace_back(service_ref);
        }
        thread_ = std::jthread {[raw_refs = std::move(raw_refs), &stop_requested = std::as_const(stop_requested_)]() {
          platf::set_thread_name("publish::mdns");
          while (!stop_requested) {
            auto fdset = fd_set {};
            FD_ZERO(&fdset);
            auto maximum_socket = -1;
            for (const auto service_ref : raw_refs) {
              const auto socket = DNSServiceRefSockFD(service_ref);
              if (socket >= 0) {
                FD_SET(socket, &fdset);
                maximum_socket = std::max(maximum_socket, socket);
              }
            }
            auto timeout = timeval {.tv_sec = 3, .tv_usec = 0};  // 3 second timeout
            const auto ready = select(maximum_socket + 1, &fdset, nullptr, nullptr, &timeout);
            if (ready == -1) {
              BOOST_LOG(error) << "Failed to obtain response from DNS service."sv;
              break;
            } else if (ready != 0) {
              for (const auto service_ref : raw_refs) {
                const auto socket = DNSServiceRefSockFD(service_ref);
                if (socket >= 0 && FD_ISSET(socket, &fdset)) {
                  static_cast<void>(DNSServiceProcessResult(service_ref));
                }
              }
            }
          }
        }};
      }

      /** @brief Ensure that we gracefully finish polling the mDNS service before freeing our
       *         connection to it.
       */
      ~deinit_t() override {
        stop_requested_ = true;
        thread_.join();
      }

      deinit_t(const deinit_t &) = delete;
      deinit_t &operator=(const deinit_t &) = delete;

    private:
      std::vector<service_ref_t> service_refs_;  ///< Owned registrations deallocated after polling stops.
      std::jthread thread_;  ///< Thread for polling mDNS registration responses.
      std::atomic<bool> stop_requested_ = false;  ///< Whether to stop polling.
    };

    std::vector<std::uint8_t> encode_txt(const service_t &service) {
      std::vector<std::uint8_t> encoded;
      for (const auto &[key, value] : service.txt) {
        const auto entry = key + '=' + value;
        if (entry.size() > 255) {
          return {};
        }
        encoded.push_back(static_cast<std::uint8_t>(entry.size()));
        encoded.insert(encoded.end(), entry.begin(), entry.end());
      }
      return encoded;
    }

    /** @brief Callback that will be invoked when the mDNS service finishes registering our service.
     *  @param errorCode Describes whether the registration was successful.
     */
    void registrationCallback(DNSServiceRef /*serviceRef*/, DNSServiceFlags /*flags*/, DNSServiceErrorType errorCode, const char * /*name*/, const char * /*regtype*/, const char * /*domain*/, void * /*context*/) {
      if (errorCode != kDNSServiceErr_NoError) {
        BOOST_LOG(error) << "Failed to register DNS service: Error "sv << errorCode;
        return;
      }
      BOOST_LOG(info) << "Successfully registered DNS service."sv;
    }
  }  // anonymous namespace

  /**
   * @brief Main entry point for publication of our service on macOS.
   *
   * This function initiates a connection to the macOS mDNS service and requests to register
   * our Sunshine service. Registration will occur asynchronously (unless it fails immediately,
   * which is probably only possible if the host machine is misconfigured).
   *
   * @return Either `nullptr` (if the registration fails immediately) or a `uniqur_ptr<deinit_t>`,
   *         which will manage polling for a response from the mDNS service, and then, when
   *         deconstructed, will deregister the service.
   */
  [[nodiscard]] std::unique_ptr<::platf::deinit_t> start() {
    std::vector<service_t> services;
    services.push_back({
      .type = platf::SERVICE_TYPE,
      .port = net::map_port(nvhttp::PORT_HTTP),
    });
    return start(std::move(services));
  }

  [[nodiscard]] std::unique_ptr<::platf::deinit_t> start(std::vector<service_t> services) {
    if (!valid_services(services)) {
      BOOST_LOG(error) << "Refusing invalid Lumen mDNS service set"sv;
      return nullptr;
    }
    std::vector<DNSServiceRef> service_refs;
    service_refs.reserve(services.size());
    for (const auto &service : services) {
      auto service_ref = DNSServiceRef {};
      const auto txt = encode_txt(service);
      const auto status = DNSServiceRegister(
        &service_ref,
        0,
        0,
        nullptr,
        service.type.c_str(),
        nullptr,
        nullptr,
        htons(service.port),
        static_cast<std::uint16_t>(txt.size()),
        txt.empty() ? nullptr : txt.data(),
        registrationCallback,
        nullptr
      );
      if (status != kDNSServiceErr_NoError) {
        BOOST_LOG(error) << "Failed immediately to register "sv << service.type << ": Error "sv << status;
        for (const auto registered : service_refs) {
          DNSServiceRefDeallocate(registered);
        }
        return nullptr;
      }
      service_refs.push_back(service_ref);
    }
    return std::make_unique<deinit_t>(std::move(service_refs));
  }
}  // namespace platf::publish
