/**
 * @file src/platform/windows/wasapi_virtual_microphone.cpp
 * @brief Event-driven WASAPI fallback for existing virtual microphone cables.
 */

// local includes
#include "wasapi_virtual_microphone.h"

#include "src/logging.h"

// platform includes
#include <Audioclient.h>
#include <ksmedia.h>
#include <Mmdeviceapi.h>
#include <Propsys.h>
#include <Windows.h>

// Declares the undocumented endpoint format policy interface; keep after the platform headers.
#include "PolicyConfig.h"

// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

using namespace std::literals;

namespace platf::win_audio {
  namespace {
    constexpr std::uint32_t SOURCE_SAMPLE_RATE = 48000;  ///< Client microphone source rate.
    constexpr std::uint32_t MAX_ENDPOINT_SAMPLE_RATE = 192000;  ///< Conversion allocation bound.
    constexpr std::uint16_t MAX_ENDPOINT_CHANNELS = 32;  ///< Conversion allocation bound.
    constexpr auto RING_DURATION = 80ms;  ///< Maximum decoded audio queued ahead of WASAPI.
    constexpr auto START_TIMEOUT = 3s;  ///< Bound for COM and endpoint startup.

    constexpr PROPERTYKEY DEVICE_FRIENDLY_NAME_KEY {
      {0xa45c254e, 0xdf1c, 0x4efd, {0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}},
      14,
    };  ///< Local value of PKEY_Device_FriendlyName without a new library dependency.
    constexpr PROPERTYKEY DEVICE_INTERFACE_FRIENDLY_NAME_KEY {
      {0x026e516e, 0xb814, 0x414b, {0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22}},
      2,
    };  ///< Local value of PKEY_DeviceInterface_FriendlyName without a new library dependency.
    constexpr PROPERTYKEY DEVICE_CONTAINER_ID_KEY {
      {0x8c7ed206, 0x3f8a, 0x4827, {0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c}},
      2,
    };  ///< Local value of PKEY_Device_ContainerId without a new library dependency.
    constexpr PROPERTYKEY AUDIO_ENGINE_DEVICE_FORMAT_KEY {
      {0xf19f064d, 0x082c, 0x4e27, {0xbc, 0x73, 0x68, 0x82, 0xa1, 0xbb, 0x8e, 0x4c}},
      0,
    };  ///< Local value of PKEY_AudioEngine_DeviceFormat without a new library dependency.

    constexpr auto STEAM_STREAMING_MICROPHONE_ADAPTER = L"Steam Streaming Microphone"sv;  ///< Stable nonlocalized adapter name.
    constexpr auto VB_CABLE_ADAPTER = L"VB-Audio Virtual Cable"sv;  ///< Stable nonlocalized adapter name.

    /**
     * @brief MTA lifetime that outlives every subsequently constructed COM pointer in its scope.
     */
    class com_apartment_t {
    public:
      /** @brief Enter a multithreaded COM apartment. */
      com_apartment_t() noexcept:
          result_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {
      }

      /** @brief Leave the apartment after later-declared COM objects have been destroyed. */
      ~com_apartment_t() {
        if (SUCCEEDED(result_)) {
          CoUninitialize();
        }
      }

      com_apartment_t(const com_apartment_t &) = delete;
      com_apartment_t &operator=(const com_apartment_t &) = delete;
      com_apartment_t(com_apartment_t &&) = delete;
      com_apartment_t &operator=(com_apartment_t &&) = delete;

      /**
       * @brief Test whether apartment initialization succeeded.
       * @return `true` when COM calls are permitted.
       */
      explicit operator bool() const noexcept {
        return SUCCEEDED(result_);
      }

    private:
      HRESULT result_;  ///< Apartment initialization result.
    };

    /**
     * @brief Minimal owning COM interface pointer.
     * @tparam T COM interface type.
     */
    template<class T>
    class com_ptr_t {
    public:
      /** @brief Construct an empty pointer. */
      com_ptr_t() = default;

      /**
       * @brief Adopt one interface reference.
       * @param value Owned interface reference.
       */
      explicit com_ptr_t(T *value) noexcept:
          value_(value) {
      }

      /** @brief Release an owned reference. */
      ~com_ptr_t() {
        reset();
      }

      com_ptr_t(const com_ptr_t &) = delete;
      com_ptr_t &operator=(const com_ptr_t &) = delete;

      /**
       * @brief Move an owned reference.
       * @param other Source pointer.
       */
      com_ptr_t(com_ptr_t &&other) noexcept:
          value_(std::exchange(other.value_, nullptr)) {
      }

      /**
       * @brief Move-assign an owned reference.
       * @param other Source pointer.
       * @return This pointer.
       */
      com_ptr_t &operator=(com_ptr_t &&other) noexcept {
        if (this != &other) {
          reset(std::exchange(other.value_, nullptr));
        }
        return *this;
      }

      /**
       * @brief Return the raw interface pointer.
       * @return Borrowed interface pointer.
       */
      [[nodiscard]] T *get() const noexcept {
        return value_;
      }

      /**
       * @brief Return a receive location after releasing an old reference.
       * @return Address for one COM output pointer.
       */
      T **put() noexcept {
        reset();
        return &value_;
      }

      /**
       * @brief Test whether a reference is owned.
       * @return `true` when non-null.
       */
      explicit operator bool() const noexcept {
        return value_ != nullptr;
      }

      /**
       * @brief Access the interface.
       * @return Borrowed interface pointer.
       */
      T *operator->() const noexcept {
        return value_;
      }

      /**
       * @brief Replace the owned reference.
       * @param value New owned reference.
       */
      void reset(T *value = nullptr) noexcept {
        if (value_) {
          value_->Release();
        }
        value_ = value;
      }

    private:
      T *value_ {};  ///< Owned interface reference.
    };

    /**
     * @brief Owning storage returned by GetMixFormat.
     */
    class mix_format_owner_t {
    public:
      /** @brief Free COM task memory. */
      ~mix_format_owner_t() {
        if (value_) {
          CoTaskMemFree(value_);
        }
      }

      mix_format_owner_t(const mix_format_owner_t &) = delete;
      mix_format_owner_t &operator=(const mix_format_owner_t &) = delete;
      mix_format_owner_t(mix_format_owner_t &&) = delete;
      mix_format_owner_t &operator=(mix_format_owner_t &&) = delete;

      /** @brief Construct empty storage. */
      mix_format_owner_t() = default;

      /** @brief Return a receive location. */
      WAVEFORMATEX **put() noexcept {
        return &value_;
      }

      /** @brief Return the owned format. */
      [[nodiscard]] WAVEFORMATEX *get() const noexcept {
        return value_;
      }

    private:
      WAVEFORMATEX *value_ {};  ///< COM-allocated mix format.
    };

    /**
     * @brief One exact selected render endpoint and its validated format.
     */
    struct endpoint_selection_t {
      com_ptr_t<IMMDevice> render_device;  ///< Exact active render endpoint.
      std::wstring render_name;  ///< Friendly name used for diagnostics.
      wasapi_mix_format_t mix_format;  ///< Parsed supported mix format.
    };

    /**
     * @brief Convert one HRESULT into a stable unsigned status for logging.
     * @param result HRESULT value.
     * @return Unsigned status bits.
     */
    [[nodiscard]] std::uint32_t status_bits(HRESULT result) noexcept {
      return static_cast<std::uint32_t>(result);
    }

    /**
     * @brief Read one exact string property.
     * @param properties Open endpoint property store.
     * @param key Property key.
     * @return String value on success.
     */
    [[nodiscard]] std::optional<std::wstring> string_property(IPropertyStore &properties, const PROPERTYKEY &key) {
      PROPVARIANT value {};
      const auto result = properties.GetValue(key, &value);
      if (FAILED(result)) {
        PropVariantClear(&value);
        return std::nullopt;
      }

      std::optional<std::wstring> name;
      if (value.vt == VT_LPWSTR && value.pwszVal) {
        name.emplace(value.pwszVal);
      }
      PropVariantClear(&value);
      return name;
    }

    /**
     * @brief Read one exact GUID property.
     * @param properties Open endpoint property store.
     * @param key Property key.
     * @return GUID value on success.
     */
    [[nodiscard]] std::optional<GUID> guid_property(IPropertyStore &properties, const PROPERTYKEY &key) {
      PROPVARIANT value {};
      const auto result = properties.GetValue(key, &value);
      if (FAILED(result)) {
        PropVariantClear(&value);
        return std::nullopt;
      }

      std::optional<GUID> guid;
      if (value.vt == VT_CLSID && value.puuid) {
        guid = *value.puuid;
      }
      PropVariantClear(&value);
      return guid;
    }

    /**
     * @brief Read the stable identity fields required to authorize one endpoint.
     * @param device Endpoint device.
     * @return Complete identity on success.
     */
    [[nodiscard]] std::optional<wasapi_endpoint_identity_t> endpoint_identity(IMMDevice &device) {
      LPWSTR raw_device_id = nullptr;
      if (FAILED(device.GetId(&raw_device_id)) || !raw_device_id) {
        CoTaskMemFree(raw_device_id);
        return std::nullopt;
      }
      std::wstring device_id {raw_device_id};
      CoTaskMemFree(raw_device_id);

      com_ptr_t<IPropertyStore> properties;
      if (FAILED(device.OpenPropertyStore(STGM_READ, properties.put()))) {
        return std::nullopt;
      }
      const auto adapter_name = string_property(*properties.get(), DEVICE_INTERFACE_FRIENDLY_NAME_KEY);
      const auto container_id = guid_property(*properties.get(), DEVICE_CONTAINER_ID_KEY);
      if (!adapter_name || !container_id) {
        return std::nullopt;
      }
      auto friendly_name = string_property(*properties.get(), DEVICE_FRIENDLY_NAME_KEY);
      return wasapi_endpoint_identity_t {
        std::move(device_id),
        friendly_name ? std::move(*friendly_name) : std::wstring {},
        *adapter_name,
        *container_id,
      };
    }

    /**
     * @brief Enumerate active endpoint identities for one data flow.
     * @param enumerator MMDevice enumerator.
     * @param flow Render or capture flow.
     * @return Every complete stable identity successfully read.
     */
    [[nodiscard]] std::vector<wasapi_endpoint_identity_t> enumerate_endpoint_identities(
      IMMDeviceEnumerator &enumerator,
      EDataFlow flow
    ) {
      com_ptr_t<IMMDeviceCollection> collection;
      if (FAILED(enumerator.EnumAudioEndpoints(flow, DEVICE_STATE_ACTIVE, collection.put()))) {
        return {};
      }

      UINT count = 0;
      if (FAILED(collection->GetCount(&count))) {
        return {};
      }

      std::vector<wasapi_endpoint_identity_t> identities;
      identities.reserve(count);
      for (UINT index = 0; index < count; ++index) {
        com_ptr_t<IMMDevice> device;
        if (SUCCEEDED(collection->Item(index, device.put()))) {
          if (auto identity = endpoint_identity(*device.get())) {
            identities.emplace_back(std::move(*identity));
          }
        }
      }
      return identities;
    }

    /**
     * @brief Parse a WASAPI mix format accepted by the portable converter.
     * @param format Native mix format.
     * @return Validated portable format.
     */
    [[nodiscard]] std::optional<wasapi_mix_format_t> parse_mix_format(const WAVEFORMATEX &format) noexcept {
      if (format.nSamplesPerSec == 0 || format.nSamplesPerSec > MAX_ENDPOINT_SAMPLE_RATE ||
          format.nChannels == 0 || format.nChannels > MAX_ENDPOINT_CHANNELS ||
          format.nBlockAlign == 0) {
        return std::nullopt;
      }

      WORD tag = format.wFormatTag;
      WORD bits = format.wBitsPerSample;
      GUID subformat {};
      if (tag == WAVE_FORMAT_EXTENSIBLE) {
        if (format.cbSize < sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX)) {
          return std::nullopt;
        }
        const auto &extensible = reinterpret_cast<const WAVEFORMATEXTENSIBLE &>(format);
        subformat = extensible.SubFormat;
        tag = IsEqualGUID(subformat, KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) ? WAVE_FORMAT_IEEE_FLOAT :
              IsEqualGUID(subformat, KSDATAFORMAT_SUBTYPE_PCM)        ? WAVE_FORMAT_PCM :
                                                                        0;
        bits = extensible.Format.wBitsPerSample;
      }

      wasapi_sample_format_e sample_format;
      std::uint16_t bytes_per_sample = 0;
      if (tag == WAVE_FORMAT_IEEE_FLOAT && bits == 32) {
        sample_format = wasapi_sample_format_e::float_f32;
        bytes_per_sample = 4;
      } else if (tag == WAVE_FORMAT_PCM && bits == 16) {
        sample_format = wasapi_sample_format_e::pcm_s16;
        bytes_per_sample = 2;
      } else if (tag == WAVE_FORMAT_PCM && bits == 24) {
        sample_format = wasapi_sample_format_e::pcm_s24;
        bytes_per_sample = 3;
      } else if (tag == WAVE_FORMAT_PCM && bits == 32) {
        sample_format = wasapi_sample_format_e::pcm_s32;
        bytes_per_sample = 4;
      } else {
        return std::nullopt;
      }

      if (format.nBlockAlign != format.nChannels * bytes_per_sample) {
        return std::nullopt;
      }
      return wasapi_mix_format_t {
        format.nSamplesPerSec,
        format.nChannels,
        format.nBlockAlign,
        sample_format,
      };
    }

    /**
     * @brief Read the shared-mode engine format of one endpoint.
     * @param enumerator MMDevice enumerator.
     * @param device_id Exact endpoint identifier.
     * @return Copied device format on success.
     */
    [[nodiscard]] std::optional<WAVEFORMATEXTENSIBLE> endpoint_device_format(
      IMMDeviceEnumerator &enumerator,
      const std::wstring &device_id
    ) {
      com_ptr_t<IMMDevice> device;
      com_ptr_t<IPropertyStore> properties;
      if (FAILED(enumerator.GetDevice(device_id.c_str(), device.put())) ||
          FAILED(device->OpenPropertyStore(STGM_READ, properties.put()))) {
        return std::nullopt;
      }

      PROPVARIANT value {};
      if (FAILED(properties->GetValue(AUDIO_ENGINE_DEVICE_FORMAT_KEY, &value))) {
        PropVariantClear(&value);
        return std::nullopt;
      }
      std::optional<WAVEFORMATEXTENSIBLE> format;
      if (value.vt == VT_BLOB && value.blob.pBlobData && value.blob.cbSize >= sizeof(WAVEFORMATEX)) {
        WAVEFORMATEXTENSIBLE copy {};
        std::memcpy(&copy, value.blob.pBlobData, std::min<std::size_t>(value.blob.cbSize, sizeof(copy)));
        if (copy.Format.wFormatTag != WAVE_FORMAT_EXTENSIBLE) {
          copy.Format.cbSize = 0;
        }
        format = copy;
      }
      PropVariantClear(&value);
      return format;
    }

    /**
     * @brief Render a device format for diagnostics.
     * @param format Endpoint device format.
     * @return Compact rate/channel/bit description.
     */
    [[nodiscard]] std::string describe_format(const WAVEFORMATEXTENSIBLE &format) {
      return std::to_string(format.Format.nSamplesPerSec) + " Hz, " + std::to_string(format.Format.nChannels) +
             " ch, " + std::to_string(format.Format.wBitsPerSample) + "-bit";
    }

    /**
     * @brief Whether two endpoint device formats produce byte-identical PCM layouts.
     * @param left First format.
     * @param right Second format.
     * @return True when rate, channels, container, and sample type match.
     */
    [[nodiscard]] bool same_byte_layout(const WAVEFORMATEXTENSIBLE &left, const WAVEFORMATEXTENSIBLE &right) noexcept {
      const auto is_float = [](const WAVEFORMATEXTENSIBLE &format) {
        return format.Format.wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
               (format.Format.wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
                IsEqualGUID(format.SubFormat, KSDATAFORMAT_SUBTYPE_IEEE_FLOAT));
      };
      return left.Format.nSamplesPerSec == right.Format.nSamplesPerSec &&
             left.Format.nChannels == right.Format.nChannels &&
             left.Format.wBitsPerSample == right.Format.wBitsPerSample &&
             left.Format.nBlockAlign == right.Format.nBlockAlign && is_float(left) == is_float(right);
    }

    /**
     * @brief Default loopback cable format: 2 channel, 32-bit integer PCM, 48000 Hz.
     * @return Extensible format accepted by both Steam Streaming Microphone endpoints.
     */
    [[nodiscard]] WAVEFORMATEXTENSIBLE preferred_loopback_format() noexcept {
      WAVEFORMATEXTENSIBLE format {};
      format.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
      format.Format.nChannels = 2;
      format.Format.nSamplesPerSec = SOURCE_SAMPLE_RATE;
      format.Format.wBitsPerSample = 32;
      format.Format.nBlockAlign = 2 * sizeof(std::int32_t);
      format.Format.nAvgBytesPerSec = SOURCE_SAMPLE_RATE * format.Format.nBlockAlign;
      format.Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
      format.Samples.wValidBitsPerSample = 32;
      format.dwChannelMask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
      format.SubFormat = KSDATAFORMAT_SUBTYPE_PCM;
      return format;
    }

    /**
     * @brief Make a loopback cable's render and capture endpoints use one device format.
     *
     * Steam Streaming Microphone and VB-CABLE copy raw bytes from their render side to
     * their capture side without converting. When the two endpoint formats differ
     * (for example stereo render and mono capture), every sample is reinterpreted, which
     * plays the microphone at the wrong speed and pitch and starves or overruns the capture
     * side. Set both endpoints to one known-good format before the render stream is opened,
     * or at least make them match if the driver rejects it.
     *
     * @param enumerator MMDevice enumerator.
     * @param render_id Exact render endpoint identifier.
     * @param capture_id Exact paired capture endpoint identifier.
     */
    void align_loopback_formats(
      IMMDeviceEnumerator &enumerator,
      const std::wstring &render_id,
      const std::wstring &capture_id
    ) {
      const auto render_format = endpoint_device_format(enumerator, render_id);
      const auto capture_format = endpoint_device_format(enumerator, capture_id);
      if (!render_format || !capture_format) {
        BOOST_LOG(warning) << "Unable to read virtual microphone endpoint formats; microphone pitch may be wrong"sv;
        return;
      }
      const auto preferred = preferred_loopback_format();
      if (same_byte_layout(*render_format, preferred) && same_byte_layout(*capture_format, preferred)) {
        BOOST_LOG(info) << "Virtual microphone endpoints use "sv << describe_format(preferred);
        return;
      }

      BOOST_LOG(info) << "Virtual microphone endpoint formats are render "sv << describe_format(*render_format)
                      << ", capture "sv << describe_format(*capture_format) << "; setting both to "sv
                      << describe_format(preferred);

      com_ptr_t<IPolicyConfig> policy;
      if (FAILED(CoCreateInstance(
            CLSID_CPolicyConfigClient,
            nullptr,
            CLSCTX_ALL,
            IID_IPolicyConfig,
            reinterpret_cast<void **>(policy.put())
          ))) {
        BOOST_LOG(warning) << "Unable to open audio policy config; set both virtual microphone endpoints to the same format in Sound settings"sv;
        return;
      }

      // The policy API is undocumented; pass private copies only.
      auto try_set = [&](const std::wstring &device_id, WAVEFORMATEXTENSIBLE format) {
        auto id_copy = device_id;
        WAVEFORMATEXTENSIBLE mix_format {};
        return SUCCEEDED(policy->SetDeviceFormat(
          id_copy.c_str(),
          reinterpret_cast<WAVEFORMATEX *>(&format),
          reinterpret_cast<WAVEFORMATEX *>(&mix_format)
        ));
      };

      const auto render_ok = same_byte_layout(*render_format, preferred) || try_set(render_id, preferred);
      const auto capture_ok = same_byte_layout(*capture_format, preferred) || try_set(capture_id, preferred);
      if (render_ok && capture_ok) {
        BOOST_LOG(info) << "Set virtual microphone endpoints to "sv << describe_format(preferred);
        return;
      }

      // The driver rejected the preferred format on one side; at least make both sides match.
      const auto current_render = endpoint_device_format(enumerator, render_id);
      const auto current_capture = endpoint_device_format(enumerator, capture_id);
      if (current_render && current_capture) {
        if (same_byte_layout(*current_render, *current_capture)) {
          BOOST_LOG(info) << "Virtual microphone endpoints share format: "sv << describe_format(*current_capture);
          return;
        }
        if (try_set(capture_id, *current_render)) {
          BOOST_LOG(info) << "Set virtual microphone capture endpoint to "sv << describe_format(*current_render);
          return;
        }
        if (try_set(render_id, *current_capture)) {
          BOOST_LOG(info) << "Set virtual microphone render endpoint to "sv << describe_format(*current_capture);
          return;
        }
      }
      BOOST_LOG(warning) << "Unable to align virtual microphone endpoint formats; set both to 2 channel, 32 bit, 48000 Hz in Sound settings"sv;
    }

    /**
     * @brief Discover the configured complete exact endpoint pair and supported render format.
     * @param kind Configured destination kind.
     * @return Selected endpoint on success.
     */
    [[nodiscard]] std::optional<endpoint_selection_t> discover_endpoint(wasapi_virtual_microphone_kind_e kind) {
      com_ptr_t<IMMDeviceEnumerator> enumerator;
      auto result = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void **>(enumerator.put())
      );
      if (FAILED(result)) {
        return std::nullopt;
      }

      const auto render_endpoints = enumerate_endpoint_identities(*enumerator.get(), eRender);
      const auto capture_endpoints = enumerate_endpoint_identities(*enumerator.get(), eCapture);
      const auto *render = select_wasapi_virtual_microphone_endpoint(render_endpoints, capture_endpoints, kind);
      if (!render) {
        return std::nullopt;
      }

      const auto capture = std::ranges::find_if(capture_endpoints, [&](const wasapi_endpoint_identity_t &candidate) {
        return IsEqualGUID(candidate.container_id, render->container_id) &&
               candidate.adapter_name == render->adapter_name;
      });
      if (capture != capture_endpoints.end()) {
        align_loopback_formats(*enumerator.get(), render->device_id, capture->device_id);
      }

      com_ptr_t<IMMDevice> render_device;
      if (FAILED(enumerator->GetDevice(render->device_id.c_str(), render_device.put()))) {
        return std::nullopt;
      }

      com_ptr_t<IAudioClient> audio_client;
      result = render_device->Activate(
        __uuidof(IAudioClient),
        CLSCTX_INPROC_SERVER,
        nullptr,
        reinterpret_cast<void **>(audio_client.put())
      );
      if (FAILED(result)) {
        return std::nullopt;
      }

      mix_format_owner_t native_format;
      result = audio_client->GetMixFormat(native_format.put());
      if (FAILED(result) || !native_format.get()) {
        return std::nullopt;
      }
      const auto mix_format = parse_mix_format(*native_format.get());
      if (!mix_format) {
        return std::nullopt;
      }

      return endpoint_selection_t {std::move(render_device), render->friendly_name, *mix_format};
    }

    /**
     * @brief Store one little-endian converted sample in all endpoint channels.
     * @param sample Source signed-16 sample.
     * @param format Output format.
     * @param output Destination frame start.
     */
    void store_frame(std::int16_t sample, const wasapi_mix_format_t &format, std::byte *output) noexcept {
      for (std::uint16_t channel = 0; channel < format.channels; ++channel) {
        switch (format.sample_format) {
          case wasapi_sample_format_e::pcm_s16:
            {
              const auto value = static_cast<std::uint16_t>(sample);
              *output++ = static_cast<std::byte>(value & 0xffU);
              *output++ = static_cast<std::byte>((value >> 8U) & 0xffU);
              break;
            }
          case wasapi_sample_format_e::pcm_s24:
            {
              const auto value = static_cast<std::uint32_t>(static_cast<std::int32_t>(sample) * 256);
              *output++ = static_cast<std::byte>(value & 0xffU);
              *output++ = static_cast<std::byte>((value >> 8U) & 0xffU);
              *output++ = static_cast<std::byte>((value >> 16U) & 0xffU);
              break;
            }
          case wasapi_sample_format_e::pcm_s32:
            {
              const auto value = static_cast<std::uint32_t>(static_cast<std::int32_t>(sample) * 65536);
              *output++ = static_cast<std::byte>(value & 0xffU);
              *output++ = static_cast<std::byte>((value >> 8U) & 0xffU);
              *output++ = static_cast<std::byte>((value >> 16U) & 0xffU);
              *output++ = static_cast<std::byte>((value >> 24U) & 0xffU);
              break;
            }
          case wasapi_sample_format_e::float_f32:
            {
              const float value = static_cast<float>(sample) / 32768.0f;
              std::memcpy(output, &value, sizeof(value));
              output += sizeof(value);
              break;
            }
        }
      }
    }

    /**
     * @brief Real event-driven WASAPI render sink.
     */
    class wasapi_virtual_microphone_t final: public virtual_microphone_sink_t {
    public:
      /**
       * @brief Bind this sink to one exact configured destination.
       * @param kind Destination kind.
       */
      explicit wasapi_virtual_microphone_t(wasapi_virtual_microphone_kind_e kind) noexcept:
          kind_(kind) {
      }

      /** @brief Stop and join the render worker. */
      ~wasapi_virtual_microphone_t() override {
        stop_worker();
      }

      bool probe() override {
        bool available = false;
        std::thread probe_thread {[this, &available] {
          const com_apartment_t apartment;
          if (apartment) {
            available = discover_endpoint(kind_).has_value();
          }
        }};
        probe_thread.join();
        if (!available) {
          BOOST_LOG(warning) << "Configured client microphone destination is unavailable: "sv << destination_name()
                             << ". Enable its render and capture endpoints, or select another destination."sv;
        }
        return available;
      }

      bool begin(std::uint64_t generation, std::uint32_t sample_rate, std::uint8_t channels) override {
        if (generation == 0 || sample_rate != SOURCE_SAMPLE_RATE || channels != 1) {
          return false;
        }

        stop_worker();
        {
          std::lock_guard lock(mutex_);
          if (!generation_state_.begin(generation)) {
            return false;
          }
          startup_complete_ = false;
          startup_succeeded_ = false;
          stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
          audio_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
          if (!stop_event_ || !audio_event_) {
            generation_state_.fail();
            close_events_locked();
            return false;
          }
        }

        try {
          worker_ = std::thread {[this] {
            render_thread();
          }};
        } catch (...) {
          std::lock_guard lock(mutex_);
          generation_state_.fail();
          close_events_locked();
          return false;
        }

        std::unique_lock lock(mutex_);
        const auto started = startup_condition_.wait_for(lock, START_TIMEOUT, [this] {
          return startup_complete_;
        });
        const auto succeeded = started && startup_succeeded_;
        lock.unlock();
        if (!succeeded) {
          stop_worker();
        }
        return succeeded;
      }

      bool write(std::uint64_t generation, std::span<const std::int16_t> samples) override {
        std::lock_guard lock(mutex_);
        if (!generation_state_.accepts(generation) || !startup_succeeded_) {
          return false;
        }

        std::vector<std::byte> converted;
        try {
          converted = converter_.convert(samples);
        } catch (...) {
          fail_closed_locked();
          return false;
        }
        if (!ring_.push(converted)) {
          fail_closed_locked();
          return false;
        }
        return true;
      }

      void end(std::uint64_t generation) override {
        {
          std::lock_guard lock(mutex_);
          if (generation_state_.generation() != generation) {
            return;
          }
        }
        stop_worker();
        std::lock_guard lock(mutex_);
        static_cast<void>(generation_state_.end(generation));
      }

    private:
      /**
       * @brief Initialize and service the WASAPI client entirely on its owning MTA thread.
       */
      void render_thread() noexcept {
        const com_apartment_t apartment;
        if (!apartment) {
          report_startup(false);
          return;
        }

        auto endpoint = discover_endpoint(kind_);
        if (!endpoint) {
          BOOST_LOG(warning) << "Configured client microphone destination became unavailable: "sv << destination_name()
                             << ". Enable its render and capture endpoints, or select another destination."sv;
          report_startup(false);
          return;
        }

        com_ptr_t<IAudioClient> audio_client;
        auto result = endpoint->render_device->Activate(
          __uuidof(IAudioClient),
          CLSCTX_INPROC_SERVER,
          nullptr,
          reinterpret_cast<void **>(audio_client.put())
        );
        mix_format_owner_t native_format;
        if (SUCCEEDED(result)) {
          result = audio_client->GetMixFormat(native_format.put());
        }
        if (SUCCEEDED(result)) {
          result = audio_client->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_NOPERSIST,
            0,
            0,
            native_format.get(),
            nullptr
          );
        }
        if (SUCCEEDED(result)) {
          result = audio_client->SetEventHandle(audio_event_);
        }

        UINT32 endpoint_buffer_frames = 0;
        if (SUCCEEDED(result)) {
          result = audio_client->GetBufferSize(&endpoint_buffer_frames);
        }

        com_ptr_t<IAudioRenderClient> render_client;
        if (SUCCEEDED(result)) {
          result = audio_client->GetService(
            __uuidof(IAudioRenderClient),
            reinterpret_cast<void **>(render_client.put())
          );
        }

        if (FAILED(result) || endpoint_buffer_frames == 0) {
          BOOST_LOG(warning) << "WASAPI virtual microphone initialization failed: "sv << status_bits(result);
          report_startup(false);
          return;
        }

        {
          std::lock_guard lock(mutex_);
          const auto duration_frames = static_cast<std::size_t>(
            (static_cast<std::uint64_t>(endpoint->mix_format.sample_rate) * RING_DURATION.count()) / 1000U
          );
          try {
            if (!converter_.reset(endpoint->mix_format) ||
                !ring_.reset(duration_frames, endpoint->mix_format.block_align)) {
              result = E_OUTOFMEMORY;
            }
          } catch (...) {
            result = E_OUTOFMEMORY;
          }
        }

        if (SUCCEEDED(result)) {
          result = audio_client->Start();
        }
        if (FAILED(result)) {
          BOOST_LOG(warning) << "WASAPI virtual microphone start failed: "sv << status_bits(result);
          report_startup(false);
          return;
        }

        BOOST_LOG(info) << "Client microphone using exact WASAPI destination: "sv << destination_name();
        report_startup(true);

        const std::array events {stop_event_, audio_event_};
        while (true) {
          const auto wait_result = WaitForMultipleObjects(
            static_cast<DWORD>(events.size()),
            events.data(),
            FALSE,
            INFINITE
          );
          if (wait_result == WAIT_OBJECT_0) {
            break;
          }
          if (wait_result != WAIT_OBJECT_0 + 1) {
            backend_failed();
            break;
          }

          UINT32 padding = 0;
          result = audio_client->GetCurrentPadding(&padding);
          if (FAILED(result) || padding > endpoint_buffer_frames) {
            backend_failed();
            break;
          }
          const auto available_frames = endpoint_buffer_frames - padding;
          if (available_frames == 0) {
            continue;
          }

          BYTE *buffer = nullptr;
          result = render_client->GetBuffer(available_frames, &buffer);
          if (FAILED(result) || !buffer) {
            backend_failed();
            break;
          }

          const auto byte_count = static_cast<std::size_t>(available_frames) * endpoint->mix_format.block_align;
          std::span destination {reinterpret_cast<std::byte *>(buffer), byte_count};
          std::size_t copied_frames = 0;
          {
            std::lock_guard lock(mutex_);
            copied_frames = ring_.pop(destination);
          }
          const auto copied_bytes = copied_frames * endpoint->mix_format.block_align;
          std::fill(destination.begin() + static_cast<std::ptrdiff_t>(copied_bytes), destination.end(), std::byte {});

          result = render_client->ReleaseBuffer(available_frames, 0);
          if (FAILED(result)) {
            backend_failed();
            break;
          }
        }

        static_cast<void>(audio_client->Stop());
        static_cast<void>(audio_client->Reset());
      }

      /**
       * @brief Publish worker startup status.
       * @param succeeded Whether the endpoint is running.
       */
      void report_startup(bool succeeded) noexcept {
        {
          std::lock_guard lock(mutex_);
          startup_complete_ = true;
          startup_succeeded_ = succeeded;
          if (!succeeded) {
            generation_state_.fail();
          }
        }
        startup_condition_.notify_all();
      }

      /**
       * @brief Latch a runtime WASAPI failure and stop accepting PCM.
       */
      void backend_failed() noexcept {
        std::lock_guard lock(mutex_);
        fail_closed_locked();
      }

      /**
       * @brief Latch fail-close state while holding the mutex.
       */
      void fail_closed_locked() noexcept {
        generation_state_.fail();
        startup_succeeded_ = false;
        if (stop_event_) {
          SetEvent(stop_event_);
        }
      }

      /**
       * @brief Signal, join, and release one worker generation.
       */
      void stop_worker() noexcept {
        {
          std::lock_guard lock(mutex_);
          if (stop_event_) {
            SetEvent(stop_event_);
          }
        }
        if (worker_.joinable()) {
          worker_.join();
        }
        std::lock_guard lock(mutex_);
        startup_complete_ = false;
        startup_succeeded_ = false;
        close_events_locked();
      }

      /**
       * @brief Close native event handles while holding the mutex.
       */
      void close_events_locked() noexcept {
        if (audio_event_) {
          CloseHandle(std::exchange(audio_event_, nullptr));
        }
        if (stop_event_) {
          CloseHandle(std::exchange(stop_event_, nullptr));
        }
      }

      /**
       * @brief Return the configured destination label for actionable logs.
       * @return Human-readable destination name.
       */
      [[nodiscard]] std::string_view destination_name() const noexcept {
        return kind_ == wasapi_virtual_microphone_kind_e::steam ?
                 "Steam Streaming Microphone"sv :
                 "VB-CABLE"sv;
      }

      wasapi_virtual_microphone_kind_e kind_;  ///< Exact configured destination.
      std::mutex mutex_;  ///< Serializes producer state and bounded ring access.
      std::condition_variable startup_condition_;  ///< Publishes worker startup.
      std::thread worker_;  ///< COM-owning event-driven render worker.
      HANDLE stop_event_ {};  ///< Manual-reset worker stop event.
      HANDLE audio_event_ {};  ///< WASAPI buffer event.
      wasapi_mono_converter_t converter_;  ///< Generation-scoped PCM converter.
      wasapi_frame_ring_t ring_;  ///< Bounded converted-frame ring.
      wasapi_generation_state_t generation_state_;  ///< Generation and fail-close latch.
      bool startup_complete_ {};  ///< Whether the worker finished initialization.
      bool startup_succeeded_ {};  ///< Whether writes may be queued.
    };
  }  // namespace

  const wasapi_endpoint_identity_t *select_wasapi_virtual_microphone_endpoint(
    std::span<const wasapi_endpoint_identity_t> render_endpoints,
    std::span<const wasapi_endpoint_identity_t> capture_endpoints,
    wasapi_virtual_microphone_kind_e kind
  ) noexcept {
    const auto expected_adapter = kind == wasapi_virtual_microphone_kind_e::steam ?
                                    STEAM_STREAMING_MICROPHONE_ADAPTER :
                                    VB_CABLE_ADAPTER;
    const auto has_capture_peer = [&](const wasapi_endpoint_identity_t &render) {
      const GUID zero {};
      if (IsEqualGUID(render.container_id, zero)) {
        return false;
      }
      return std::ranges::any_of(capture_endpoints, [&](const wasapi_endpoint_identity_t &capture) {
        return IsEqualGUID(render.container_id, capture.container_id) && capture.adapter_name == expected_adapter;
      });
    };

    for (const auto &render : render_endpoints) {
      if (render.adapter_name == expected_adapter && has_capture_peer(render)) {
        return &render;
      }
    }
    return nullptr;
  }

  bool wasapi_mono_converter_t::reset(const wasapi_mix_format_t &format) noexcept {
    std::uint16_t bytes_per_sample = 0;
    switch (format.sample_format) {
      case wasapi_sample_format_e::pcm_s16:
        bytes_per_sample = 2;
        break;
      case wasapi_sample_format_e::pcm_s24:
        bytes_per_sample = 3;
        break;
      case wasapi_sample_format_e::pcm_s32:
      case wasapi_sample_format_e::float_f32:
        bytes_per_sample = 4;
        break;
    }
    configured_ = format.sample_rate > 0 && format.sample_rate <= MAX_ENDPOINT_SAMPLE_RATE &&
                  format.channels > 0 && format.channels <= MAX_ENDPOINT_CHANNELS &&
                  format.block_align == format.channels * bytes_per_sample;
    format_ = configured_ ? format : wasapi_mix_format_t {};
    source_frames_ = 0;
    output_frames_ = 0;
    previous_sample_ = 0;
    have_previous_ = false;
    return configured_;
  }

  std::vector<std::byte> wasapi_mono_converter_t::convert(std::span<const std::int16_t> samples) {
    if (!configured_ || samples.empty()) {
      return {};
    }

    const auto chunk_begin = source_frames_;
    const auto chunk_end = chunk_begin + samples.size() - 1U;
    std::vector<std::int16_t> resampled;
    const auto estimate = (static_cast<std::uint64_t>(samples.size()) * format_.sample_rate + SOURCE_SAMPLE_RATE - 1U) /
                          SOURCE_SAMPLE_RATE;
    resampled.reserve(static_cast<std::size_t>(estimate + 1U));

    while (true) {
      const auto source_numerator = output_frames_ * SOURCE_SAMPLE_RATE;
      const auto source_index = source_numerator / format_.sample_rate;
      const auto remainder = source_numerator % format_.sample_rate;
      const auto needs_following = remainder != 0;
      if (source_index > chunk_end || (needs_following && source_index + 1U > chunk_end)) {
        break;
      }
      if (source_index + 1U < chunk_begin || source_index > chunk_end) {
        throw std::logic_error("Non-contiguous WASAPI microphone source chunks");
      }

      const auto sample_at = [&](std::uint64_t index) -> std::int16_t {
        if (index + 1U == chunk_begin && have_previous_) {
          return previous_sample_;
        }
        return samples[static_cast<std::size_t>(index - chunk_begin)];
      };

      const auto first = sample_at(source_index);
      std::int16_t converted = first;
      if (needs_following) {
        const auto second = sample_at(source_index + 1U);
        const auto weighted = static_cast<std::int64_t>(first) *
                                static_cast<std::int64_t>(format_.sample_rate - remainder) +
                              static_cast<std::int64_t>(second) * static_cast<std::int64_t>(remainder);
        const auto rounded = weighted >= 0 ?
                               weighted + static_cast<std::int64_t>(format_.sample_rate / 2U) :
                               weighted - static_cast<std::int64_t>(format_.sample_rate / 2U);
        converted = static_cast<std::int16_t>(std::clamp<std::int64_t>(
          rounded / static_cast<std::int64_t>(format_.sample_rate),
          std::numeric_limits<std::int16_t>::min(),
          std::numeric_limits<std::int16_t>::max()
        ));
      }
      resampled.push_back(converted);
      ++output_frames_;
    }

    source_frames_ += samples.size();
    previous_sample_ = samples.back();
    have_previous_ = true;

    std::vector<std::byte> output(resampled.size() * format_.block_align);
    auto *destination = output.data();
    for (const auto sample : resampled) {
      store_frame(sample, format_, destination);
      destination += format_.block_align;
    }
    return output;
  }

  const wasapi_mix_format_t &wasapi_mono_converter_t::format() const noexcept {
    return format_;
  }

  bool wasapi_frame_ring_t::reset(std::size_t capacity_frames, std::size_t block_align) {
    if (capacity_frames == 0 || block_align == 0 ||
        capacity_frames > std::numeric_limits<std::size_t>::max() / block_align) {
      return false;
    }
    storage_.assign(capacity_frames * block_align, std::byte {});
    block_align_ = block_align;
    read_frame_ = 0;
    write_frame_ = 0;
    size_frames_ = 0;
    return true;
  }

  bool wasapi_frame_ring_t::push(std::span<const std::byte> bytes) noexcept {
    if (block_align_ == 0 || bytes.size() % block_align_ != 0) {
      return false;
    }
    const auto frames = bytes.size() / block_align_;
    if (frames > free_frames()) {
      return false;
    }

    const auto capacity_frames = storage_.size() / block_align_;
    for (std::size_t frame = 0; frame < frames; ++frame) {
      const auto source = bytes.subspan(frame * block_align_, block_align_);
      std::copy(source.begin(), source.end(), storage_.begin() + static_cast<std::ptrdiff_t>(write_frame_ * block_align_));
      write_frame_ = (write_frame_ + 1U) % capacity_frames;
    }
    size_frames_ += frames;
    return true;
  }

  std::size_t wasapi_frame_ring_t::pop(std::span<std::byte> destination) noexcept {
    if (block_align_ == 0 || destination.size() % block_align_ != 0) {
      return 0;
    }
    const auto frames = std::min(size_frames_, destination.size() / block_align_);
    const auto capacity_frames = storage_.size() / block_align_;
    for (std::size_t frame = 0; frame < frames; ++frame) {
      const auto source = std::span<const std::byte> {storage_}.subspan(read_frame_ * block_align_, block_align_);
      std::copy(source.begin(), source.end(), destination.begin() + static_cast<std::ptrdiff_t>(frame * block_align_));
      read_frame_ = (read_frame_ + 1U) % capacity_frames;
    }
    size_frames_ -= frames;
    return frames;
  }

  std::size_t wasapi_frame_ring_t::size_frames() const noexcept {
    return size_frames_;
  }

  std::size_t wasapi_frame_ring_t::free_frames() const noexcept {
    return block_align_ == 0 ? 0 : storage_.size() / block_align_ - size_frames_;
  }

  bool wasapi_generation_state_t::begin(std::uint64_t generation) noexcept {
    if (generation == 0) {
      return false;
    }
    generation_ = generation;
    failed_ = false;
    return true;
  }

  bool wasapi_generation_state_t::accepts(std::uint64_t generation) const noexcept {
    return generation_ != 0 && generation == generation_ && !failed_;
  }

  void wasapi_generation_state_t::fail() noexcept {
    if (generation_ != 0) {
      failed_ = true;
    }
  }

  bool wasapi_generation_state_t::end(std::uint64_t generation) noexcept {
    if (generation == 0 || generation != generation_) {
      return false;
    }
    generation_ = 0;
    failed_ = false;
    return true;
  }

  std::uint64_t wasapi_generation_state_t::generation() const noexcept {
    return generation_;
  }

  bool wasapi_generation_state_t::failed() const noexcept {
    return failed_;
  }

  std::unique_ptr<virtual_microphone_sink_t> make_wasapi_virtual_microphone(wasapi_virtual_microphone_kind_e kind) {
    return std::make_unique<wasapi_virtual_microphone_t>(kind);
  }
}  // namespace platf::win_audio
