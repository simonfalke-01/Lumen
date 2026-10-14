/**
 * @file tools/lumen-clipboard.cpp
 * @brief User-session clipboard helper for LSP clipboard sharing.
 *
 * Lumen runs as SYSTEM, which cannot reliably read clipboard data owned by
 * user applications. Lumen starts this helper with the interactive user's
 * token; the helper owns every clipboard read and write and exchanges
 * clipboard bundles with Lumen over stdin/stdout.
 *
 * Pipe frames are a 4-byte little-endian length followed by one bundle.
 * A bundle is a sequence of entries: 1-byte kind, 4-byte big-endian length,
 * then the bytes. Kinds: 1 plain UTF-8 text (LF line endings), 2 UTF-8 HTML
 * markup fragment, 3 PNG image. The helper exits when stdin closes.
 */
// standard includes
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// platform includes
#include <Windows.h>
#include <objbase.h>
#include <shlwapi.h>
#include <wincodec.h>

namespace {
  constexpr std::uint8_t kind_text = 1;
  constexpr std::uint8_t kind_html = 2;
  constexpr std::uint8_t kind_png = 3;
  constexpr std::size_t maximum_bundle_bytes = 16U * 1'024U * 1'024U;
  constexpr UINT apply_message = WM_APP + 1;
  constexpr int open_attempts = 20;

  struct Content {
    std::string text;
    std::string html;
    std::vector<std::uint8_t> png;
  };

  HWND window_handle = nullptr;
  std::mutex pending_mutex;
  std::optional<std::vector<std::uint8_t>> pending_apply;
  std::mutex output_mutex;
  DWORD own_sequence = 0;
  std::vector<std::uint8_t> last_applied_bundle;
  UINT html_format = 0;
  UINT png_format = 0;

  void append_entry(std::vector<std::uint8_t> &bundle, const std::uint8_t kind, const std::uint8_t *data, const std::size_t size) {
    bundle.push_back(kind);
    bundle.push_back(static_cast<std::uint8_t>(size >> 24U));
    bundle.push_back(static_cast<std::uint8_t>(size >> 16U));
    bundle.push_back(static_cast<std::uint8_t>(size >> 8U));
    bundle.push_back(static_cast<std::uint8_t>(size));
    bundle.insert(bundle.end(), data, data + size);
  }

  std::vector<std::uint8_t> encode_bundle(const Content &content) {
    std::vector<std::uint8_t> bundle;
    if (!content.text.empty()) {
      append_entry(bundle, kind_text, reinterpret_cast<const std::uint8_t *>(content.text.data()), content.text.size());
    }
    if (!content.html.empty()) {
      append_entry(bundle, kind_html, reinterpret_cast<const std::uint8_t *>(content.html.data()), content.html.size());
    }
    if (!content.png.empty()) {
      append_entry(bundle, kind_png, content.png.data(), content.png.size());
    }
    return bundle;
  }

  std::optional<Content> decode_bundle(const std::vector<std::uint8_t> &bundle) {
    Content content;
    std::size_t index = 0;
    while (index < bundle.size()) {
      if (bundle.size() - index < 5U) {
        return std::nullopt;
      }
      const auto kind = bundle[index];
      const std::size_t size = (std::size_t {bundle[index + 1]} << 24U) | (std::size_t {bundle[index + 2]} << 16U) |
                               (std::size_t {bundle[index + 3]} << 8U) | std::size_t {bundle[index + 4]};
      index += 5U;
      if (size == 0 || size > bundle.size() - index) {
        return std::nullopt;
      }
      const auto *data = bundle.data() + index;
      if (kind == kind_text) {
        content.text.assign(reinterpret_cast<const char *>(data), size);
      } else if (kind == kind_html) {
        content.html.assign(reinterpret_cast<const char *>(data), size);
      } else if (kind == kind_png) {
        content.png.assign(data, data + size);
      }
      index += size;
    }
    return content;
  }

  std::wstring widen(const std::string_view text) {
    if (text.empty()) {
      return {};
    }
    const auto size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(std::max(size, 0)), L'\0');
    if (size > 0) {
      MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
    }
    return result;
  }

  std::string narrow(const std::wstring_view text) {
    if (text.empty()) {
      return {};
    }
    const auto size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(std::max(size, 0)), '\0');
    if (size > 0) {
      WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    }
    return result;
  }

  std::string to_lf(const std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
      if (text[index] == '\r' && index + 1 < text.size() && text[index + 1] == '\n') {
        continue;
      }
      result.push_back(text[index]);
    }
    return result;
  }

  std::string to_crlf(const std::string_view text) {
    std::string result;
    result.reserve(text.size() + text.size() / 16U);
    for (std::size_t index = 0; index < text.size(); ++index) {
      if (text[index] == '\n' && (index == 0 || text[index - 1] != '\r')) {
        result.push_back('\r');
      }
      result.push_back(text[index]);
    }
    return result;
  }

  std::optional<std::size_t> header_offset(const std::string_view payload, const std::string_view key) {
    const auto position = payload.find(key);
    if (position == std::string_view::npos) {
      return std::nullopt;
    }
    std::size_t value = 0;
    bool digits = false;
    for (auto index = position + key.size(); index < payload.size() && payload[index] >= '0' && payload[index] <= '9'; ++index) {
      value = value * 10U + static_cast<std::size_t>(payload[index] - '0');
      digits = true;
    }
    return digits ? std::optional<std::size_t> {value} : std::nullopt;
  }

  /** @brief Return the copied markup fragment from one CF_HTML payload. */
  std::string html_fragment(const std::string_view payload) {
    const auto start = header_offset(payload, "StartFragment:");
    const auto end = header_offset(payload, "EndFragment:");
    if (!start || !end || *start > *end || *end > payload.size()) {
      return {};
    }
    return std::string {payload.substr(*start, *end - *start)};
  }

  /** @brief Wrap one markup fragment (or document body) in a CF_HTML payload. */
  std::string cf_html(std::string_view markup) {
    const auto lower_find = [&](const std::string_view needle) {
      for (std::size_t index = 0; index + needle.size() <= markup.size(); ++index) {
        bool equal = true;
        for (std::size_t offset = 0; offset < needle.size() && equal; ++offset) {
          equal = std::tolower(static_cast<unsigned char>(markup[index + offset])) == needle[offset];
        }
        if (equal) {
          return index;
        }
      }
      return std::string_view::npos;
    };
    if (const auto body = lower_find("<body"); body != std::string_view::npos) {
      const auto body_open_end = markup.find('>', body);
      const auto body_close = lower_find("</body");
      if (body_open_end != std::string_view::npos && body_close != std::string_view::npos && body_close > body_open_end) {
        markup = markup.substr(body_open_end + 1U, body_close - body_open_end - 1U);
      }
    }
    constexpr std::string_view header_template =
      "Version:0.9\r\nStartHTML:0000000000\r\nEndHTML:0000000000\r\nStartFragment:0000000000\r\nEndFragment:0000000000\r\n";
    constexpr std::string_view prefix = "<html><body>\r\n<!--StartFragment-->";
    constexpr std::string_view suffix = "<!--EndFragment-->\r\n</body></html>";
    const auto start_html = header_template.size();
    const auto start_fragment = start_html + prefix.size();
    const auto end_fragment = start_fragment + markup.size();
    const auto end_html = end_fragment + suffix.size();
    char header[160];
    std::snprintf(
      header,
      sizeof(header),
      "Version:0.9\r\nStartHTML:%010zu\r\nEndHTML:%010zu\r\nStartFragment:%010zu\r\nEndFragment:%010zu\r\n",
      start_html,
      end_html,
      start_fragment,
      end_fragment
    );
    std::string result {header};
    result += prefix;
    result += markup;
    result += suffix;
    return result;
  }

  IWICImagingFactory *imaging_factory() {
    static IWICImagingFactory *factory = []() -> IWICImagingFactory * {
      IWICImagingFactory *created = nullptr;
      if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&created)))) {
        return nullptr;
      }
      return created;
    }();
    return factory;
  }

  /** @brief Encode one WIC bitmap source as PNG bytes. */
  std::vector<std::uint8_t> encode_png(IWICBitmapSource *source) {
    std::vector<std::uint8_t> result;
    auto *factory = imaging_factory();
    IStream *stream = SHCreateMemStream(nullptr, 0);
    if (factory == nullptr || stream == nullptr) {
      if (stream != nullptr) {
        stream->Release();
      }
      return result;
    }
    IWICBitmapEncoder *encoder = nullptr;
    IWICBitmapFrameEncode *frame = nullptr;
    if (SUCCEEDED(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder)) &&
        SUCCEEDED(encoder->Initialize(stream, WICBitmapEncoderNoCache)) &&
        SUCCEEDED(encoder->CreateNewFrame(&frame, nullptr)) && SUCCEEDED(frame->Initialize(nullptr)) &&
        SUCCEEDED(frame->WriteSource(source, nullptr)) && SUCCEEDED(frame->Commit()) && SUCCEEDED(encoder->Commit())) {
      STATSTG stat {};
      if (SUCCEEDED(stream->Stat(&stat, STATFLAG_NONAME)) && stat.cbSize.QuadPart <= maximum_bundle_bytes) {
        result.resize(static_cast<std::size_t>(stat.cbSize.QuadPart));
        LARGE_INTEGER zero {};
        ULONG read = 0;
        if (FAILED(stream->Seek(zero, STREAM_SEEK_SET, nullptr)) ||
            FAILED(stream->Read(result.data(), static_cast<ULONG>(result.size()), &read)) || read != result.size()) {
          result.clear();
        }
      }
    }
    if (frame != nullptr) {
      frame->Release();
    }
    if (encoder != nullptr) {
      encoder->Release();
    }
    stream->Release();
    return result;
  }

  /** @brief Convert one packed DIB (header + optional masks/palette + pixels) to PNG. */
  std::vector<std::uint8_t> dib_to_png(const std::uint8_t *dib, const std::size_t size) {
    if (size < sizeof(BITMAPINFOHEADER)) {
      return {};
    }
    BITMAPINFOHEADER info {};
    std::memcpy(&info, dib, sizeof(info));
    std::size_t palette_bytes = info.biClrUsed * sizeof(RGBQUAD);
    if (info.biClrUsed == 0 && info.biBitCount <= 8) {
      palette_bytes = (std::size_t {1} << info.biBitCount) * sizeof(RGBQUAD);
    }
    std::size_t mask_bytes = 0;
    if (info.biSize == sizeof(BITMAPINFOHEADER) && info.biCompression == BI_BITFIELDS) {
      mask_bytes = 3U * sizeof(DWORD);
    }
    BITMAPFILEHEADER file {};
    file.bfType = 0x4d42;
    file.bfSize = static_cast<DWORD>(sizeof(file) + size);
    file.bfOffBits = static_cast<DWORD>(sizeof(file) + info.biSize + mask_bytes + palette_bytes);
    std::vector<std::uint8_t> bmp(sizeof(file) + size);
    std::memcpy(bmp.data(), &file, sizeof(file));
    std::memcpy(bmp.data() + sizeof(file), dib, size);
    auto *factory = imaging_factory();
    IStream *stream = SHCreateMemStream(bmp.data(), static_cast<UINT>(bmp.size()));
    std::vector<std::uint8_t> result;
    IWICBitmapDecoder *decoder = nullptr;
    IWICBitmapFrameDecode *frame = nullptr;
    if (factory != nullptr && stream != nullptr &&
        SUCCEEDED(factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnDemand, &decoder)) &&
        SUCCEEDED(decoder->GetFrame(0, &frame))) {
      result = encode_png(frame);
    }
    if (frame != nullptr) {
      frame->Release();
    }
    if (decoder != nullptr) {
      decoder->Release();
    }
    if (stream != nullptr) {
      stream->Release();
    }
    return result;
  }

  /** @brief Decode PNG bytes to a bottom-up 32-bit CF_DIB for applications without PNG support. */
  HGLOBAL png_to_dib(const std::vector<std::uint8_t> &png) {
    auto *factory = imaging_factory();
    IStream *stream = SHCreateMemStream(png.data(), static_cast<UINT>(png.size()));
    HGLOBAL result = nullptr;
    IWICBitmapDecoder *decoder = nullptr;
    IWICBitmapFrameDecode *frame = nullptr;
    IWICFormatConverter *converter = nullptr;
    UINT width = 0;
    UINT height = 0;
    if (factory != nullptr && stream != nullptr &&
        SUCCEEDED(factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnDemand, &decoder)) &&
        SUCCEEDED(decoder->GetFrame(0, &frame)) && SUCCEEDED(factory->CreateFormatConverter(&converter)) &&
        SUCCEEDED(converter->Initialize(frame, GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom)) &&
        SUCCEEDED(converter->GetSize(&width, &height)) && width > 0 && height > 0 && width <= 32'768U && height <= 32'768U) {
      const std::size_t stride = std::size_t {width} * 4U;
      const std::size_t pixels = stride * height;
      std::vector<std::uint8_t> top_down(pixels);
      if (SUCCEEDED(converter->CopyPixels(nullptr, static_cast<UINT>(stride), static_cast<UINT>(pixels), top_down.data()))) {
        result = GlobalAlloc(GMEM_MOVEABLE, sizeof(BITMAPINFOHEADER) + pixels);
        if (result != nullptr) {
          auto *destination = static_cast<std::uint8_t *>(GlobalLock(result));
          BITMAPINFOHEADER info {};
          info.biSize = sizeof(info);
          info.biWidth = static_cast<LONG>(width);
          info.biHeight = static_cast<LONG>(height);
          info.biPlanes = 1;
          info.biBitCount = 32;
          info.biCompression = BI_RGB;
          info.biSizeImage = static_cast<DWORD>(pixels);
          std::memcpy(destination, &info, sizeof(info));
          for (UINT row = 0; row < height; ++row) {
            std::memcpy(destination + sizeof(info) + std::size_t {row} * stride, top_down.data() + std::size_t {height - 1U - row} * stride, stride);
          }
          GlobalUnlock(result);
        }
      }
    }
    if (converter != nullptr) {
      converter->Release();
    }
    if (frame != nullptr) {
      frame->Release();
    }
    if (decoder != nullptr) {
      decoder->Release();
    }
    if (stream != nullptr) {
      stream->Release();
    }
    return result;
  }

  bool open_clipboard() {
    for (int attempt = 0; attempt < open_attempts; ++attempt) {
      if (OpenClipboard(window_handle)) {
        return true;
      }
      Sleep(10);
    }
    return false;
  }

  /** @brief Copy one clipboard format's bytes while the clipboard is open. */
  std::vector<std::uint8_t> clipboard_bytes(const UINT format) {
    std::vector<std::uint8_t> bytes;
    if (const auto data = GetClipboardData(format); data != nullptr) {
      if (const auto *pointer = static_cast<const std::uint8_t *>(GlobalLock(data)); pointer != nullptr) {
        const auto size = GlobalSize(data);
        if (size <= maximum_bundle_bytes * 4U) {
          bytes.assign(pointer, pointer + size);
        }
        GlobalUnlock(data);
      }
    }
    return bytes;
  }

  bool write_frame(const std::vector<std::uint8_t> &bundle) {
    std::scoped_lock lock(output_mutex);
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    const std::uint32_t size = static_cast<std::uint32_t>(bundle.size());
    const std::uint8_t header[4] = {
      static_cast<std::uint8_t>(size),
      static_cast<std::uint8_t>(size >> 8U),
      static_cast<std::uint8_t>(size >> 16U),
      static_cast<std::uint8_t>(size >> 24U),
    };
    DWORD written = 0;
    if (!WriteFile(output, header, sizeof(header), &written, nullptr) || written != sizeof(header)) {
      return false;
    }
    std::size_t offset = 0;
    while (offset < bundle.size()) {
      const auto chunk = static_cast<DWORD>(std::min<std::size_t>(bundle.size() - offset, 1U << 20U));
      if (!WriteFile(output, bundle.data() + offset, chunk, &written, nullptr) || written == 0) {
        return false;
      }
      offset += written;
    }
    return true;
  }

  void read_change() {
    const auto sequence = GetClipboardSequenceNumber();
    if (sequence == own_sequence || !open_clipboard()) {
      return;
    }
    Content content;
    if (auto text = clipboard_bytes(CF_UNICODETEXT); text.size() >= sizeof(wchar_t)) {
      const auto *wide = reinterpret_cast<const wchar_t *>(text.data());
      content.text = to_lf(narrow({wide, wcsnlen(wide, text.size() / sizeof(wchar_t))}));
    }
    if (auto html = clipboard_bytes(html_format); !html.empty()) {
      content.html = html_fragment({reinterpret_cast<const char *>(html.data()), strnlen(reinterpret_cast<const char *>(html.data()), html.size())});
    }
    if (auto png = clipboard_bytes(png_format); png.size() > 8U && std::memcmp(png.data(), "\x89PNG", 4) == 0) {
      content.png = std::move(png);
    } else if (IsClipboardFormatAvailable(CF_DIB)) {
      const auto dib = clipboard_bytes(CF_DIB);
      if (!dib.empty()) {
        CloseClipboard();
        // WIC conversion can be slow; never hold the clipboard open during it.
        content.png = dib_to_png(dib.data(), dib.size());
        auto bundle = encode_bundle(content);
        if (!bundle.empty() && bundle.size() <= maximum_bundle_bytes && bundle != last_applied_bundle) {
          (void) write_frame(bundle);
        }
        return;
      }
    }
    CloseClipboard();
    if (content.png.size() > maximum_bundle_bytes) {
      content.png.clear();
    }
    auto bundle = encode_bundle(content);
    if (bundle.empty() || bundle.size() > maximum_bundle_bytes || bundle == last_applied_bundle) {
      return;
    }
    (void) write_frame(bundle);
  }

  bool set_global(const UINT format, const void *data, const std::size_t size) {
    const auto memory = GlobalAlloc(GMEM_MOVEABLE, size);
    if (memory == nullptr) {
      return false;
    }
    if (auto *destination = GlobalLock(memory); destination != nullptr) {
      std::memcpy(destination, data, size);
      GlobalUnlock(memory);
    }
    if (SetClipboardData(format, memory) == nullptr) {
      GlobalFree(memory);
      return false;
    }
    return true;
  }

  void apply_pending() {
    std::optional<std::vector<std::uint8_t>> bundle;
    {
      std::scoped_lock lock(pending_mutex);
      bundle = std::exchange(pending_apply, std::nullopt);
    }
    if (!bundle) {
      return;
    }
    const auto content = decode_bundle(*bundle);
    if (!content || (content->text.empty() && content->html.empty() && content->png.empty())) {
      return;
    }
    // Decode the image before opening the clipboard so other applications are not blocked.
    HGLOBAL dib = content->png.empty() ? nullptr : png_to_dib(content->png);
    if (!open_clipboard()) {
      if (dib != nullptr) {
        GlobalFree(dib);
      }
      return;
    }
    EmptyClipboard();
    if (!content->text.empty()) {
      const auto wide = widen(to_crlf(content->text));
      (void) set_global(CF_UNICODETEXT, wide.c_str(), (wide.size() + 1U) * sizeof(wchar_t));
    }
    if (!content->html.empty()) {
      const auto payload = cf_html(content->html);
      (void) set_global(html_format, payload.c_str(), payload.size() + 1U);
    }
    if (!content->png.empty()) {
      (void) set_global(png_format, content->png.data(), content->png.size());
      if (dib != nullptr && SetClipboardData(CF_DIB, dib) == nullptr) {
        GlobalFree(dib);
      }
    }
    CloseClipboard();
    own_sequence = GetClipboardSequenceNumber();
    last_applied_bundle = std::move(*bundle);
  }

  LRESULT CALLBACK window_procedure(const HWND window, const UINT message, const WPARAM wparam, const LPARAM lparam) {
    if (message == WM_CLIPBOARDUPDATE) {
      read_change();
      return 0;
    }
    if (message == apply_message) {
      apply_pending();
      return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
  }

  bool read_exact(const HANDLE input, std::uint8_t *data, const std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
      DWORD read = 0;
      const auto chunk = static_cast<DWORD>(std::min<std::size_t>(size - offset, 1U << 20U));
      if (!ReadFile(input, data + offset, chunk, &read, nullptr) || read == 0) {
        return false;
      }
      offset += read;
    }
    return true;
  }

  /** @brief Read apply frames from Lumen until stdin closes, then stop the message loop. */
  void input_loop(const DWORD main_thread) {
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    while (true) {
      std::uint8_t header[4];
      if (!read_exact(input, header, sizeof(header))) {
        break;
      }
      const std::size_t size = std::size_t {header[0]} | (std::size_t {header[1]} << 8U) |
                               (std::size_t {header[2]} << 16U) | (std::size_t {header[3]} << 24U);
      if (size == 0 || size > maximum_bundle_bytes) {
        break;
      }
      std::vector<std::uint8_t> bundle(size);
      if (!read_exact(input, bundle.data(), size)) {
        break;
      }
      {
        std::scoped_lock lock(pending_mutex);
        pending_apply = std::move(bundle);
      }
      PostMessageW(window_handle, apply_message, 0, 0);
    }
    PostThreadMessageW(main_thread, WM_QUIT, 0, 0);
  }
}  // namespace

int main() {
  const auto instance = GetModuleHandleW(nullptr);
  if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) {
    return 1;
  }
  html_format = RegisterClipboardFormatW(L"HTML Format");
  png_format = RegisterClipboardFormatW(L"PNG");
  WNDCLASSEXW window_class {
    .cbSize = sizeof(WNDCLASSEXW),
    .lpfnWndProc = window_procedure,
    .hInstance = instance,
    .lpszClassName = L"LumenClipboardHelper",
  };
  if (RegisterClassExW(&window_class) == 0) {
    return 2;
  }
  window_handle = CreateWindowExW(0, window_class.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, instance, nullptr);
  if (window_handle == nullptr || !AddClipboardFormatListener(window_handle)) {
    return 3;
  }
  std::thread input {input_loop, GetCurrentThreadId()};
  input.detach();
  MSG message {};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
  RemoveClipboardFormatListener(window_handle);
  DestroyWindow(window_handle);
  CoUninitialize();
  return 0;
}
