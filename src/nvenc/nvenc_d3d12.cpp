/**
 * @file src/nvenc/nvenc_d3d12.cpp
 * @brief Definitions for the Direct3D12 NVENC encoder.
 */
// local includes
#include "src/logging.h"

#ifdef _WIN32
  // this include
  #include "nvenc_d3d12.h"

  #if NVENC_SDK_VERSION >= 1200

    // local includes
    #include "nvenc_utils.h"

namespace NVENC_NAMESPACE {

  nvenc_d3d12::nvenc_d3d12(ID3D12Device *d3d_device, ::nvenc::shared_dll dll):
      nvenc_base(NV_ENC_DEVICE_TYPE_DIRECTX),
      dll(std::move(dll)),
      d3d_device(d3d_device) {
    device = d3d_device;
    async_event_handle = CreateEvent(nullptr, FALSE, FALSE, nullptr);
  }

  nvenc_d3d12::~nvenc_d3d12() {
    if (encoder) {
      destroy_encoder();
    }
    if (async_event_handle) {
      CloseHandle(async_event_handle);
    }
  }

  ID3D12Resource *nvenc_d3d12::get_input_resource() {
    return input_texture.Get();
  }

  void nvenc_d3d12::set_input_fence_point(ID3D12Fence *fence, const std::uint64_t value) {
    input_fence = fence;
    input_fence_value = value;
  }

  bool nvenc_d3d12::init_library() {
    if (nvenc) {
      return true;
    }

    auto create_instance = reinterpret_cast<decltype(NvEncodeAPICreateInstance) *>(
      GetProcAddress(dll.get(), "NvEncodeAPICreateInstance")
    );
    if (!create_instance) {
      BOOST_LOG(error) << "NvEnc: No NvEncodeAPICreateInstance() in NVENC driver library";
      return false;
    }

    auto new_nvenc = std::make_unique<NV_ENCODE_API_FUNCTION_LIST>();
    new_nvenc->version = NV_ENCODE_API_FUNCTION_LIST_VER;
    if (nvenc_failed(create_instance(new_nvenc.get()))) {
      BOOST_LOG(error) << "NvEnc: NvEncodeAPICreateInstance() failed: " << last_nvenc_error_string;
      return false;
    }

    nvenc = std::move(new_nvenc);
    return true;
  }

  bool nvenc_d3d12::create_and_register_input_buffer() {
    if (encoder_params.buffer_format != NV_ENC_BUFFER_FORMAT_NV12) {
      BOOST_LOG(error) << "NvEnc: the D3D12 path encodes 8-bit 4:2:0 only";
      return false;
    }

    if (!input_texture) {
      D3D12_HEAP_PROPERTIES heap {};
      heap.Type = D3D12_HEAP_TYPE_DEFAULT;
      D3D12_RESOURCE_DESC desc {};
      desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
      desc.Width = encoder_params.width;
      desc.Height = encoder_params.height;
      desc.DepthOrArraySize = 1;
      desc.MipLevels = 1;
      desc.Format = DXGI_FORMAT_NV12;
      desc.SampleDesc.Count = 1;
      desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
      desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
      if (FAILED(d3d_device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&input_texture)))) {
        BOOST_LOG(error) << "NvEnc: couldn't create the D3D12 NV12 input texture";
        return false;
      }
    }

    if (!registered_input_buffer) {
      NV_ENC_REGISTER_RESOURCE register_resource = {NV_ENC_REGISTER_RESOURCE_VER};
      register_resource.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX;
      register_resource.width = encoder_params.width;
      register_resource.height = encoder_params.height;
      register_resource.resourceToRegister = input_texture.Get();
      register_resource.bufferFormat = encoder_params.buffer_format;
      register_resource.bufferUsage = NV_ENC_INPUT_IMAGE;

      if (nvenc_failed(nvenc->nvEncRegisterResource(encoder, &register_resource))) {
        BOOST_LOG(error) << "NvEnc: NvEncRegisterResource() failed for the D3D12 input: " << last_nvenc_error_string;
        return false;
      }

      registered_input_buffer = register_resource.registeredResource;
    }

    return true;
  }

  bool nvenc_d3d12::create_output_bitstream() {
    // Twice an uncompressed NV12 picture, the size NVIDIA recommends for the readback buffer.
    const auto buffer_bytes = static_cast<std::uint64_t>(encoder_params.width) * encoder_params.height * 3U;

    if (!output_fence && FAILED(d3d_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&output_fence)))) {
      BOOST_LOG(error) << "NvEnc: couldn't create the D3D12 output fence";
      return false;
    }

    D3D12_HEAP_PROPERTIES heap {};
    heap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC desc {};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = buffer_bytes;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_UNKNOWN;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    if (FAILED(d3d_device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&output_buffer)))) {
      BOOST_LOG(error) << "NvEnc: couldn't create the D3D12 bitstream readback buffer";
      return false;
    }

    NV_ENC_REGISTER_RESOURCE register_resource = {NV_ENC_REGISTER_RESOURCE_VER};
    register_resource.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX;
    register_resource.width = static_cast<std::uint32_t>(buffer_bytes);
    register_resource.height = 1;
    register_resource.resourceToRegister = output_buffer.Get();
    register_resource.bufferFormat = NV_ENC_BUFFER_FORMAT_U8;
    register_resource.bufferUsage = NV_ENC_OUTPUT_BITSTREAM;
    if (nvenc_failed(nvenc->nvEncRegisterResource(encoder, &register_resource))) {
      BOOST_LOG(error) << "NvEnc: NvEncRegisterResource() failed for the D3D12 bitstream: " << last_nvenc_error_string;
      return false;
    }
    registered_output_buffer = register_resource.registeredResource;

    // The output stays mapped for the session; NVENC hands it back through each lock.
    NV_ENC_MAP_INPUT_RESOURCE map_resource = {NV_ENC_MAP_INPUT_RESOURCE_VER};
    map_resource.registeredResource = registered_output_buffer;
    if (nvenc_failed(nvenc->nvEncMapInputResource(encoder, &map_resource))) {
      BOOST_LOG(error) << "NvEnc: NvEncMapInputResource() failed for the D3D12 bitstream: " << last_nvenc_error_string;
      return false;
    }
    mapped_output_buffer = map_resource.mappedResource;

    output_resource = {NV_ENC_OUTPUT_RESOURCE_D3D12_VER};
    output_resource.pOutputBuffer = mapped_output_buffer;
    output_resource.outputFencePoint.version = NV_ENC_FENCE_POINT_D3D12_VER;
    output_resource.outputFencePoint.pFence = output_fence.Get();
    return true;
  }

  void nvenc_d3d12::destroy_output_bitstream() {
    if (mapped_output_buffer) {
      if (nvenc_failed(nvenc->nvEncUnmapInputResource(encoder, mapped_output_buffer))) {
        BOOST_LOG(error) << "NvEnc: NvEncUnmapInputResource() failed for the D3D12 bitstream: " << last_nvenc_error_string;
      }
      mapped_output_buffer = nullptr;
    }
    if (registered_output_buffer) {
      if (nvenc_failed(nvenc->nvEncUnregisterResource(encoder, registered_output_buffer))) {
        BOOST_LOG(error) << "NvEnc: NvEncUnregisterResource() failed for the D3D12 bitstream: " << last_nvenc_error_string;
      }
      registered_output_buffer = nullptr;
    }
    output_buffer.Reset();
    output_resource = {};
  }

  void *nvenc_d3d12::picture_input_buffer(NV_ENC_INPUT_PTR mapped_input) {
    // D3D12 mapping does not order NVENC after the conversion; the fence point does.
    input_resource = {NV_ENC_INPUT_RESOURCE_D3D12_VER};
    input_resource.pInputBuffer = mapped_input;
    input_resource.inputFencePoint.version = NV_ENC_FENCE_POINT_D3D12_VER;
    if (input_fence) {
      input_resource.inputFencePoint.pFence = input_fence;
      input_resource.inputFencePoint.waitValue = input_fence_value;
      input_resource.inputFencePoint.bWait = 1;
    }
    output_resource.outputFencePoint.signalValue = ++output_fence_value;
    output_resource.outputFencePoint.bSignal = 1;
    return &input_resource;
  }

  void *nvenc_d3d12::picture_output_bitstream() {
    return mapped_output_buffer ? &output_resource : nullptr;
  }

  bool nvenc_d3d12::wait_for_async_event(uint32_t timeout_ms) {
    return WaitForSingleObject(async_event_handle, timeout_ms) == WAIT_OBJECT_0;
  }

}  // namespace NVENC_NAMESPACE
  #endif
#endif
