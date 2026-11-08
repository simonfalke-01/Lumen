/**
 * @file src/platform/windows/d3d12_nv12_converter.cpp
 * @brief BGRA to NV12 conversion on a Direct3D12 compute queue.
 */
#include "d3d12_nv12_converter.h"

// standard includes
#include <algorithm>
#include <string>

// platform includes
#include <d3dcompiler.h>

// local includes
#include "src/logging.h"

using namespace std::literals;

namespace platf::dxgi {
  namespace {
    using Microsoft::WRL::ComPtr;

    constexpr UINT root_constant_count = 25;

    /**
     * Compute port of convert_yuv420_planar_y_ps and convert_yuv420_packed_uv_type0(s)_ps with
     * their vertex shaders. One thread writes one chroma sample and its 2x2 luma block. Texture
     * coordinates are the ones the fullscreen triangle interpolates at each pixel centre inside
     * the aspect-fit viewport; pixels outside it get the D3D11 path's clear values. SampleLevel
     * at mip 0 matches Sample on these single-mip textures, and the typed UNORM stores round
     * exactly like the D3D11 render targets.
     */
    constexpr std::string_view shader_source = R"(
Texture2D<float4> image : register(t0);
RWTexture2D<unorm float> out_y : register(u0);
RWTexture2D<unorm float2> out_uv : register(u1);
SamplerState def_sampler : register(s0);

cbuffer params : register(b0) {
  float4 color_vec_y;
  float4 color_vec_u;
  float4 color_vec_v;
  float2 range_y;
  float2 range_uv;
  float4 viewport;
  float2 subsample_offset;
  uint2 luma_size;
  uint fill_black;
};

#if LINEAR_INPUT
float3 ApplySRGBCurve(float3 x)
{
  return x < 0.0031308 ? 12.92 * x : 1.13005 * sqrt(x - 0.00228) - 0.13448 * x + 0.005719;
}

float3 convert_rgb(float3 input)
{
  return ApplySRGBCurve(saturate(input));
}
#else
float3 convert_rgb(float3 input)
{
  return saturate(input);
}
#endif

float3 sample_rgb(float2 tex)
{
  return image.SampleLevel(def_sampler, tex, 0).rgb;
}

bool inside(float2 center, float4 rect)
{
  return center.x >= rect.x && center.x < rect.x + rect.z && center.y >= rect.y && center.y < rect.y + rect.w;
}

[numthreads(8, 8, 1)]
void main_cs(uint3 id : SV_DispatchThreadID)
{
  uint2 chroma = id.xy;
  if (chroma.x * 2 >= luma_size.x || chroma.y * 2 >= luma_size.y) {
    return;
  }

  [unroll]
  for (uint dy = 0; dy < 2; ++dy) {
    [unroll]
    for (uint dx = 0; dx < 2; ++dx) {
      uint2 pixel = chroma * 2 + uint2(dx, dy);
      float2 center = float2(pixel) + 0.5;
      float y = 0;
      if (fill_black == 0 && inside(center, viewport)) {
        float3 rgb = convert_rgb(sample_rgb((center - viewport.xy) / viewport.zw));
        y = dot(color_vec_y.xyz, rgb) + color_vec_y.w;
        y = y * range_y.x + range_y.y;
      }
      out_y[pixel] = y;
    }
  }

  float4 chroma_viewport = viewport * 0.5;
  float2 chroma_center = float2(chroma) + 0.5;
  float2 uv = float2(0.5, 0.5);
  if (fill_black == 0 && inside(chroma_center, chroma_viewport)) {
    float2 tex = (chroma_center - chroma_viewport.xy) / chroma_viewport.zw;
#if DOWNSCALE
    float2 half_offset = subsample_offset / 2;
    float right = tex.x + half_offset.x;
    float middle = tex.x - half_offset.x;
    float left = tex.x - 3 * half_offset.x;
    float top = tex.y - half_offset.y;
    float bottom = tex.y + half_offset.y;
    float3 rgb = sample_rgb(float2(middle, top));
    rgb += sample_rgb(float2(middle, bottom));
    rgb *= 2;
    rgb += sample_rgb(float2(right, top));
    rgb += sample_rgb(float2(left, top));
    rgb += sample_rgb(float2(right, bottom));
    rgb += sample_rgb(float2(left, bottom));
    rgb = convert_rgb(rgb * (1. / 8));
#else
    float3 rgb_left = sample_rgb(tex);
    float3 rgb_right = sample_rgb(float2(tex.x - subsample_offset.x, tex.y));
    float3 rgb = convert_rgb((rgb_left + rgb_right) * 0.5);
#endif
    float u = dot(color_vec_u.xyz, rgb) + color_vec_u.w;
    float v = dot(color_vec_v.xyz, rgb) + color_vec_v.w;
    uv = float2(u, v) * range_uv.x + range_uv.y;
  }
  out_uv[chroma] = uv;
}
)";

    /** @brief Return a printable copy of a compiler or serializer message blob. */
    std::string blob_text(ID3DBlob *blob) {
      return blob ? std::string(static_cast<const char *>(blob->GetBufferPointer()), blob->GetBufferSize()) : "unknown"s;
    }

    /** @brief Return whether the conversion reads this capture format. */
    bool supported_source_format(const DXGI_FORMAT format) {
      return format == DXGI_FORMAT_B8G8R8A8_UNORM || format == DXGI_FORMAT_B8G8R8X8_UNORM ||
             format == DXGI_FORMAT_R8G8B8A8_UNORM || format == DXGI_FORMAT_R16G16B16A16_FLOAT;
    }

    /** @brief Convert GPU ticks between two readings to microseconds, saturating. */
    std::uint32_t ticks_to_us(const std::uint64_t ticks, const std::uint64_t frequency) {
      const auto us = ticks / frequency * 1'000'000U + ticks % frequency * 1'000'000U / frequency;
      return static_cast<std::uint32_t>(std::min<std::uint64_t>(us, UINT32_MAX));
    }
  }  // namespace

  d3d12_nv12_converter_t::~d3d12_nv12_converter_t() {
    wait_idle();
    if (timestamp_readback_ && timestamp_values_) {
      const D3D12_RANGE written {0, 0};
      timestamp_readback_->Unmap(0, &written);
    }
    if (wait_event_) {
      CloseHandle(wait_event_);
    }
  }

  std::unique_ptr<d3d12_nv12_converter_t> d3d12_nv12_converter_t::create(
    IDXGIAdapter *adapter,
    HANDLE capture_fence,
    HANDLE consumption_fence
  ) {
    std::unique_ptr<d3d12_nv12_converter_t> converter {new d3d12_nv12_converter_t()};
    auto &self = *converter;

    if (FAILED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&self.device_)))) {
      BOOST_LOG(warning) << "D3D12 compute conversion: no D3D12 device on the capture adapter"sv;
      return nullptr;
    }

    // NVENC writes NV12 through typed UAV stores on each plane.
    D3D12_FEATURE_DATA_FORMAT_SUPPORT nv12_support {};
    nv12_support.Format = DXGI_FORMAT_NV12;
    if (FAILED(self.device_->CheckFeatureSupport(D3D12_FEATURE_FORMAT_SUPPORT, &nv12_support, sizeof(nv12_support))) ||
        !(nv12_support.Support1 & D3D12_FORMAT_SUPPORT1_TYPED_UNORDERED_ACCESS_VIEW)) {
      BOOST_LOG(warning) << "D3D12 compute conversion: the GPU cannot write NV12 from a compute shader"sv;
      return nullptr;
    }

    // Global realtime needs SeIncreaseBasePriorityPrivilege, which a service may hold.
    D3D12_COMMAND_QUEUE_DESC queue_desc {};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_COMPUTE;
    queue_desc.Priority = D3D12_COMMAND_QUEUE_PRIORITY_GLOBAL_REALTIME;
    if (SUCCEEDED(self.device_->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&self.queue_)))) {
      self.queue_priority_ = "global realtime"sv;
    } else {
      queue_desc.Priority = D3D12_COMMAND_QUEUE_PRIORITY_HIGH;
      if (FAILED(self.device_->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&self.queue_)))) {
        BOOST_LOG(warning) << "D3D12 compute conversion: couldn't create a compute queue"sv;
        return nullptr;
      }
      self.queue_priority_ = "high"sv;
    }
    if (FAILED(self.queue_->GetTimestampFrequency(&self.timestamp_frequency_)) || self.timestamp_frequency_ == 0) {
      self.timestamp_frequency_ = 0;
    }

    if (FAILED(self.device_->OpenSharedHandle(capture_fence, IID_PPV_ARGS(&self.capture_fence_))) ||
        FAILED(self.device_->OpenSharedHandle(consumption_fence, IID_PPV_ARGS(&self.consumption_fence_)))) {
      BOOST_LOG(warning) << "D3D12 compute conversion: couldn't open the shared capture fences"sv;
      return nullptr;
    }

    for (auto &slot : self.slots_) {
      if (FAILED(self.device_->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_COMPUTE, IID_PPV_ARGS(&slot.allocator)))) {
        BOOST_LOG(warning) << "D3D12 compute conversion: couldn't create a command allocator"sv;
        return nullptr;
      }
    }
    if (FAILED(self.device_->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_COMPUTE, self.slots_[0].allocator.Get(), nullptr, IID_PPV_ARGS(&self.list_))) ||
        FAILED(self.list_->Close())) {
      BOOST_LOG(warning) << "D3D12 compute conversion: couldn't create a command list"sv;
      return nullptr;
    }

    // Two UAVs for the NV12 planes, then one SRV per slot.
    D3D12_DESCRIPTOR_HEAP_DESC heap_desc {};
    heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heap_desc.NumDescriptors = 2 + slot_count;
    heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    if (FAILED(self.device_->CreateDescriptorHeap(&heap_desc, IID_PPV_ARGS(&self.descriptors_)))) {
      BOOST_LOG(warning) << "D3D12 compute conversion: couldn't create a descriptor heap"sv;
      return nullptr;
    }
    self.descriptor_size_ = self.device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);

    D3D12_QUERY_HEAP_DESC query_desc {};
    query_desc.Type = D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
    query_desc.Count = 2 * slot_count;
    D3D12_HEAP_PROPERTIES readback_heap {};
    readback_heap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC readback_desc {};
    readback_desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    readback_desc.Width = sizeof(std::uint64_t) * 2 * slot_count;
    readback_desc.Height = 1;
    readback_desc.DepthOrArraySize = 1;
    readback_desc.MipLevels = 1;
    readback_desc.SampleDesc.Count = 1;
    readback_desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    void *mapped = nullptr;
    if (self.timestamp_frequency_ == 0 ||
        FAILED(self.device_->CreateQueryHeap(&query_desc, IID_PPV_ARGS(&self.timestamps_))) ||
        FAILED(self.device_->CreateCommittedResource(&readback_heap, D3D12_HEAP_FLAG_NONE, &readback_desc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&self.timestamp_readback_))) ||
        FAILED(self.timestamp_readback_->Map(0, nullptr, &mapped))) {
      // Conversion works without timings; only the diagnostics are lost.
      BOOST_LOG(warning) << "D3D12 compute conversion: GPU timestamps unavailable"sv;
      self.timestamps_.Reset();
      self.timestamp_readback_.Reset();
    } else {
      self.timestamp_values_ = static_cast<const std::uint64_t *>(mapped);
    }

    self.wait_event_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!self.wait_event_ || !self.create_pipelines()) {
      return nullptr;
    }
    return converter;
  }

  bool d3d12_nv12_converter_t::create_pipelines() {
    D3D12_DESCRIPTOR_RANGE ranges[2] {};
    ranges[0].RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    ranges[0].NumDescriptors = 1;
    ranges[0].BaseShaderRegister = 0;
    ranges[1].RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_UAV;
    ranges[1].NumDescriptors = 2;
    ranges[1].BaseShaderRegister = 0;

    D3D12_ROOT_PARAMETER parameters[3] {};
    parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
    parameters[0].Constants.ShaderRegister = 0;
    parameters[0].Constants.Num32BitValues = root_constant_count;
    parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[1].DescriptorTable.NumDescriptorRanges = 1;
    parameters[1].DescriptorTable.pDescriptorRanges = &ranges[0];
    parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[2].DescriptorTable.NumDescriptorRanges = 1;
    parameters[2].DescriptorTable.pDescriptorRanges = &ranges[1];
    parameters[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    // Same filtering and addressing as the D3D11 conversion sampler.
    D3D12_STATIC_SAMPLER_DESC sampler {};
    sampler.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
    sampler.AddressU = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    sampler.AddressV = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    sampler.AddressW = D3D12_TEXTURE_ADDRESS_MODE_WRAP;
    sampler.ComparisonFunc = D3D12_COMPARISON_FUNC_NEVER;
    sampler.MaxLOD = D3D12_FLOAT32_MAX;
    sampler.ShaderRegister = 0;
    sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    D3D12_ROOT_SIGNATURE_DESC root_desc {};
    root_desc.NumParameters = 3;
    root_desc.pParameters = parameters;
    root_desc.NumStaticSamplers = 1;
    root_desc.pStaticSamplers = &sampler;

    ComPtr<ID3DBlob> serialized;
    ComPtr<ID3DBlob> errors;
    if (FAILED(D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors)) ||
        FAILED(device_->CreateRootSignature(0, serialized->GetBufferPointer(), serialized->GetBufferSize(), IID_PPV_ARGS(&root_signature_)))) {
      BOOST_LOG(warning) << "D3D12 compute conversion: root signature failed: "sv << blob_text(errors.Get());
      return false;
    }

    for (std::size_t index = 0; index < pipelines_.size(); ++index) {
      const D3D_SHADER_MACRO defines[] {
        {"LINEAR_INPUT", index & 2U ? "1" : "0"},
        {"DOWNSCALE", index & 1U ? "1" : "0"},
        {nullptr, nullptr},
      };
      ComPtr<ID3DBlob> compiled;
      ComPtr<ID3DBlob> compile_errors;
      if (FAILED(D3DCompile(shader_source.data(), shader_source.size(), "d3d12_nv12_converter", defines, nullptr, "main_cs", "cs_5_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &compiled, &compile_errors))) {
        BOOST_LOG(warning) << "D3D12 compute conversion: shader failed to compile: "sv << blob_text(compile_errors.Get());
        return false;
      }
      D3D12_COMPUTE_PIPELINE_STATE_DESC pipeline_desc {};
      pipeline_desc.pRootSignature = root_signature_.Get();
      pipeline_desc.CS = {compiled->GetBufferPointer(), compiled->GetBufferSize()};
      if (FAILED(device_->CreateComputePipelineState(&pipeline_desc, IID_PPV_ARGS(&pipelines_[index])))) {
        BOOST_LOG(warning) << "D3D12 compute conversion: couldn't create a compute pipeline"sv;
        return false;
      }
    }
    return true;
  }

  ID3D12PipelineState *d3d12_nv12_converter_t::pipeline_for(const DXGI_FORMAT source_format) {
    if (!supported_source_format(source_format)) {
      return nullptr;
    }
    const auto linear = source_format == DXGI_FORMAT_R16G16B16A16_FLOAT;
    return pipelines_[(linear ? 2U : 0U) + (downscaling_ ? 1U : 0U)].Get();
  }

  bool d3d12_nv12_converter_t::init_output(
    ID3D12Resource *output,
    const std::uint32_t out_width,
    const std::uint32_t out_height,
    const std::uint32_t in_width,
    const std::uint32_t in_height,
    const ::video::color_t &color,
    const std::uint64_t fill_value
  ) {
    static_assert(sizeof(constants_t) == root_constant_count * sizeof(std::uint32_t));
    if (!output || out_width == 0 || out_height == 0 || in_width == 0 || in_height == 0) {
      return false;
    }
    output_ = output;

    // Aspect-fit placement, exactly as d3d_base_encode_device::init_output computes it.
    const auto in_width_f = static_cast<float>(in_width);
    const auto in_height_f = static_cast<float>(in_height);
    const auto scalar = std::fminf(static_cast<float>(out_width) / in_width_f, static_cast<float>(out_height) / in_height_f);
    const auto fit_width = in_width_f * scalar;
    const auto fit_height = in_height_f * scalar;
    downscaling_ = in_width > out_width || in_height > out_height;

    std::copy_n(color.color_vec_y, 4, constants_.color_vec_y);
    std::copy_n(color.color_vec_u, 4, constants_.color_vec_u);
    std::copy_n(color.color_vec_v, 4, constants_.color_vec_v);
    std::copy_n(color.range_y, 2, constants_.range_y);
    std::copy_n(color.range_uv, 2, constants_.range_uv);
    constants_.viewport[0] = (static_cast<float>(out_width) - fit_width) / 2;
    constants_.viewport[1] = (static_cast<float>(out_height) - fit_height) / 2;
    constants_.viewport[2] = fit_width;
    constants_.viewport[3] = fit_height;
    constants_.subsample_offset[0] = 1.0f / fit_width;
    constants_.subsample_offset[1] = 1.0f / fit_height;
    constants_.luma_size[0] = out_width;
    constants_.luma_size[1] = out_height;

    const auto cpu_start = descriptors_->GetCPUDescriptorHandleForHeapStart();
    D3D12_UNORDERED_ACCESS_VIEW_DESC uav {};
    uav.ViewDimension = D3D12_UAV_DIMENSION_TEXTURE2D;
    uav.Format = DXGI_FORMAT_R8_UNORM;
    uav.Texture2D.PlaneSlice = 0;
    device_->CreateUnorderedAccessView(output, nullptr, &uav, cpu_start);
    uav.Format = DXGI_FORMAT_R8G8_UNORM;
    uav.Texture2D.PlaneSlice = 1;
    device_->CreateUnorderedAccessView(output, nullptr, &uav, {cpu_start.ptr + descriptor_size_});

    return submit(nullptr, DXGI_FORMAT_B8G8R8A8_UNORM, true, 0, fill_value);
  }

  ComPtr<ID3D12Resource> d3d12_nv12_converter_t::open_shared_texture(HANDLE handle) const {
    ComPtr<ID3D12Resource> resource;
    if (FAILED(device_->OpenSharedHandle(handle, IID_PPV_ARGS(&resource)))) {
      BOOST_LOG(error) << "D3D12 compute conversion: couldn't open the shared capture texture"sv;
      return nullptr;
    }
    return resource;
  }

  bool d3d12_nv12_converter_t::convert(
    ID3D12Resource *source,
    const DXGI_FORMAT source_format,
    const std::uint64_t capture_value,
    const std::uint64_t consumption_value
  ) {
    if (!source || !output_) {
      return false;
    }
    return submit(source, source_format, false, capture_value, consumption_value);
  }

  bool d3d12_nv12_converter_t::wait_for_slot(const frame_slot_t &slot) noexcept {
    if (slot.consumption_value == 0 || consumption_fence_->GetCompletedValue() >= slot.consumption_value) {
      return true;
    }
    // Only reached when NVENC fell four pictures behind; the encode loop normally drains each one.
    if (FAILED(consumption_fence_->SetEventOnCompletion(slot.consumption_value, wait_event_)) ||
        WaitForSingleObject(wait_event_, 1000) != WAIT_OBJECT_0) {
      BOOST_LOG(error) << "D3D12 compute conversion: a conversion did not finish within one second"sv;
      return false;
    }
    return true;
  }

  bool d3d12_nv12_converter_t::submit(
    ID3D12Resource *source,
    const DXGI_FORMAT source_format,
    const bool fill_black,
    const std::uint64_t capture_value,
    const std::uint64_t consumption_value
  ) {
    auto *pipeline = pipeline_for(source_format);
    if (!pipeline) {
      BOOST_LOG(error) << "D3D12 compute conversion: unsupported capture format "sv << static_cast<int>(source_format);
      return false;
    }
    const auto slot_index = next_slot_ % slot_count;
    auto &slot = slots_[slot_index];
    if (!wait_for_slot(slot) || FAILED(slot.allocator->Reset()) || FAILED(list_->Reset(slot.allocator.Get(), pipeline))) {
      return false;
    }

    const auto cpu_start = descriptors_->GetCPUDescriptorHandleForHeapStart();
    const auto gpu_start = descriptors_->GetGPUDescriptorHandleForHeapStart();
    const auto srv_offset = (2 + slot_index) * descriptor_size_;
    D3D12_SHADER_RESOURCE_VIEW_DESC null_srv {};
    null_srv.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    null_srv.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
    null_srv.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    null_srv.Texture2D.MipLevels = 1;
    device_->CreateShaderResourceView(source, source ? nullptr : &null_srv, {cpu_start.ptr + srv_offset});

    auto constants = constants_;
    constants.fill_black = fill_black ? 1U : 0U;
    ID3D12DescriptorHeap *heaps[] {descriptors_.Get()};
    list_->SetComputeRootSignature(root_signature_.Get());
    list_->SetDescriptorHeaps(1, heaps);
    list_->SetComputeRoot32BitConstants(0, root_constant_count, &constants, 0);
    list_->SetComputeRootDescriptorTable(1, {gpu_start.ptr + srv_offset});
    list_->SetComputeRootDescriptorTable(2, gpu_start);

    if (timestamps_) {
      list_->EndQuery(timestamps_.Get(), D3D12_QUERY_TYPE_TIMESTAMP, static_cast<UINT>(slot_index * 2));
    }

    // The source is promoted from COMMON to a shader-read state implicitly and decays back at the
    // end of the submission; the UAV state of the NV12 target has to be explicit.
    D3D12_RESOURCE_BARRIER barrier {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = output_;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COMMON;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
    list_->ResourceBarrier(1, &barrier);

    const auto chroma_width = (constants_.luma_size[0] + 1U) / 2U;
    const auto chroma_height = (constants_.luma_size[1] + 1U) / 2U;
    list_->Dispatch((chroma_width + 7U) / 8U, (chroma_height + 7U) / 8U, 1);

    std::swap(barrier.Transition.StateBefore, barrier.Transition.StateAfter);
    list_->ResourceBarrier(1, &barrier);

    if (timestamps_) {
      list_->EndQuery(timestamps_.Get(), D3D12_QUERY_TYPE_TIMESTAMP, static_cast<UINT>(slot_index * 2 + 1));
      list_->ResolveQueryData(timestamps_.Get(), D3D12_QUERY_TYPE_TIMESTAMP, static_cast<UINT>(slot_index * 2), 2, timestamp_readback_.Get(), slot_index * 2 * sizeof(std::uint64_t));
    }
    if (FAILED(list_->Close())) {
      return false;
    }

    // The capture copy is the only D3D11 work this conversion depends on; wait for it on the GPU.
    if (capture_value != 0 && FAILED(queue_->Wait(capture_fence_.Get(), capture_value))) {
      return false;
    }
    slot.submitted = std::chrono::steady_clock::now();
    ID3D12CommandList *lists[] {list_.Get()};
    queue_->ExecuteCommandLists(1, lists);
    if (FAILED(queue_->Signal(consumption_fence_.Get(), consumption_value))) {
      return false;
    }
    slot.consumption_value = consumption_value;
    ++next_slot_;
    return true;
  }

  std::optional<d3d12_conversion_timing_t> d3d12_nv12_converter_t::timing(const std::uint64_t consumption_value) {
    if (!timestamp_values_ || consumption_value == 0 || consumption_fence_->GetCompletedValue() < consumption_value) {
      return std::nullopt;
    }
    const auto slot = std::find_if(slots_.begin(), slots_.end(), [consumption_value](const frame_slot_t &candidate) {
      return candidate.consumption_value == consumption_value;
    });
    if (slot == slots_.end()) {
      return std::nullopt;
    }
    const auto slot_index = static_cast<std::size_t>(slot - slots_.begin());
    const auto begin_ticks = timestamp_values_[slot_index * 2];
    const auto end_ticks = timestamp_values_[slot_index * 2 + 1];
    if (end_ticks < begin_ticks) {
      return std::nullopt;
    }

    // Place the GPU ticks on the CPU clock through the queue's calibration pair.
    UINT64 gpu_now = 0;
    UINT64 qpc_at_gpu_now = 0;
    LARGE_INTEGER qpc_frequency {};
    if (FAILED(queue_->GetClockCalibration(&gpu_now, &qpc_at_gpu_now)) || !QueryPerformanceFrequency(&qpc_frequency) ||
        qpc_frequency.QuadPart <= 0) {
      return std::nullopt;
    }
    LARGE_INTEGER qpc_now {};
    QueryPerformanceCounter(&qpc_now);
    const auto steady_now = std::chrono::steady_clock::now();
    const auto ago = [&](const std::uint64_t ticks) {
      // Time between `ticks` and now: GPU ticks up to the calibration point plus QPC since it.
      const auto gpu_ns = static_cast<long double>(static_cast<std::int64_t>(gpu_now - ticks)) * 1e9L / timestamp_frequency_;
      const auto qpc_ns = static_cast<long double>(qpc_now.QuadPart - static_cast<LONGLONG>(qpc_at_gpu_now)) * 1e9L / qpc_frequency.QuadPart;
      return std::chrono::nanoseconds(static_cast<std::int64_t>(gpu_ns + qpc_ns));
    };
    const auto convert_begin = steady_now - std::chrono::duration_cast<std::chrono::steady_clock::duration>(ago(begin_ticks));
    const auto convert_end = steady_now - std::chrono::duration_cast<std::chrono::steady_clock::duration>(ago(end_ticks));
    const auto copy_wait = convert_begin > slot->submitted ?
                             std::chrono::duration_cast<std::chrono::microseconds>(convert_begin - slot->submitted).count() :
                             0;
    return d3d12_conversion_timing_t {
      .copy_wait_us = static_cast<std::uint32_t>(std::min<std::int64_t>(copy_wait, UINT32_MAX)),
      .convert_gpu_us = ticks_to_us(end_ticks - begin_ticks, timestamp_frequency_),
      .convert_end = convert_end,
    };
  }

  void d3d12_nv12_converter_t::wait_idle() noexcept {
    if (!consumption_fence_ || !wait_event_) {
      return;
    }
    std::uint64_t last = 0;
    for (const auto &slot : slots_) {
      last = std::max(last, slot.consumption_value);
    }
    if (last != 0 && consumption_fence_->GetCompletedValue() < last &&
        SUCCEEDED(consumption_fence_->SetEventOnCompletion(last, wait_event_))) {
      WaitForSingleObject(wait_event_, 1000);
    }
  }

}  // namespace platf::dxgi
