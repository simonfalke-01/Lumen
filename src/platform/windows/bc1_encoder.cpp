/**
 * @file src/platform/windows/bc1_encoder.cpp
 * @brief Intra-only BC1 encoder that stands in for NVENC on very fast links.
 */
#include "bc1_encoder.h"

// standard includes
#include <algorithm>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

// platform includes
#include <d3dcompiler.h>
#include <wrl/client.h>

// local includes
#include "src/logging.h"
#include "src/video.h"

using namespace std::literals;

namespace platf::dxgi {
  namespace {
    using Microsoft::WRL::ComPtr;

    /** @brief Bytes before the first block: "LBC1", width, height, block bytes, reserved. */
    constexpr std::size_t header_bytes = 16;

    /**
     * One thread compresses one 4x4 block. Endpoints come from the block's bounding box,
     * oriented along the dominant colour diagonal and inset by 1/16, which is the usual
     * real-time BC1 fit; indices project each texel onto the endpoint axis.
     */
    constexpr std::string_view shader_source = R"(
Texture2D<float4> source : register(t0);
RWByteAddressBuffer blocks : register(u0);
cbuffer parameters : register(b0) {
  uint width;
  uint height;
  uint blocks_x;
  uint blocks_y;
};

uint pack565(float3 color) {
  uint3 q = uint3(round(saturate(color) * float3(31.0, 63.0, 31.0)));
  return (q.r << 11) | (q.g << 5) | q.b;
}

float3 unpack565(uint value) {
  return float3((value >> 11) & 31, (value >> 5) & 63, value & 31) / float3(31.0, 63.0, 31.0);
}

[numthreads(8, 8, 1)]
void main_cs(uint3 id : SV_DispatchThreadID) {
  if (id.x >= blocks_x || id.y >= blocks_y) {
    return;
  }
  float3 texels[16];
  float3 low = float3(1.0, 1.0, 1.0);
  float3 high = float3(0.0, 0.0, 0.0);
  [unroll] for (uint i = 0; i < 16; ++i) {
    uint2 position = min(uint2(id.x * 4 + (i & 3), id.y * 4 + (i >> 2)), uint2(width - 1, height - 1));
    texels[i] = source.Load(int3(position, 0)).rgb;
    low = min(low, texels[i]);
    high = max(high, texels[i]);
  }
  float3 center = (low + high) * 0.5;
  float red_green = 0.0;
  float red_blue = 0.0;
  [unroll] for (uint j = 0; j < 16; ++j) {
    float3 offset = texels[j] - center;
    red_green += offset.r * offset.g;
    red_blue += offset.r * offset.b;
  }
  if (red_green < 0.0) {
    float swap = low.g; low.g = high.g; high.g = swap;
  }
  if (red_blue < 0.0) {
    float swap = low.b; low.b = high.b; high.b = swap;
  }
  float3 inset = (high - low) / 16.0;
  high -= inset;
  low += inset;

  uint color0 = pack565(high);
  uint color1 = pack565(low);
  if (color0 < color1) {
    uint swap = color0; color0 = color1; color1 = swap;
  }
  uint indices = 0;
  if (color0 != color1) {
    float3 end0 = unpack565(color0);
    float3 end1 = unpack565(color1);
    float3 axis = end1 - end0;
    float length_squared = max(dot(axis, axis), 1e-8);
    [unroll] for (uint k = 0; k < 16; ++k) {
      float t = saturate(dot(texels[k] - end0, axis) / length_squared);
      // Four-colour mode palette order: end0, end1, 2/3 end0 + 1/3 end1, 1/3 end0 + 2/3 end1.
      uint index = t < (1.0 / 6.0) ? 0 : t < 0.5 ? 2 : t < (5.0 / 6.0) ? 3 : 1;
      indices |= index << (2 * k);
    }
  }
  blocks.Store2((id.y * blocks_x + id.x) * 8, uint2(color0 | (color1 << 16), indices));
}
)";

    /** @brief Append an unsigned LEB128 value. */
    void append_leb128(std::vector<std::uint8_t> &output, std::size_t value) {
      do {
        auto byte = static_cast<std::uint8_t>(value & 0x7FU);
        value >>= 7U;
        if (value != 0) {
          byte |= 0x80U;
        }
        output.push_back(byte);
      } while (value != 0);
    }

    void append_le(std::vector<std::uint8_t> &output, std::uint32_t value, std::size_t bytes) {
      for (std::size_t index = 0; index < bytes; ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * index)));
      }
    }

    class bc1_encoder final: public nvenc::nvenc_d3d11_interface {
    public:
      explicit bc1_encoder(ID3D11Device *device):
          device_(device) {
        device_->GetImmediateContext(&context_);
      }

      ID3D11Texture2D *get_input_texture() override {
        return input_.Get();
      }

      bool create_encoder(
        const nvenc::nvenc_config &,
        const video::config_t &client_config,
        const video::stream_colorspace_t &,
        platf::pix_fmt_e,
        const std::optional<nvenc::hdr_static_metadata_t> &
      ) override {
        destroy_encoder();
        width_ = static_cast<std::uint32_t>(client_config.width);
        height_ = static_cast<std::uint32_t>(client_config.height);
        if (width_ == 0 || height_ == 0) {
          return false;
        }
        blocks_x_ = (width_ + 3U) / 4U;
        blocks_y_ = (height_ + 3U) / 4U;
        block_bytes_ = blocks_x_ * blocks_y_ * 8U;

        ComPtr<ID3DBlob> compiled;
        ComPtr<ID3DBlob> errors;
        if (FAILED(D3DCompile(
              shader_source.data(),
              shader_source.size(),
              "bc1_encoder",
              nullptr,
              nullptr,
              "main_cs",
              "cs_5_0",
              D3DCOMPILE_OPTIMIZATION_LEVEL3,
              0,
              &compiled,
              &errors
            ))) {
          BOOST_LOG(error) << "BC1 encoder shader failed to compile: "sv
                           << (errors ? std::string_view(static_cast<const char *>(errors->GetBufferPointer()), errors->GetBufferSize()) : "unknown"sv);
          return false;
        }
        if (FAILED(device_->CreateComputeShader(compiled->GetBufferPointer(), compiled->GetBufferSize(), nullptr, &shader_))) {
          return false;
        }

        D3D11_TEXTURE2D_DESC texture {};
        texture.Width = width_;
        texture.Height = height_;
        texture.MipLevels = 1;
        texture.ArraySize = 1;
        texture.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        texture.SampleDesc.Count = 1;
        texture.Usage = D3D11_USAGE_DEFAULT;
        texture.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
        if (FAILED(device_->CreateTexture2D(&texture, nullptr, &input_)) ||
            FAILED(device_->CreateShaderResourceView(input_.Get(), nullptr, &input_view_))) {
          return false;
        }

        D3D11_BUFFER_DESC output {};
        output.ByteWidth = block_bytes_;
        output.Usage = D3D11_USAGE_DEFAULT;
        output.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
        output.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
        if (FAILED(device_->CreateBuffer(&output, nullptr, &blocks_))) {
          return false;
        }
        D3D11_UNORDERED_ACCESS_VIEW_DESC view {};
        view.Format = DXGI_FORMAT_R32_TYPELESS;
        view.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        view.Buffer.NumElements = block_bytes_ / 4U;
        view.Buffer.Flags = D3D11_BUFFER_UAV_FLAG_RAW;
        if (FAILED(device_->CreateUnorderedAccessView(blocks_.Get(), &view, &blocks_view_))) {
          return false;
        }

        D3D11_BUFFER_DESC staging {};
        staging.ByteWidth = block_bytes_;
        staging.Usage = D3D11_USAGE_STAGING;
        staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        if (FAILED(device_->CreateBuffer(&staging, nullptr, &staging_))) {
          return false;
        }

        const std::uint32_t parameters[4] {width_, height_, blocks_x_, blocks_y_};
        D3D11_BUFFER_DESC constants {};
        constants.ByteWidth = sizeof(parameters);
        constants.Usage = D3D11_USAGE_IMMUTABLE;
        constants.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        D3D11_SUBRESOURCE_DATA initial {parameters, 0, 0};
        if (FAILED(device_->CreateBuffer(&constants, &initial, &constants_))) {
          return false;
        }
        BOOST_LOG(info) << "BC1 encoder ready for "sv << width_ << "x"sv << height_ << " ("sv << block_bytes_ << " bytes per frame)"sv;
        return true;
      }

      bool update_hdr_metadata(const nvenc::hdr_static_metadata_t &) override {
        return false;
      }

      void destroy_encoder() override {
        shader_.Reset();
        input_view_.Reset();
        input_.Reset();
        blocks_view_.Reset();
        blocks_.Reset();
        staging_.Reset();
        constants_.Reset();
      }

      nvenc::nvenc_encoded_frame encode_frame(std::uint64_t frame_index, bool) override {
        nvenc::nvenc_encoded_frame frame;
        frame.frame_index = frame_index;
        frame.idr = true;
        if (!shader_) {
          return frame;
        }
        ID3D11ShaderResourceView *views[] {input_view_.Get()};
        ID3D11UnorderedAccessView *outputs[] {blocks_view_.Get()};
        ID3D11Buffer *constants[] {constants_.Get()};
        context_->CSSetShader(shader_.Get(), nullptr, 0);
        context_->CSSetShaderResources(0, 1, views);
        context_->CSSetUnorderedAccessViews(0, 1, outputs, nullptr);
        context_->CSSetConstantBuffers(0, 1, constants);
        context_->Dispatch((blocks_x_ + 7U) / 8U, (blocks_y_ + 7U) / 8U, 1);
        ID3D11ShaderResourceView *no_views[] {nullptr};
        ID3D11UnorderedAccessView *no_outputs[] {nullptr};
        context_->CSSetShaderResources(0, 1, no_views);
        context_->CSSetUnorderedAccessViews(0, 1, no_outputs, nullptr);
        context_->CSSetShader(nullptr, nullptr, 0);
        context_->CopyResource(staging_.Get(), blocks_.Get());

        D3D11_MAPPED_SUBRESOURCE mapped {};
        if (FAILED(context_->Map(staging_.Get(), 0, D3D11_MAP_READ, 0, &mapped))) {
          BOOST_LOG(error) << "BC1 encoder readback failed"sv;
          return frame;
        }
        const auto payload_bytes = header_bytes + block_bytes_;
        frame.data.reserve(1U + 5U + payload_bytes);
        frame.data.push_back(0x7AU);  // AV1 padding OBU (type 15) with an explicit size field.
        append_leb128(frame.data, payload_bytes);
        frame.data.insert(frame.data.end(), {'L', 'B', 'C', '1'});
        append_le(frame.data, width_, 2);
        append_le(frame.data, height_, 2);
        append_le(frame.data, block_bytes_, 4);
        append_le(frame.data, 0, 4);
        const auto *source = static_cast<const std::uint8_t *>(mapped.pData);
        frame.data.insert(frame.data.end(), source, source + block_bytes_);
        context_->Unmap(staging_.Get(), 0);
        return frame;
      }

      bool invalidate_ref_frames(std::uint64_t, std::uint64_t) override {
        return true;  // Every frame is intra-only.
      }

      bool reconfigure_bitrate(std::uint32_t) override {
        return true;  // BC1 is fixed-rate.
      }

    private:
      ComPtr<ID3D11Device> device_;
      ComPtr<ID3D11DeviceContext> context_;
      ComPtr<ID3D11ComputeShader> shader_;
      ComPtr<ID3D11Texture2D> input_;
      ComPtr<ID3D11ShaderResourceView> input_view_;
      ComPtr<ID3D11Buffer> blocks_;
      ComPtr<ID3D11UnorderedAccessView> blocks_view_;
      ComPtr<ID3D11Buffer> staging_;
      ComPtr<ID3D11Buffer> constants_;
      std::uint32_t width_ {};
      std::uint32_t height_ {};
      std::uint32_t blocks_x_ {};
      std::uint32_t blocks_y_ {};
      std::uint32_t block_bytes_ {};
    };
  }  // namespace

  std::unique_ptr<nvenc::nvenc_d3d11_interface> make_bc1_encoder(ID3D11Device *device) {
    return std::make_unique<bc1_encoder>(device);
  }

}  // namespace platf::dxgi
