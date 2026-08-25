#include "include/common.hlsl"

Texture1D<float4> vdd_color_lut : register(t1);

cbuffer vdd_color_transform_cbuffer : register(b1) {
    float4 vdd_color_matrix_0;
    float4 vdd_color_matrix_1;
    float4 vdd_color_matrix_2;
    uint vdd_transform_type;
    uint vdd_input_linear;
    uint vdd_output_transfer;
    uint vdd_lut_size;
};

float VddLutCoordinate(float value)
{
    return (saturate(value) * (vdd_lut_size - 1) + 0.5) / vdd_lut_size;
}

float3 ApplyVddLut(float3 value)
{
    if (vdd_lut_size == 0) {
        return value;
    }
    return float3(
        vdd_color_lut.SampleLevel(def_sampler, VddLutCoordinate(value.r), 0).r,
        vdd_color_lut.SampleLevel(def_sampler, VddLutCoordinate(value.g), 0).g,
        vdd_color_lut.SampleLevel(def_sampler, VddLutCoordinate(value.b), 0).b
    );
}

float3 ApplyVddWireTransfer(float3 linear_rgb)
{
    if (vdd_output_transfer == 1) {
        return NitsToPQ(linear_rgb * 80.0);
    }
    if (vdd_output_transfer == 2) {
        return NitsToHLG(linear_rgb * 80.0);
    }
    return ApplySRGBCurve(saturate(linear_rgb));
}

float3 ApplyVddColorTransform(float3 input_rgb)
{
    if (vdd_transform_type == 2) {
        float3 wire_rgb;
        if (vdd_output_transfer == 1) {
            float3 linear_rgb = vdd_input_linear != 0 ? input_rgb : RemoveSRGBCurve(input_rgb);
            wire_rgb = NitsToPQ(Rec709toRec2020(linear_rgb) * 80.0);
        } else if (vdd_output_transfer == 2) {
            float3 linear_rgb = vdd_input_linear != 0 ? input_rgb : RemoveSRGBCurve(input_rgb);
            wire_rgb = NitsToHLG(Rec709toRec2020(linear_rgb) * 80.0);
        } else {
            wire_rgb = vdd_input_linear != 0 ? ApplySRGBCurve(saturate(input_rgb)) : saturate(input_rgb);
        }
        return ApplyVddLut(wire_rgb);
    }

    float3 linear_rgb = vdd_input_linear != 0 ? input_rgb : RemoveSRGBCurve(input_rgb);
    float3 transformed_linear = float3(
        dot(vdd_color_matrix_0.xyz, linear_rgb) + vdd_color_matrix_0.w,
        dot(vdd_color_matrix_1.xyz, linear_rgb) + vdd_color_matrix_1.w,
        dot(vdd_color_matrix_2.xyz, linear_rgb) + vdd_color_matrix_2.w
    );
    return ApplyVddLut(ApplyVddWireTransfer(transformed_linear));
}

#define CONVERT_FUNCTION ApplyVddColorTransform
#define CONVERT_EACH_SAMPLE
