// This is a fast sRGB approximation from Microsoft's ColorSpaceUtility.hlsli
float3 ApplySRGBCurve(float3 x)
{
    return x < 0.0031308 ? 12.92 * x : 1.13005 * sqrt(x - 0.00228) - 0.13448 * x + 0.005719;
}

float3 RemoveSRGBCurve(float3 x)
{
    x = saturate(x);
    return x <= 0.04045 ? x / 12.92 : pow((x + 0.055) / 1.055, 2.4);
}

float3 NitsToPQ(float3 L)
{
    // Constants from SMPTE 2084 PQ
    static const float m1 = 2610.0 / 4096.0 / 4;
    static const float m2 = 2523.0 / 4096.0 * 128;
    static const float c1 = 3424.0 / 4096.0;
    static const float c2 = 2413.0 / 4096.0 * 32;
    static const float c3 = 2392.0 / 4096.0 * 32;

    float3 Lp = pow(saturate(L / 10000.0), m1);
    return pow((c1 + c2 * Lp) / (1 + c3 * Lp), m2);
}

float3 NitsToHLG(float3 L)
{
    // ITU-R BT.2100 HLG with the nominal 1000-nit reference display.
    static const float system_gamma = 1.2;
    static const float a = 0.17883277;
    static const float b = 0.28466892;
    static const float c = 0.55991073;

    float3 scene_linear = pow(saturate(L / 1000.0), 1.0 / system_gamma);
    return scene_linear <= (1.0 / 12.0) ?
        sqrt(3.0 * scene_linear) :
        a * log(max(12.0 * scene_linear - b, 1e-6)) + c;
}

float3 Rec709toRec2020(float3 rec709)
{
    static const float3x3 ConvMat =
    {
        0.627402, 0.329292, 0.043306,
        0.069095, 0.919544, 0.011360,
        0.016394, 0.088028, 0.895578
    };
    return mul(ConvMat, rec709);
}

float3 scRGBTo2100PQ(float3 rgb)
{
    // Convert from Rec 709 primaries (used by scRGB) to Rec 2020 primaries (used by Rec 2100)
    rgb = Rec709toRec2020(rgb);

    // 1.0f is defined as 80 nits in the scRGB colorspace
    rgb *= 80;

    // Apply the PQ transfer function on the raw color values in nits
    return NitsToPQ(rgb);
}
