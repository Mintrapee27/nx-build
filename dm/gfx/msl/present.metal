// The present: the frame drawn into the drawable, cropped (nvn_mtl.m present_pipeline)
#include <metal_stdlib>
using namespace metal;
struct V { float4 p [[position]]; float2 uv; };
vertex V vs(uint id [[vertex_id]]) { float2 uv = float2((id << 1) & 2, id & 2); V o; o.p = float4(uv * float2(2, -2) + float2(-1, 1), 0, 1); o.uv = uv; return o; }
struct Crop { float4 rect; float4 edge; };
// Auto-HDR (nvn_mtl.m present_pipeline, front_mac.m hdr_apply): on a screen with HDR on, the drawable is extended linear sRGB in half floats, where 1.0 is SDR white and the
// screen shows up to its headroom above it. The game's picture is SDR (sRGB bytes, read raw): decoded to linear, it stays as it is up to HDR_KNEE of white and its highlights
// are lifted from there to hdr_peak at white, along a curve that starts with the picture's own slope (no step at the knee), scaling the colour by its luminance (no hue shift)
constant float hdr_peak [[function_constant(0)]];
constant bool hdr_on = is_function_constant_defined(hdr_peak);
constant float HDR_KNEE = 0.55;
static float3 srgb_linear(float3 c) { return select(pow((c + 0.055) / 1.055, 2.4), c / 12.92, c <= 0.04045); }
static float3 hdr_lift(float3 l) {
    float y = dot(l, float3(0.2126, 0.7152, 0.0722));
    if (y <= HDR_KNEE) return l;
    float t = min((y - HDR_KNEE) / (1.0 - HDR_KNEE), 1.0);
    float y2 = HDR_KNEE + (1.0 - HDR_KNEE) * t + (hdr_peak - 1.0) * t * t;
    return l * (y2 / y);
}
// Native HDR (hle_vi.c: a game told the display is in HDR draws HDR10, RGB10A2 holding PQ-encoded BT.2020): decoded to nits, converted to BT.709 primaries and divided by
// the paper white the game was told (pq_white nits, SDR white = 1.0). On the HDR layer that is extended linear sRGB, rolling off into the screen's current headroom (hdr_peak); on
// an SDR layer (the window moved to an SDR screen) it rolls off above 0.8 of white and is encoded as sRGB bytes
constant float pq_white [[function_constant(1)]];
constant bool src_pq = is_function_constant_defined(pq_white);
static float3 pq_nits(float3 e) {
    const float m1 = 0.1593017578125, m2 = 78.84375, c1 = 0.8359375, c2 = 18.8515625, c3 = 18.6875;
    float3 p = pow(saturate(e), 1.0 / m2);
    return pow(max(p - c1, 0.0) / (c2 - c3 * p), 1.0 / m1) * 10000.0;
}
static float3 bt2020_to_709(float3 c) {
    return float3(dot(c, float3(1.6605, -0.5876, -0.0728)), dot(c, float3(-0.1246, 1.1329, -0.0083)), dot(c, float3(-0.0182, -0.1006, 1.1187)));
}
static float3 srgb_encode(float3 l) { return select(1.055 * pow(l, 1.0 / 2.4) - 0.055, l * 12.92, l <= 0.0031308); }
fragment float4 fs(V in [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]], constant Crop& c [[buffer(0)]]) {
    float4 px = t.sample(s, clamp(in.uv * c.rect.zw + c.rect.xy, c.edge.xy, c.edge.zw));
    if (src_pq) {
        float3 l = max(bt2020_to_709(pq_nits(px.rgb)) / pq_white, 0.0);
        if (hdr_on) {   // above 3/4 of the screen's headroom the luminance rolls off into it, so highlights mastered brighter than the screen shows keep their detail
            float y = dot(l, float3(0.2126, 0.7152, 0.0722)), k = 0.75 * hdr_peak;
            if (y > k) l *= (k + (hdr_peak - k) * (1.0 - exp(-(y - k) / (hdr_peak - k)))) / y;
            return float4(l, 1.0);
        }
        float3 r = select(0.8 + 0.2 * (1.0 - exp(-(l - 0.8) / 0.2)), l, l <= 0.8);   // soft knee into SDR white
        return float4(srgb_encode(saturate(r)), 1.0);
    }
    if (hdr_on) return float4(hdr_lift(srgb_linear(saturate(px.rgb))), 1.0);
    return px;
}
