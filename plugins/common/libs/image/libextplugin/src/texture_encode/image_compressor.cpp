/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "image_compressor.h"

#include <unistd.h>
#include <fstream>

#include "securec.h"
#include "media_errors.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ClAstcEnc"

namespace OHOS {
namespace ImagePlugin {
namespace AstcEncBasedCl {
constexpr int MAX_WIDTH = 8192;
constexpr int MAX_HEIGHT = 8192;
constexpr int TEXTURE_HEAD_BYTES = 16;
constexpr int TEXTURE_BLOCK_BYTES = 16;
constexpr int MAGIC_FILE_CONSTANT = 0x5CA1AB13;
constexpr int DIM = 4;
constexpr uint8_t BIT_SHIFT_8BITS = 8;
constexpr uint8_t BIT_SHIFT_16BITS = 16;
constexpr uint8_t BIT_SHIFT_24BITS = 24;
constexpr uint8_t BYTES_MASK = 0xFF;
constexpr uint8_t GLOBAL_WH_NUM_CL = 2;
constexpr size_t MAX_MALLOC_BYTES = 10000000; // max 10MB
constexpr size_t WORK_GROUP_SIZE = 8;


const char *g_programSource = R"(
// Notice: the code from line 42 to line 1266 is openCL language
// openCL cound only support C language style and could not support constexpr and static_cast in same platform
#define DIM (4)
#define BLOCK_SIZE (16)
#define X_GRIDS (4)
#define Y_GRIDS (4)
#define SMALL_VALUE (0.00001f) // avoid divide 0
#define BLOCK_MAX_WEIGHTS (64)
#define BLOCK_MAX_WEIGHTS_SHORT (64)
#define BLOCK_MAX_WEIGHTS_FLOAT (64.0f)
#define CEM_LDR_RGBA_DIRECT (12)
#define CEM_LDR_RGBA_BASE_OFFSET (13)
#define PIXEL_MAX_VALUE (255.0f)

#define START_INDEX (0)
#define FLOAT_ZERO (0.0f)
#define FLOAT_ONE (1.0f)
#define INT_ZERO (0)
#define INT_ONE (1)
#define SHORT_ZERO (0)
#define UINT_ZERO (0)
#define UINT_ONE (1u)
#define EP0_INDEX (0)
#define EP1_INDEX (1)
#define END_POINT_NUM (2)
#define EP0_R_INDEX (0)
#define EP1_R_INDEX (1)
#define EP0_G_INDEX (2)
#define EP1_G_INDEX (3)
#define EP0_B_INDEX (4)
#define EP1_B_INDEX (5)
#define EP0_A_INDEX (6)
#define EP1_A_INDEX (7)
#define COLOR_COMPONENT_NUM (8)
#define QUANTIZE_WEIGHT_MIN (0)
#define QUANTIZE_WEIGHT_MAX (5)
#define INTEGER_INDEX_MAX (242)

#define TRIT_MSB_SIZE (8)
#define TRIT_BLOCK_SIZE (5)
#define TRIT_ROUND_NUM (4)
#define QUINT_MSB_SIZE (7)
#define QUINT_BLOCK_SIZE (3)
#define QUINT_ROUND_NUM (2)
#define ISE_0 (0)
#define ISE_1 (1)
#define ISE_2 (2)
#define ISE_3 (3)
#define ISE_4 (4)

#define WEIGHT_0 (0)
#define WEIGHT_1 (1)
#define WEIGHT_2 (2)
#define WEIGHT_3 (3)
#define WEIGHT_4 (4)
#define WEIGHT_5 (5)
#define WEIGHT_6 (6)
#define WEIGHT_7 (7)
#define WEIGHT_8 (8)
#define WEIGHT_9 (9)
#define WEIGHT_10 (10)
#define WEIGHT_11 (11)
#define WEIGHT_12 (12)
#define WEIGHT_13 (13)
#define WEIGHT_14 (14)
#define WEIGHT_15 (15)

#define BYTE_1_POS (8)
#define BYTE_2_POS (16)
#define BYTE_3_POS (24)
#define BYTE_MASK (0xFFu)
#define CEM_POS (13)
#define COLOR_EP_POS (17)
#define COLOR_EP_HIGH_BIT (15)
#define MASK_FOR_4BITS (0xFu)
#define MASK_FOR_15BITS (0x7FFFu)
#define MASK_FOR_17BITS (0x1FFFFu)

#define HEIGHT_BITS_OFFSET (2)
#define WIDTH_BITS_OFFSET (4)
#define MASK_FOR_2BITS (0x3u)
#define MASK_FOR_1BITS (0x1u)
#define WEIGHT_METHOD_OFFSET (2u)
#define WEIGHT_METHOD_RIGHT_BIT (1)
#define WEIGHT_METHOD_POS (4u)
#define BLOCK_WIDTH_POS (5u)
#define BLOCK_HEIGHT_POS (5u)
#define WEIGHT_PRECISION_POS (9u)
#define IS_DUALPLANE_POS (10u)

#define WEIGHT_QUANT_METHOD (4)
#define ENDPOINT_QUANT_METHOD (20)
#define WEIGHT_RANGE (6)
#define WEIGHT_MAX (5)
#define BLOCK_MODE (67)

__constant short g_scrambleTable[WEIGHT_RANGE] = {
    0, 2, 4, 5, 3, 1,
};

__constant short g_weightUnquant[WEIGHT_RANGE] = {
    0, 64, 12, 52, 25, 39
};
__constant short g_integerFromTrits[243] = { // the numbers of integer to derivated from trits is 243
    0, 1, 2, 4, 5, 6, 8, 9, 10,
    16, 17, 18, 20, 21, 22, 24, 25, 26,
    3, 7, 15, 19, 23, 27, 12, 13, 14,
    32, 33, 34, 36, 37, 38, 40, 41, 42,
    48, 49, 50, 52, 53, 54, 56, 57, 58,
    35, 39, 47, 51, 55, 59, 44, 45, 46,
    64, 65, 66, 68, 69, 70, 72, 73, 74,
    80, 81, 82, 84, 85, 86, 88, 89, 90,
    67, 71, 79, 83, 87, 91, 76, 77, 78,

    128, 129, 130, 132, 133, 134, 136, 137, 138,
    144, 145, 146, 148, 149, 150, 152, 153, 154,
    131, 135, 143, 147, 151, 155, 140, 141, 142,
    160, 161, 162, 164, 165, 166, 168, 169, 170,
    176, 177, 178, 180, 181, 182, 184, 185, 186,
    163, 167, 175, 179, 183, 187, 172, 173, 174,
    192, 193, 194, 196, 197, 198, 200, 201, 202,
    208, 209, 210, 212, 213, 214, 216, 217, 218,
    195, 199, 207, 211, 215, 219, 204, 205, 206,

    96, 97, 98, 100, 101, 102, 104, 105, 106,
    112, 113, 114, 116, 117, 118, 120, 121, 122,
    99, 103, 111, 115, 119, 123, 108, 109, 110,
    224, 225, 226, 228, 229, 230, 232, 233, 234,
    240, 241, 242, 244, 245, 246, 248, 249, 250,
    227, 231, 239, 243, 247, 251, 236, 237, 238,
    28, 29, 30, 60, 61, 62, 92, 93, 94,
    156, 157, 158, 188, 189, 190, 220, 221, 222,
    31, 63, 127, 159, 191, 255, 252, 253, 254
};

void Swap(float4* lhs, float4* rhs)
{
    if ((lhs == NULL) || (rhs == NULL)) {
        return;
    }
    float4 tmp = *lhs;
    *lhs = *rhs;
    *rhs = tmp;
}

void FindMinMax(float4* texels, float4 ptMean, float4 vecK, float4* e0, float4* e1)
{
    if ((texels == NULL) || (e0 == NULL) || (e1 == NULL)) {
        return;
    }
    float a = 1e31f; // max float is clipped to 1e31f
    float b = -1e31f; // min float is clipped to -1e31f
    for (int i = START_INDEX; i < BLOCK_SIZE; ++i) {
        float t = dot(texels[i] - ptMean, vecK);
        a = min(a, t);
        b = max(b, t);
    }
    *e0 = clamp(vecK * a + ptMean, 0.0f, 255.0f); // 8bit max is 255.0f
    *e1 = clamp(vecK * b + ptMean, 0.0f, 255.0f); // 8bit max is 255.0f
    // if the direction_vector ends up pointing from light to dark, FLIP IT!
    // this will make the endpoint the darkest one;
    float4 e0u = round(*e0);
    float4 e1u = round(*e1);
    if (e0u.x + e0u.y + e0u.z > e1u.x + e1u.y + e1u.z) {
        Swap(e0, e1);
    }
}

void MaxAccumulationPixelDirection(float4* texels, float4 ptMean, float4* e0, float4* e1)
{
    if ((texels == NULL) || (e0 == NULL) || (e1 == NULL)) {
        return;
    }
    float4 sumR = (float4)(FLOAT_ZERO);
    float4 sumG = (float4)(FLOAT_ZERO);
    float4 sumB = (float4)(FLOAT_ZERO);
    float4 sumA = (float4)(FLOAT_ZERO);
    for (int i = START_INDEX; i < BLOCK_SIZE; ++i) {
        float4 dt = texels[i] - ptMean;
        sumR += (dt.x > FLOAT_ZERO) ? dt : (float4)(FLOAT_ZERO);
        sumG += (dt.y > FLOAT_ZERO) ? dt : (float4)(FLOAT_ZERO);
        sumB += (dt.z > FLOAT_ZERO) ? dt : (float4)(FLOAT_ZERO);
        sumA += (dt.w > FLOAT_ZERO) ? dt : (float4)(FLOAT_ZERO);
    }
    float dotR = dot(sumR, sumR);
    float dotG = dot(sumG, sumG);
    float dotB = dot(sumB, sumB);
    float dotA = dot(sumA, sumA);
    float maxDot = dotR;
    float4 vecK = sumR;
    if (dotG > maxDot) {
        vecK = sumG;
        maxDot = dotG;
    }
    if (dotB > maxDot) {
        vecK = sumB;
        maxDot = dotB;
    }
    if (dotA > maxDot) {
        vecK = sumA;
        maxDot = dotA;
    }
    // safe normalize
    float lenk = length(vecK);
    vecK = (lenk < SMALL_VALUE) ? vecK : normalize(vecK);
    FindMinMax(texels, ptMean, vecK, e0, e1);
}

void EncodeColorNormal(float4 e0, float4 e1, short* endpointQuantized)
{
    if (endpointQuantized == NULL) {
        return;
    }
    int4 e0q = (int4)((int)(round(e0.x)), (int)(round(e0.y)),
        (int)(round(e0.z)), (int)(round(e0.w)));
    e0q = clamp(e0q, 0, 255);
    int4 e1q = (int4)((int)(round(e1.x)), (int)(round(e1.y)),
        (int)(round(e1.z)), (int)(round(e1.w)));
    e1q = clamp(e1q, 0, 255);
    endpointQuantized[EP0_R_INDEX] = e0q.x;
    endpointQuantized[EP1_R_INDEX] = e1q.x;
    endpointQuantized[EP0_G_INDEX] = e0q.y;
    endpointQuantized[EP1_G_INDEX] = e1q.y;
    endpointQuantized[EP0_B_INDEX] = e0q.z;
    endpointQuantized[EP1_B_INDEX] = e1q.z;
    endpointQuantized[EP0_A_INDEX] = e0q.w;
    endpointQuantized[EP1_A_INDEX] = e1q.w;
}

void DecodeColor(short endpointQuantized[COLOR_COMPONENT_NUM], float4* e0, float4* e1)
{
    if ((endpointQuantized == NULL) || (e0 == NULL) || (e1 == NULL)) {
        return;
    }
    (*e0).x = (float)(endpointQuantized[EP0_R_INDEX]);
    (*e1).x = (float)(endpointQuantized[EP1_R_INDEX]);
    (*e0).y = (float)(endpointQuantized[EP0_G_INDEX]);
    (*e1).y = (float)(endpointQuantized[EP1_G_INDEX]);
    (*e0).z = (float)(endpointQuantized[EP0_B_INDEX]);
    (*e1).z = (float)(endpointQuantized[EP1_B_INDEX]);
    (*e0).w = (float)(endpointQuantized[EP0_A_INDEX]);
    (*e1).w = (float)(endpointQuantized[EP1_A_INDEX]);
}

// calculate quantize weights
short QuantizeWeight(float weight)
{
    short q = (short)(round(weight * ((float)(QUANTIZE_WEIGHT_MAX))));
    return clamp(q, (short)(QUANTIZE_WEIGHT_MIN), (short)(QUANTIZE_WEIGHT_MAX));
}

void CalculateNormalWeights(int part, float4* texels,
    float4 endPoint[END_POINT_NUM], float* projw)
{
    if ((texels == NULL) || (endPoint == NULL) || (projw == NULL)) {
        return;
    }
    int i = START_INDEX;
    float4 vecK = endPoint[EP1_INDEX] - endPoint[EP0_INDEX];
    if (length(vecK) < SMALL_VALUE) {
        for (i = START_INDEX; i < X_GRIDS * Y_GRIDS; ++i) {
            projw[i] = FLOAT_ZERO;
        }
    } else {
        vecK = normalize(vecK);
        float minw = 1e31f; // max float is clipped to 1e31f
        float maxw = -1e31f; // min float is clipped to -1e31f
        for (i = START_INDEX; i < BLOCK_SIZE; ++i) {
            float w = dot(vecK, texels[i] - endPoint[EP0_INDEX]);
            minw = min(w, minw);
            maxw = max(w, maxw);
            projw[i] = w;
        }
        float invlen = maxw - minw;
        invlen = max(SMALL_VALUE, invlen);
        invlen = FLOAT_ONE / invlen; // invlen min is SMALL_VALUE, not zero
        for (i = START_INDEX; i < X_GRIDS * Y_GRIDS; ++i) {
            projw[i] = (projw[i] - minw) * invlen;
        }
    }
}

void QuantizeWeights(float projw[X_GRIDS * Y_GRIDS], short* weights)
{
    for (int i = START_INDEX; i < X_GRIDS * Y_GRIDS; ++i) {
        weights[i] = QuantizeWeight(projw[i]);
    }
}

void CalculateQuantizedWeights(float4* texels, float4 endPoint[END_POINT_NUM], short* weights)
{
    if ((texels == NULL) || (endPoint == NULL) || (weights == NULL)) {
        return;
    }
    float projw[X_GRIDS * Y_GRIDS];
    CalculateNormalWeights(INT_ZERO, texels, endPoint, projw);
    QuantizeWeights(projw, weights);
}

void Orbits8Ptr(uint4* outputs, uint* bitoffset, uint number, uint bitcount)
{
    if ((outputs == NULL) || (bitoffset == NULL)) {
        return;
    }
    uint newpos = *bitoffset + bitcount;
    uint nidx = newpos >> 5; // split low bits (5 bits) to get high bits
    uint uidx = *bitoffset >> 5; // split low bits (5 bits) to get high bits
    uint bitIdx = *bitoffset & 31u; // split low bits to get low bits (31 for mask 5 bits)
    if (uidx == 0) { // high bits is 0 for x
        (*outputs).x |= (number << bitIdx);
        (*outputs).y |= (nidx > uidx) ? (number >> (32u - bitIdx)) : UINT_ZERO; // uint 32 bits
    } else if (uidx == 1) { // high bits is 1 for y
        (*outputs).y |= (number << bitIdx);
        (*outputs).z |= (nidx > uidx) ? (number >> (32u - bitIdx)) : UINT_ZERO; // uint 32 bits
    } else if (uidx == 2) { // high bits is 2 for z
        (*outputs).z |= (number << bitIdx);
        (*outputs).w |= (nidx > uidx) ? (number >> (32u - bitIdx)) : UINT_ZERO; // uint 32 bits
    }
    *bitoffset = newpos;
}

void SplitHighLow(uint n, uint i, int* high, uint* low)
{
    uint low_mask = (UINT_ONE << i) - UINT_ONE;
    *low = n & low_mask;
    *high = ((int)(n >> i)) & 0xFF; // mask 0xFF to get low 8 bits
}

uint ReverseByte(uint p)
{
    p = ((p & 0xFu) << 4) | ((p >> 4) & 0xFu); // 0xFu 4 for reverse
    p = ((p & 0x33u) << 2) | ((p >> 2) & 0x33u); // 0x33u 2 for reverse
    p = ((p & 0x55u) << 1) | ((p >> 1) & 0x55u); // 0x55u 1 for reverse
    return p;
}

void EncodeTrits(uint bitcount, uint tritInput[TRIT_BLOCK_SIZE], uint4* outputs, uint* outpos)
{
    int t0;
    int t1;
    int t2;
    int t3;
    int t4;
    uint m0;
    uint m1;
    uint m2;
    uint m3;
    uint m4;
    SplitHighLow(tritInput[ISE_0], bitcount, &t0, &m0);
    SplitHighLow(tritInput[ISE_1], bitcount, &t1, &m1);
    SplitHighLow(tritInput[ISE_2], bitcount, &t2, &m2);
    SplitHighLow(tritInput[ISE_3], bitcount, &t3, &m3);
    SplitHighLow(tritInput[ISE_4], bitcount, &t4, &m4);
    short index = (short)(t4 * 81 + t3 * 27 + t2 * 9 + t1 * 3 + t0);
    index = clamp(index, (short)(QUANTIZE_WEIGHT_MIN), (short)(INTEGER_INDEX_MAX));
    ushort packhigh = (ushort)(g_integerFromTrits[index]); //trits for 3 9 27 81
    Orbits8Ptr(outputs, outpos, m0, bitcount);
    Orbits8Ptr(outputs, outpos, packhigh & 3u, 2u); // low 2bits (mask 3u) offset 2u

    Orbits8Ptr(outputs, outpos, m1, bitcount);
    Orbits8Ptr(outputs, outpos, (packhigh >> 2) & 3u, 2u); // right shift 2 bits for low 2bits (mask 3u) offset 2u

    Orbits8Ptr(outputs, outpos, m2, bitcount);
    Orbits8Ptr(outputs, outpos, (packhigh >> 4) & 1u, 1u); // right shift 4 bits for low 1bits (mask 1u) offset 1u

    Orbits8Ptr(outputs, outpos, m3, bitcount);
    Orbits8Ptr(outputs, outpos, (packhigh >> 5) & 3u, 2u); // right shift 5 bits for low 2bits (mask 3u) offset 2u

    Orbits8Ptr(outputs, outpos, m4, bitcount);
    Orbits8Ptr(outputs, outpos, (packhigh >> 7) & 1u, 1u); // right shift 7 bits for low 1bits (mask 1u) offset 1u
}

void BiseEndpoints(short numbers[COLOR_COMPONENT_NUM], uint4* outputs, uint* bitPos)
{
    uint bits = 8; // bits == 8; trits == 0; quints == 0
    uint count = 8u; // RGBA 4x2 = 8
    for (uint i = UINT_ZERO; i < count; ++i) {
        Orbits8Ptr(outputs, bitPos, numbers[i], bits);
    }
}

uint4 EndpointIse(float4* ep0, float4* ep1)
{
    short epQuantized[COLOR_COMPONENT_NUM];
    EncodeColorNormal(*ep0, *ep1, epQuantized);
    DecodeColor(epQuantized, ep0, ep1);
    uint4 epIse = (uint4)(UINT_ZERO);
    uint bitPos = UINT_ZERO;
    BiseEndpoints(epQuantized, &epIse, &bitPos);
    return epIse;
}

void BiseWeights(short numbers[BLOCK_SIZE], uint4* outputs)
{
    uint bitPos = UINT_ZERO;
    uint bits = UINT_ONE; // Quints 3 offset 0
    uint trits = UINT_ONE; // Quints 3 offset 1
    uint tritsInput[TRIT_BLOCK_SIZE];
    tritsInput[ISE_0] = numbers[WEIGHT_0];
    tritsInput[ISE_1] = numbers[WEIGHT_1];
    tritsInput[ISE_2] = numbers[WEIGHT_2];
    tritsInput[ISE_3] = numbers[WEIGHT_3];
    tritsInput[ISE_4] = numbers[WEIGHT_4];
    EncodeTrits(bits, tritsInput, outputs, &bitPos);
    tritsInput[ISE_0] = numbers[WEIGHT_5];
    tritsInput[ISE_1] = numbers[WEIGHT_6];
    tritsInput[ISE_2] = numbers[WEIGHT_7];
    tritsInput[ISE_3] = numbers[WEIGHT_8];
    tritsInput[ISE_4] = numbers[WEIGHT_9];
    EncodeTrits(bits, tritsInput, outputs, &bitPos);
    tritsInput[ISE_0] = numbers[WEIGHT_10];
    tritsInput[ISE_1] = numbers[WEIGHT_11];
    tritsInput[ISE_2] = numbers[WEIGHT_12];
    tritsInput[ISE_3] = numbers[WEIGHT_13];
    tritsInput[ISE_4] = numbers[WEIGHT_14];
    EncodeTrits(bits, tritsInput, outputs, &bitPos);
    tritsInput[ISE_0] = numbers[WEIGHT_15];
    tritsInput[ISE_1] = UINT_ZERO;
    tritsInput[ISE_2] = UINT_ZERO;
    tritsInput[ISE_3] = UINT_ZERO;
    tritsInput[ISE_4] = UINT_ZERO;
    EncodeTrits(bits, tritsInput, outputs, &bitPos);
    bitPos = ((TRIT_MSB_SIZE + TRIT_BLOCK_SIZE * bits) * BLOCK_SIZE + TRIT_ROUND_NUM) / TRIT_BLOCK_SIZE;
}

float4 CalTexel(short weight, float4 ep0, float4 ep1)
{
    short weight0 = BLOCK_MAX_WEIGHTS_SHORT - weight;
    return (ep0 * weight0 + ep1 * weight) / BLOCK_MAX_WEIGHTS_FLOAT;
}

uint4 WeightIse(float4* texels, float4 endPoint[END_POINT_NUM], float* errval)
{
    int i = START_INDEX;
    short wtQuantized[X_GRIDS * Y_GRIDS];
    CalculateQuantizedWeights(texels, endPoint, wtQuantized);
    float sumErr = FLOAT_ZERO;
    for (i = START_INDEX; i < X_GRIDS * Y_GRIDS; ++i) {
        short w = wtQuantized[i];
        wtQuantized[i] = g_scrambleTable[w];
        w = wtQuantized[i];
        short wt = g_weightUnquant[w];
        float4 new_texel = CalTexel(wt, endPoint[EP0_INDEX], endPoint[EP1_INDEX]);
        float4 diff = new_texel - texels[i];
        sumErr += dot(diff, diff);
    }
    *errval = sumErr;
    uint4 wtIse = (uint4)(UINT_ZERO);
    BiseWeights(wtQuantized, &wtIse);
    return wtIse;
}

float TryEncode(float4* texels, float4 texelsMean, uint4* epIse, uint4* wtIse)
{
    float errval;
    float4 ep0;
    float4 ep1;
    float4 endPoint[END_POINT_NUM];
    MaxAccumulationPixelDirection(texels, texelsMean, &ep0, &ep1);
    *epIse = EndpointIse(&ep0, &ep1);
    endPoint[EP0_INDEX] = ep0;
    endPoint[EP1_INDEX] = ep1;
    *wtIse = WeightIse(texels, endPoint, &errval);
    return errval;
}

uint4 AssembleBlock(uint blockMode, uint colorEndpointMode, uint4 epIse, uint4 wtIse)
{
    uint4 phyBlk = (uint4)(0, 0, 0, 0); // initialize to (0, 0, 0, 0)
    phyBlk.w |= ReverseByte(wtIse.x & BYTE_MASK) << BYTE_3_POS;
    phyBlk.w |= ReverseByte((wtIse.x >> BYTE_1_POS) & BYTE_MASK) << BYTE_2_POS;
    phyBlk.w |= ReverseByte((wtIse.x >> BYTE_2_POS) & BYTE_MASK) << BYTE_1_POS;
    phyBlk.w |= ReverseByte((wtIse.x >> BYTE_3_POS) & BYTE_MASK);
    phyBlk.z |= ReverseByte(wtIse.y & BYTE_MASK) << BYTE_3_POS;
    phyBlk.z |= ReverseByte((wtIse.y >> BYTE_1_POS) & BYTE_MASK) << BYTE_2_POS;
    phyBlk.z |= ReverseByte((wtIse.y >> BYTE_2_POS) & BYTE_MASK) << BYTE_1_POS;
    phyBlk.z |= ReverseByte((wtIse.y >> BYTE_3_POS) & BYTE_MASK);
    phyBlk.y |= ReverseByte(wtIse.z & BYTE_MASK) << BYTE_3_POS;
    phyBlk.y |= ReverseByte((wtIse.z >> BYTE_1_POS) & BYTE_MASK) << BYTE_2_POS;
    phyBlk.y |= ReverseByte((wtIse.z >> BYTE_2_POS) & BYTE_MASK) << BYTE_1_POS;
    phyBlk.y |= ReverseByte((wtIse.z >> BYTE_3_POS) & BYTE_MASK);
    phyBlk.x = blockMode;

    phyBlk.x |= (colorEndpointMode & MASK_FOR_4BITS) << CEM_POS;
    phyBlk.x |= (epIse.x & MASK_FOR_15BITS) << COLOR_EP_POS;
    phyBlk.y |= ((epIse.x >> COLOR_EP_HIGH_BIT) & MASK_FOR_17BITS);
    phyBlk.y |= (epIse.y & MASK_FOR_15BITS) << COLOR_EP_POS;
    phyBlk.z |= ((epIse.y >> COLOR_EP_HIGH_BIT) & MASK_FOR_17BITS);

    return phyBlk;
}

uint4 EncodeBlock(float4* texels, float4 texelsMean, int blockID, __global uint* errs)
{
    float errval = 10000000.0f; // the errval is initialized to 10000000.0f

    uint4 epIse, wtIse;
    errval = TryEncode(texels, texelsMean, &epIse, &wtIse);

    uint blockMode = BLOCK_MODE;
    uint ColorEndpointMode = CEM_LDR_RGBA_DIRECT;
    errs[blockID] = (uint)(errval);
    return AssembleBlock(blockMode, ColorEndpointMode, epIse, wtIse);
}

void GotTexelFromImage(read_only image2d_t inputImage, float4 texels[BLOCK_SIZE],
    int width, int height, float4 *texelMean)
{
    int2 pos = (int2)(get_global_id(0), get_global_id(1));
    pos.x *= DIM;
    pos.y *= DIM;
    for (int i = 0; i < DIM; ++i) {
        for (int j = 0; j < DIM; ++j) {
            int2 pixelPos = pos + (int2)(j, i);
            if (pixelPos.x >= width) {
                pixelPos.x = width - 1;
            }
            if (pixelPos.y >= height) {
                pixelPos.y = height - 1;
            }
            float4 texel = read_imagef(inputImage, pixelPos);
            texel = clamp(texel * PIXEL_MAX_VALUE, 0.0f, 255.0f);
            texels[i * DIM + j] = texel;
            *texelMean += texel;
        }
    }
}

__kernel void AstcCl(read_only image2d_t inputImage, __global uint4* astcArr, __global uint* errs,
    int width, int height)
{
    const int2 globalSize = (int2)(get_global_size(0), get_global_size(1));
    const int2 globalId = (int2)(get_global_id(0), get_global_id(1));
    int blockID = globalId.y * globalSize.x + globalId.x;
    int blockNum = ((width + DIM - 1) / DIM) * ((height + DIM - 1) / DIM);
    if (blockID >= blockNum) {
        return;
    }
    float4 texels[BLOCK_SIZE];
    float4 texelMean = 0;
    GotTexelFromImage(inputImage, texels, width, height, &texelMean);
    texelMean = texelMean / ((float)(BLOCK_SIZE));
    astcArr[blockID] = EncodeBlock(texels, texelMean, blockID, errs);
}
)";

class OpenCLSoManager {
public:
    OpenCLSoManager();
    ~OpenCLSoManager();
    bool LoadOpenCLSo();
private:
    void *clSoHandle = nullptr;
    bool loadSuccess = false;
    std::mutex openClSoMutex_ = {};
};

static OpenCLSoManager g_clSoManager;
std::mutex checkClBinPathMutex = {};

OpenCLSoManager::OpenCLSoManager()
{
    clSoHandle = nullptr;
    loadSuccess = false;
}

OpenCLSoManager::~OpenCLSoManager()
{
    if (!UnLoadCLExtern(clSoHandle)) {
        IMAGE_LOGE("astcenc OpenCLSoManager UnLoad failed!");
    } else {
        IMAGE_LOGD("astcenc OpenCLSoManager UnLoad success!");
        loadSuccess = false;
    }
}

bool OpenCLSoManager::LoadOpenCLSo()
{
    std::lock_guard<std::mutex> lock(openClSoMutex_);
    if (!loadSuccess) {
        loadSuccess = InitOpenCLExtern(&clSoHandle);
    }
    return loadSuccess;
}

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClClose(ClAstcHandle *clAstcHandle)
{
    if (clAstcHandle == nullptr) {
        IMAGE_LOGE("astc AstcClClose clAstcHandle is nullptr!");
        return CL_ASTC_ENC_FAILED;
    }
    cl_int clRet;
    if (clAstcHandle->kernel != nullptr) {
        clRet = clReleaseKernel(clAstcHandle->kernel);
        if (clRet != CL_SUCCESS) {
            IMAGE_LOGE("astc clReleaseKernel failed ret %{public}d!", clRet);
            return CL_ASTC_ENC_FAILED;
        }
        clAstcHandle->kernel = nullptr;
    }
    if (clAstcHandle->queue != nullptr) {
        clRet = clReleaseCommandQueue(clAstcHandle->queue);
        if (clRet != CL_SUCCESS) {
            IMAGE_LOGE("astc clReleaseCommandQueue failed ret %{public}d!", clRet);
            return CL_ASTC_ENC_FAILED;
        }
        clAstcHandle->queue = nullptr;
    }
    if (clAstcHandle->context != nullptr) {
        clRet = clReleaseContext(clAstcHandle->context);
        if (clRet != CL_SUCCESS) {
            IMAGE_LOGE("astc clReleaseContext failed ret %{public}d!", clRet);
            return CL_ASTC_ENC_FAILED;
        }
        clAstcHandle->context = nullptr;
    }
    if (clAstcHandle->encObj.blockErrs_ != nullptr) {
        free(clAstcHandle->encObj.blockErrs_);
        clAstcHandle->encObj.blockErrs_ = nullptr;
    }
    if (clAstcHandle != nullptr) {
        free(clAstcHandle);
    }
    return CL_ASTC_ENC_SUCCESS;
}

static bool CheckClBinIsExist(const std::string &name)
{
    std::lock_guard<std::mutex> lock(checkClBinPathMutex);
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

static CL_ASTC_STATUS SaveClBin(cl_program program, const std::string &clBinPath)
{
    std::lock_guard<std::mutex> lock(checkClBinPathMutex);
    size_t programBinarySizes;
    cl_int clRet = clGetProgramInfo(program, CL_PROGRAM_BINARY_SIZES, sizeof(size_t), &programBinarySizes, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clGetProgramInfo CL_PROGRAM_BINARY_SIZES failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    bool genBinFail = (programBinarySizes == 0) || (programBinarySizes > MAX_MALLOC_BYTES);
    if (genBinFail) {
        IMAGE_LOGE("astc clGetProgramInfo programBinarySizes %{public}zu too big!", programBinarySizes);
        return CL_ASTC_ENC_FAILED;
    }
    uint8_t *programBinaries = static_cast<uint8_t *>(malloc(programBinarySizes));
    if (programBinaries == nullptr) {
        IMAGE_LOGE("astc programBinaries malloc failed!");
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clGetProgramInfo(program, CL_PROGRAM_BINARIES, programBinarySizes, &programBinaries, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clGetProgramInfo CL_PROGRAM_BINARIES failed ret %{public}d!", clRet);
        free(programBinaries);
        return CL_ASTC_ENC_FAILED;
    }
    FILE *fp = fopen(clBinPath.c_str(), "wb");
    if (fp == nullptr) {
        IMAGE_LOGE("astc create file: %{public}s failed!", clBinPath.c_str());
        free(programBinaries);
        return CL_ASTC_ENC_FAILED;
    }
    CL_ASTC_STATUS ret = CL_ASTC_ENC_SUCCESS;
    if (fwrite(programBinaries, 1, programBinarySizes, fp) != programBinarySizes) {
        IMAGE_LOGE("astc fwrite programBinaries file failed!");
        ret = CL_ASTC_ENC_FAILED;
    }
    if (fclose(fp) != 0) {
        IMAGE_LOGE("astc SaveClBin close file failed!");
        ret = CL_ASTC_ENC_FAILED;
    }
    fp = nullptr;
    free(programBinaries);
    return ret;
}

static CL_ASTC_STATUS BuildProgramAndCreateKernel(cl_program program, ClAstcHandle *clAstcHandle)
{
    cl_int clRet = clBuildProgram(program, 1, &clAstcHandle->deviceID, "-cl-std=CL3.0", nullptr, nullptr);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clBuildProgram failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clAstcHandle->kernel = clCreateKernel(program, "AstcCl", &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateKernel failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS AstcClBuildProgram(ClAstcHandle *clAstcHandle, const std::string &clBinPath)
{
    cl_int clRet;
    cl_program program = nullptr;
    if (!CheckClBinIsExist(clBinPath)) {
        IMAGE_LOGI("astc CheckClBinIsExist failed");
        size_t sourceSize = strlen(g_programSource) + 1; // '\0' occupies 1 bytes
        program = clCreateProgramWithSource(clAstcHandle->context, 1, &g_programSource, &sourceSize, &clRet);
        if (clRet != CL_SUCCESS) {
            IMAGE_LOGE("astc clCreateProgramWithSource failed ret %{public}d!", clRet);
            return CL_ASTC_ENC_FAILED;
        }
        if (BuildProgramAndCreateKernel(program, clAstcHandle) != CL_ASTC_ENC_SUCCESS) {
            IMAGE_LOGE("astc BuildProgramAndCreateKernel failed ret %{public}d!", clRet);
            clReleaseProgram(program);
            return CL_ASTC_ENC_FAILED;
        }
        if (SaveClBin(program, clBinPath) != CL_ASTC_ENC_SUCCESS) {
            IMAGE_LOGI("astc SaveClBin failed!");
        }
    } else {
        IMAGE_LOGI("astc CheckClBinIsExist");
        std::ifstream contents{clBinPath};
        std::string binaryContent{std::istreambuf_iterator<char>{contents}, {}};
        size_t binSize = binaryContent.length();
        bool invaildSize = (binSize == 0) || (binSize > MAX_MALLOC_BYTES);
        if (invaildSize) {
            IMAGE_LOGE("astc AstcClBuildProgram read CLbin file lenth error %{public}zu!", binSize);
            return CL_ASTC_ENC_FAILED;
        }
        const char *binary = static_cast<const char *>(binaryContent.c_str());
        program = clCreateProgramWithBinary(clAstcHandle->context, 1, &clAstcHandle->deviceID, &binSize,
            (const unsigned char **)&binary, nullptr, &clRet);
        if (clRet != CL_SUCCESS) {
            IMAGE_LOGE("astc clCreateProgramWithBinary failed ret %{public}d!", clRet);
            return CL_ASTC_ENC_FAILED;
        }
        if (BuildProgramAndCreateKernel(program, clAstcHandle) != CL_ASTC_ENC_SUCCESS) {
            IMAGE_LOGE("astc BuildProgramAndCreateKernel with bin failed!");
            clReleaseProgram(program);
            return CL_ASTC_ENC_FAILED;
        }
    }
    clRet = clReleaseProgram(program);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clReleaseProgram failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS AstcCreateClKernel(ClAstcHandle *clAstcHandle, const std::string &clBinPath)
{
    if (!g_clSoManager.LoadOpenCLSo()) {
        IMAGE_LOGE("astc InitOpenCL error!");
        return CL_ASTC_ENC_FAILED;
    }
    cl_int clRet;
    cl_platform_id platformID;
    clRet = clGetPlatformIDs(1, &platformID, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clGetPlatformIDs failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clGetDeviceIDs(platformID, CL_DEVICE_TYPE_GPU, 1, &clAstcHandle->deviceID, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clGetDeviceIDs failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clAstcHandle->context = clCreateContext(0, 1, &clAstcHandle->deviceID, NULL, NULL, &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateContext failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    cl_queue_properties props[] = {CL_QUEUE_PRIORITY_KHR, CL_QUEUE_PRIORITY_HIGH_KHR, 0};
    clAstcHandle->queue = clCreateCommandQueueWithProperties(clAstcHandle->context,
        clAstcHandle->deviceID, props, &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateCommandQueueWithProperties failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    if (AstcClBuildProgram(clAstcHandle, clBinPath) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClBuildProgram failed!");
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClCreate(ClAstcHandle **handle, const std::string &clBinPath)
{
    ClAstcHandle *clAstcHandle = static_cast<ClAstcHandle *>(calloc(1, sizeof(ClAstcHandle)));
    if (clAstcHandle == nullptr) {
        IMAGE_LOGE("astc AstcClCreate handle calloc failed!");
        return CL_ASTC_ENC_FAILED;
    }
    *handle = clAstcHandle;
    size_t numMaxBlocks = static_cast<size_t>(((MAX_WIDTH + DIM - 1) / DIM) * ((MAX_HEIGHT + DIM - 1) / DIM));
    clAstcHandle->encObj.blockErrs_ =
        static_cast<uint32_t *>(malloc((numMaxBlocks * sizeof(uint32_t)))); // 8MB mem Max
    if (clAstcHandle->encObj.blockErrs_ == nullptr) {
        IMAGE_LOGE("astc blockErrs_ malloc failed!");
        AstcClClose(*handle);
        return CL_ASTC_ENC_FAILED;
    }
    if (AstcCreateClKernel(clAstcHandle, clBinPath) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcCreateClKernel failed!");
        AstcClClose(*handle);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS AstcClEncImageCheckImageOption(const ClAstcImageOption *imageIn)
{
    if ((imageIn->width <= 0) || (imageIn->height <= 0) || (imageIn->stride < imageIn->width)) {
        IMAGE_LOGE("astc AstcClEncImage width <= 0 or height <= 0 or stride < width!");
        return CL_ASTC_ENC_FAILED;
    }
    if ((imageIn->width > MAX_WIDTH) || (imageIn->height > MAX_HEIGHT)) {
        IMAGE_LOGE("astc AstcClEncImage width[%{public}d] \
            need be [1, %{public}d] and height[%{public}d] need be [1, %{public}d]", \
            imageIn->width, MAX_WIDTH, imageIn->height, MAX_HEIGHT);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClFillImage(ClAstcImageOption *imageIn, uint8_t *data, int32_t stride,
    int32_t width, int32_t height)
{
    if (imageIn == nullptr) {
        IMAGE_LOGE("astc AstcClFillImage imageIn is  nullptr!");
        return CL_ASTC_ENC_FAILED;
    }
    imageIn->data = data;
    imageIn->stride = stride;
    imageIn->width = width;
    imageIn->height = height;
    if (AstcClEncImageCheckImageOption(imageIn) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClEncImageCheckImageOption failed!");
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static void GenAstcHeader(uint8_t *buffer, uint8_t blockX, uint8_t blockY, uint32_t dimX, uint32_t dimY)
{
    uint8_t *headInfo = buffer;
    *headInfo++ = MAGIC_FILE_CONSTANT & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_8BITS) & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_16BITS) & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_24BITS) & BYTES_MASK;
    *headInfo++ = static_cast<uint8_t>(blockX);
    *headInfo++ = static_cast<uint8_t>(blockY);
    *headInfo++ = 1;
    *headInfo++ = dimX & BYTES_MASK;
    *headInfo++ = (dimX >> BIT_SHIFT_8BITS) & BYTES_MASK;
    *headInfo++ = (dimX >> BIT_SHIFT_16BITS) & BYTES_MASK;
    *headInfo++ = dimY & BYTES_MASK;
    *headInfo++ = (dimY >> BIT_SHIFT_8BITS) & BYTES_MASK;
    *headInfo++ = (dimY >> BIT_SHIFT_16BITS) & BYTES_MASK;
    *headInfo++ = 1;
    *headInfo++ = 0;
    *headInfo++ = 0;
}

static void ReleaseClAstcObj(ClAstcObjEnc *obj)
{
    cl_int clRet;
    if (obj != nullptr) {
        if (obj->inputImage != nullptr) {
            clRet = clReleaseMemObject(obj->inputImage);
            if (clRet != CL_SUCCESS) {
                IMAGE_LOGE("astc inputImage release failed ret %{public}d!", clRet);
            }
            obj->inputImage = nullptr;
        }
        if (obj->astcResult != nullptr) {
            clRet = clReleaseMemObject(obj->astcResult);
            if (clRet != CL_SUCCESS) {
                IMAGE_LOGE("astc astcResult release failed ret %{public}d!", clRet);
            }
            obj->astcResult = nullptr;
        }
        if (obj->errBuffer != nullptr) {
            clRet = clReleaseMemObject(obj->errBuffer);
            if (clRet != CL_SUCCESS) {
                IMAGE_LOGE("astc errBuffer release failed ret %{public}d!", clRet);
            }
            obj->errBuffer = nullptr;
        }
    }
}

static void GetMaxAndSumVal(size_t numBlocks, uint32_t *blockErrs, uint32_t &maxVal, uint32_t &sumVal)
{
    sumVal = 0;
    for (size_t i = 0; i < numBlocks; i++) {
        sumVal += blockErrs[i];
        maxVal = fmax(maxVal, blockErrs[i]);
    }
}

static CL_ASTC_STATUS ClCreateBufferAndImage(const ClAstcImageOption *imageIn,
    ClAstcHandle *clAstcHandle, ClAstcObjEnc *encObj)
{
    uint8_t *data = imageIn->data;
    int32_t stride = imageIn->stride;
    int32_t width = imageIn->width;
    int32_t height = imageIn->height;
    size_t numBlocks = static_cast<size_t>(((width + DIM - 1) / DIM) * ((height + DIM - 1) / DIM));
    uint32_t *blockErrs = encObj->blockErrs_;
    size_t blockErrBytes = sizeof(uint32_t) * numBlocks;
    encObj->astcSize = numBlocks * TEXTURE_BLOCK_BYTES;
    if ((blockErrs == nullptr) || (memset_s(blockErrs, blockErrBytes, 0, blockErrBytes))) {
        IMAGE_LOGE("astc blockErrs is nullptr or memset failed!");
        return CL_ASTC_ENC_FAILED;
    }
    cl_image_format imageFormat = { CL_RGBA, CL_UNORM_INT8 };
    cl_image_desc desc = { CL_MEM_OBJECT_IMAGE2D, stride, height };
    cl_int clRet;
    encObj->inputImage = clCreateImage(clAstcHandle->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, &imageFormat,
        &desc, data, &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateImage failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    encObj->astcResult = clCreateBuffer(clAstcHandle->context,
        CL_MEM_ALLOC_HOST_PTR, encObj->astcSize, NULL, &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateBuffer astcResult failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    encObj->errBuffer = clCreateBuffer(clAstcHandle->context, CL_MEM_USE_HOST_PTR, blockErrBytes, blockErrs, &clRet);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clCreateBuffer errBuffer failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS ClKernelArgSet(ClAstcHandle *clAstcHandle, ClAstcObjEnc *encObj, int width, int height)
{
    int32_t kernelId = 0;
    cl_int clRet = clSetKernelArg(clAstcHandle->kernel, kernelId++, sizeof(cl_mem), &encObj->inputImage);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clSetKernelArg inputImage failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clSetKernelArg(clAstcHandle->kernel, kernelId++, sizeof(cl_mem), &encObj->astcResult);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clSetKernelArg astcResult failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clSetKernelArg(clAstcHandle->kernel, kernelId++, sizeof(cl_mem), &encObj->errBuffer);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clSetKernelArg errBuffer failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clSetKernelArg(clAstcHandle->kernel, kernelId++, sizeof(int), &width);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clSetKernelArg width failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clSetKernelArg(clAstcHandle->kernel, kernelId++, sizeof(int), &height);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clSetKernelArg height failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS ClKernelArgSetAndRun(ClAstcHandle *clAstcHandle, ClAstcObjEnc *encObj, int width, int height)
{
    if (ClKernelArgSet(clAstcHandle, encObj, width, height) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc ClKernelArgSet failed!");
        return CL_ASTC_ENC_FAILED;
    }
    size_t local[] = {WORK_GROUP_SIZE, WORK_GROUP_SIZE};
    size_t global[GLOBAL_WH_NUM_CL];
    global[0] = static_cast<size_t>((width + DIM - 1) / DIM);
    global[1] = static_cast<size_t>((height + DIM - 1) / DIM);
    size_t localMax;
    cl_int clRet = clGetKernelWorkGroupInfo(clAstcHandle->kernel, clAstcHandle->deviceID, CL_KERNEL_WORK_GROUP_SIZE,
        sizeof(size_t), &localMax, nullptr);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clGetKernelWorkGroupInfo failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    while (local[0] * local[1] > localMax) {
        local[0]--;
        local[1]--;
    }
    bool invalidLocal = (local[0] < 1) || (local[1] < 1);
    if (invalidLocal) {
        IMAGE_LOGE("astc ClKernelArgSetAndRun local set failed!");
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clEnqueueNDRangeKernel(clAstcHandle->queue, clAstcHandle->kernel, GLOBAL_WH_NUM_CL, nullptr, global, local,
        0, nullptr, nullptr);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clEnqueueNDRangeKernel failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    clRet = clFinish(clAstcHandle->queue);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clFinish failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    return CL_ASTC_ENC_SUCCESS;
}

static CL_ASTC_STATUS ClReadAstcBufAndBlockError(ClAstcHandle *clAstcHandle, ClAstcObjEnc *encObj,
    const ClAstcImageOption *imageIn, uint8_t *buffer)
{
    cl_int clRet = clEnqueueReadBuffer(clAstcHandle->queue, encObj->astcResult, CL_TRUE,
        0, encObj->astcSize, buffer + TEXTURE_HEAD_BYTES, 0, NULL, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clEnqueueReadBuffer astcResult failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    uint32_t maxVal = 0;
    uint32_t sumVal = 0;
    size_t numBlocks = ((imageIn->width + DIM - 1) / DIM) * ((imageIn->height + DIM - 1) / DIM);
    clRet = clEnqueueReadBuffer(clAstcHandle->queue, encObj->errBuffer, CL_TRUE,
        0, sizeof(uint32_t) * numBlocks, encObj->blockErrs_, 0, NULL, NULL);
    if (clRet != CL_SUCCESS) {
        IMAGE_LOGE("astc clEnqueueReadBuffer blockErrs failed ret %{public}d!", clRet);
        return CL_ASTC_ENC_FAILED;
    }
    GetMaxAndSumVal(numBlocks, encObj->blockErrs_, maxVal, sumVal);
    return CL_ASTC_ENC_SUCCESS;
}

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClEncImage(ClAstcHandle *clAstcHandle,
    const ClAstcImageOption *imageIn, uint8_t *buffer)
{
    if ((clAstcHandle == nullptr) || (imageIn == nullptr) || (buffer == nullptr)) {
        IMAGE_LOGE("astc AstcClEncImage clAstcHandle or imageIn or buffer is nullptr!");
        return CL_ASTC_ENC_FAILED;
    }
    if (AstcClEncImageCheckImageOption(imageIn) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClEncImageCheckImageOption failed!");
        return CL_ASTC_ENC_FAILED;
    }
    GenAstcHeader(buffer, DIM, DIM, imageIn->width, imageIn->height);
    ClAstcObjEnc *encObj = &clAstcHandle->encObj;
    if (encObj == nullptr) {
        IMAGE_LOGE("astc AstcClEncImage clAstcHandle encObj is nullptr!");
        return CL_ASTC_ENC_FAILED;
    }
    if (ClCreateBufferAndImage(imageIn, clAstcHandle, encObj) != CL_ASTC_ENC_SUCCESS) {
        ReleaseClAstcObj(encObj);
        IMAGE_LOGE("astc ClCreateBufferAndImage failed!");
        return CL_ASTC_ENC_FAILED;
    }
    if (ClKernelArgSetAndRun(clAstcHandle, encObj, imageIn->width, imageIn->height) != CL_ASTC_ENC_SUCCESS) {
        ReleaseClAstcObj(encObj);
        IMAGE_LOGE("astc ClKernelArgSetAndRun failed!");
        return CL_ASTC_ENC_FAILED;
    }
    if (ClReadAstcBufAndBlockError(clAstcHandle, encObj, imageIn, buffer) != CL_ASTC_ENC_SUCCESS) {
        ReleaseClAstcObj(encObj);
        IMAGE_LOGE("astc ClReadAstcBufAndBlockError failed!");
        return CL_ASTC_ENC_FAILED;
    }
    ReleaseClAstcObj(encObj);
    return CL_ASTC_ENC_SUCCESS;
}
}
}
}