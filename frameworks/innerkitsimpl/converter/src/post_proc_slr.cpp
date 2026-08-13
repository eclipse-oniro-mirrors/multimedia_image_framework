/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "post_proc_slr.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <unistd.h>
#include <vector>
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "ffrt.h"
#endif
#include "image_log.h"
#include "image_trace.h"
#include "image_utils.h"
#include "memory_manager.h"

namespace OHOS {
namespace Media {
using namespace std;

constexpr float PI = 3.14159265;
constexpr float EPSILON = 1e-6;
constexpr int FFRT_THREAD_LIMIT = 8;
constexpr int SLR_MIN_RADIUS = 2;
constexpr int SLR_WEIGHT_SPAN_FACTOR = 2;
constexpr size_t SLR_PIXEL_BYTES = sizeof(uint32_t);

bool SLRMat::IsValid() const
{
    if (data_ == nullptr || size_.width <= 0 || size_.height <= 0 || rowStride_ <= 0 ||
        rowStride_ < size_.width) {
        return false;
    }
    const size_t stride = static_cast<size_t>(rowStride_);
    const size_t height = static_cast<size_t>(size_.height);
    const size_t width = static_cast<size_t>(size_.width);
    const uint64_t requiredPixels = static_cast<uint64_t>(height - 1) * static_cast<uint64_t>(stride) +
        static_cast<uint64_t>(width);
    return requiredPixels <= static_cast<uint64_t>(bufferSize_ / SLR_PIXEL_BYTES);
}

bool SLRMat::GetIndex(int32_t row, int32_t column, size_t &index) const
{
    if (row < 0 || column < 0 || row >= size_.height || column >= size_.width || rowStride_ <= 0) {
        return false;
    }
    const uint64_t index64 = static_cast<uint64_t>(row) * static_cast<uint64_t>(rowStride_) +
        static_cast<uint64_t>(column);
    if (index64 >= static_cast<uint64_t>(bufferSize_ / SLR_PIXEL_BYTES)) {
        return false;
    }
    index = static_cast<size_t>(index64);
    return true;
}

float GetSLRFactor(float x, int a)
{
    if (a <= 0) {
        return 1.0f;
    }
    if (std::fabs(x) < EPSILON) {
        return 1.0f;
    }
    if (x > a || x < -a) {
        return 0.0f;
    }

    x *= PI;
    return a * std::sin(x) * std::sin(x / a) / (x * x);
}

SLRWeightMat SLRProc::GetWeights(float coeff, int n)
{
    CHECK_ERROR_RETURN_RET(std::fabs(coeff) < EPSILON || coeff < .0f || n <= 0, nullptr);
    float tao = 1.0f / coeff;
    int a = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(tao)));
    SLRWeightMat weights = std::make_shared<SLRWeightVec>(n, std::vector<float>(SLR_WEIGHT_SPAN_FACTOR * a, 0));
    float beta = 1.0f;
    if (coeff > 0.8999f && coeff < 1.0f) { // 0.8999f adjust low pass filter
        beta = 1.2f; // 1.2f adjust low pass filter
    } else if (coeff < 0.9f && coeff > 0.8f) { // 0.9f adjust low pass filter
        beta = 1.1f; // 1.1f adjust low pass filter
    }
    float scale = coeff > 1.0f ? 1.0f : coeff;

    for (int i = 0; i < n; i++) {
        float etaf = (i + 0.5) / coeff - 0.5;
        int eta = std::floor(etaf);
        for (int k = eta - a + 1; k < eta + a + 1; k++) {
            float factor = GetSLRFactor(scale / beta * (etaf - k), a);
            (*weights)[i][k - eta + a - 1] = factor;
        }
    }
    std::vector<float> rowSum(n, 0);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < SLR_WEIGHT_SPAN_FACTOR * a; j++) {
            rowSum[i] += (*weights)[i][j];
        }
        if (std::fabs(rowSum[i]) < EPSILON) {
            rowSum[i] = 1.0f; // 1.0f default weight
        }
        for (int j = 0; j < SLR_WEIGHT_SPAN_FACTOR * a; j++) {
            (*weights)[i][j] /= rowSum[i];
        }
    }
    return weights;
}

bool SLRCheck(const SLRMat &src, const SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    CHECK_ERROR_RETURN_RET(x == nullptr || y == nullptr, false);
    CHECK_ERROR_RETURN_RET(!src.IsValid() || !dst.IsValid(), false);
    CHECK_ERROR_RETURN_RET((*x).empty() || (*y).empty(), false);
    CHECK_ERROR_RETURN_RET(static_cast<int>((*x).size()) != dst.size_.width, false);
    CHECK_ERROR_RETURN_RET(static_cast<int>((*y).size()) != dst.size_.height, false);

    float coeffX = static_cast<float>(dst.size_.height) / src.size_.height;
    float coeffY = static_cast<float>(dst.size_.width) / src.size_.width;
    float taoX = 1 / coeffX;
    float taoY = 1 / coeffY;
    int aX = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoX)));
    int aY = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoY)));
    const size_t minXWeightSize = static_cast<size_t>(SLR_WEIGHT_SPAN_FACTOR * aY);
    const size_t minYWeightSize = static_cast<size_t>(SLR_WEIGHT_SPAN_FACTOR * aX);
    CHECK_ERROR_RETURN_RET(std::any_of(x->begin(), x->end(),
        [minXWeightSize](const auto &weights) { return weights.size() < minXWeightSize; }), false);
    CHECK_ERROR_RETURN_RET(std::any_of(y->begin(), y->end(),
        [minYWeightSize](const auto &weights) { return weights.size() < minYWeightSize; }), false);
    return true;
}

inline uint32_t SLRCast(float v)
{
    v = std::clamp(v, 0.0f, 255.0f); // 255.0f rgba max value
    uint32_t uv = static_cast<uint32_t>(v + 0.5f); // 0.5 : round
    return uv;
}

struct SLRSliceKey {
    SLRSliceKey(int v1, int v2) : x(v1), y(v2) {}
    int x;
    int y;
};

bool SLRBoxCheck(const SLRSliceKey &key, const SLRMat &src, const SLRMat &dst, const SLRWeightMat &x,
    const SLRWeightMat &y)
{
    if (key.x < 0 || key.y < 0) {
        IMAGE_LOGE("SLRBoxCheck Key error:%{public}d, %{public}d", key.x, key.y);
        return false;
    }
    uint32_t* srcArr = static_cast<uint32_t*>(src.data_);
    CHECK_ERROR_RETURN_RET_LOG(srcArr == nullptr, false, "SLRBoxCheck srcArr null");
    uint32_t* dstArr = static_cast<uint32_t*>(dst.data_);
    CHECK_ERROR_RETURN_RET_LOG(dstArr == nullptr, false, "SLRBoxCheck dstArr null");

    int srcM = src.size_.height;
    int srcN = src.size_.width;
    int dstM = dst.size_.height;
    int dstN = dst.size_.width;
    float coeffX = static_cast<float>(dstM) / srcM;
    float coeffY = static_cast<float>(dstN) / srcN;
    float taoX = 1 / coeffX;
    float taoY = 1 / coeffY;
    int aX = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoX)));
    int aY = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoY)));
    if (key.y >= static_cast<int>((*x).size()) ||
        static_cast<int>((*x)[key.y].size()) < SLR_WEIGHT_SPAN_FACTOR * aY) {
        IMAGE_LOGE("SLRBoxCheck h_y error:%{public}zu, %{public}d", (*x).size(), aY);
        return false;
    }
    if (key.x >= static_cast<int>((*y).size()) ||
        static_cast<int>((*y)[key.x].size()) < SLR_WEIGHT_SPAN_FACTOR * aX) {
        IMAGE_LOGE("SLRBoxCheck h_x error:%{public}zu, %{public}d", (*y).size(), aX);
        return false;
    }
    size_t dstIndex = 0;
    CHECK_ERROR_RETURN_RET_LOG(!dst.GetIndex(key.x, key.y, dstIndex), false,
        "SLRBoxCheck dst index error:%{public}d, %{public}d", key.x, key.y);
    return true;
}

void SLRBox(const SLRSliceKey &key, const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    CHECK_ERROR_RETURN(!SLRBoxCheck(key, src, dst, x, y));
    uint32_t* srcArr = static_cast<uint32_t*>(src.data_);
    uint32_t* dstArr = static_cast<uint32_t*>(dst.data_);
    int srcM = src.size_.height;
    int srcN = src.size_.width;
    int dstM = dst.size_.height;
    int dstN = dst.size_.width;
    float coeffX = static_cast<float>(dstM) / srcM;
    float coeffY = static_cast<float>(dstN) / srcN;
    float taoX = 1 / coeffX;
    float taoY = 1 / coeffY;
    int aX = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoX)));
    int aY = std::max(SLR_MIN_RADIUS, static_cast<int>(std::floor(taoY)));
    int etaI = static_cast<int>((key.x + 0.5) * taoX - 0.5); // 0.5 middle index
    int etaJ = static_cast<int>((key.y + 0.5) * taoY - 0.5); // 0.5 middle index
    int rStart = etaI - aX + 1;
    int rEnd = etaI + aX;
    int cStart = etaJ - aY + 1;
    int cEnd = etaJ + aY;
    float rgba[4]{ .0f, .0f, .0f, .0f };
    for (int r = rStart; r <= rEnd; ++r) {
        int nR = min(max(0, r), srcM - 1);
        for (int c = cStart; c <= cEnd; ++c) {
            int nC = min(max(0, c), srcN - 1);
            auto w = (*x)[key.y][c - cStart];
            w *= (*y)[key.x][r - rStart];
            size_t srcIndex = 0;
            if (!src.GetIndex(nR, nC, srcIndex)) {
                IMAGE_LOGE("SLRBox src index error:%{public}d, %{public}d", nR, nC);
                return;
            }
            uint32_t color = *(srcArr + srcIndex);
            rgba[0] += ((color >> 24) & 0xFF) * w; // 24 rgba r
            rgba[1] += ((color >> 16) & 0xFF) * w; // 16 rgba g
            rgba[2] += ((color >> 8) & 0xFF) * w;  // 2 8 rgba b
            rgba[3] += (color & 0xFF) * w;         // 3 rgba a
        }
    }
    uint32_t r = SLRCast(rgba[0]);
    uint32_t g = SLRCast(rgba[1]);
    uint32_t b = SLRCast(rgba[2]); // 2 rgba
    uint32_t a = SLRCast(rgba[3]); // 3 rgba
    size_t dstIndex = 0;
    CHECK_ERROR_RETURN(!dst.GetIndex(key.x, key.y, dstIndex));
    dstArr[dstIndex] = (r << 24) | (g << 16) | (b << 8) | a; // 24 16 8 rgba
}

bool SLRProc::Laplacian(const SLRMat &src, SLRMat &dst, float alpha)
{
    IMAGE_LOGD("Laplacian pixelMap SLR:width=%{public}d,height=%{public}d,alpha=%{public}f", src.size_.width,
        src.size_.height, alpha);
    CHECK_ERROR_RETURN_RET_LOG(!src.IsValid() || !dst.IsValid() || src.size_.width != dst.size_.width ||
        src.size_.height != dst.size_.height, false, "SLRProc::Laplacian invalid buffer layout");
    const int m = src.size_.height;
    const int n = src.size_.width;
    uint32_t* srcArr = static_cast<uint32_t*>(src.data_);
    uint32_t* dstArr = static_cast<uint32_t*>(dst.data_);
  
    auto getPixel = [&](int i, int j) -> uint32_t {
        i = std::clamp(i, 0, m - 1);
        j = std::clamp(j, 0, n - 1);
        size_t index = 0;
        if (!src.GetIndex(i, j, index)) {
            return 0;
        }
        return srcArr[index];
    };

    auto extract = [](uint32_t color, int shift) -> uint32_t { return (color >> shift) & 0xFF; };
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            const uint32_t pixels[5] = {
                getPixel(i, j),       // center
                getPixel(i, j - 1),     // left
                getPixel(i, j + 1),     // right
                getPixel(i - 1, j),     // up
                getPixel(i + 1, j)      // down
            };
            const uint32_t cr = extract(pixels[0], 24); // 24 r
            const uint32_t cg = extract(pixels[0], 16); // 16 g
            const uint32_t cb = extract(pixels[0], 8); // 8 b
            const uint32_t ca = pixels[0] & 0xFF;

            auto delta = [&](uint32_t c, int shift) -> int {
                return 4 * c
                    - extract(pixels[1], shift) // l left
                    - extract(pixels[2], shift) // 2 right
                    - extract(pixels[3], shift) // 3 up
                    - extract(pixels[4], shift); // 4 down
            };
            size_t dstIndex = 0;
            CHECK_ERROR_RETURN_RET(!dst.GetIndex(i, j, dstIndex), false);
            dstArr[dstIndex] =
                (SLRCast(cr + alpha * delta(cr, 24)) << 24) | // 24 r
                (SLRCast(cg + alpha * delta(cg, 16)) << 16) | // 16 g
                (SLRCast(cb + alpha * delta(cb, 8))  << 8)  | // 8 b
                ca;
        }
    }
    return true;
}
 
bool SLRProc::Serial(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    CHECK_ERROR_RETURN_RET_LOG(!SLRCheck(src, dst, x, y), false, "SLRProc::Serial param error");

    int m = dst.size_.height;
    int n = dst.size_.width;
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            SLRSliceKey key(i, j);
            SLRBox(key, src, dst, x, y);
        }
    }
    return true;
}

inline void SLRSubtask(const SLRSliceKey &key, const SLRMat &src, SLRMat &dst,
    const SLRWeightMat &x, const SLRWeightMat &y)
{
    int start = key.x;
    int end = key.y;
    int n = dst.size_.width;
    for (int i = start; i < end; i++) {
        for (int j = 0; j < n; j++) {
            SLRSliceKey boxKey(i, j);
            SLRBox(boxKey, src, dst, x, y);
        }
    }
}

bool SLRProc::Parallel(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    CHECK_ERROR_RETURN_RET_LOG(!SLRCheck(src, dst, x, y), false, "SLRProc::Parallel param error");
    const int maxThread = 16; // 16 max thread size
    int m = dst.size_.height;
    int n = dst.size_.width;
    int step = m / maxThread;
    int stepMod = (m % maxThread == 0) ? 1 : 0;
    std::vector<ffrt::dependence> ffrtHandles;
    std::vector<ffrt::dependence> ffrtHandles1;
    for (int k = 0; k < maxThread - stepMod; k++) {
        int start = k * step;
        int end = (k + 1) * step;
        auto func = [&src, &dst, &x, &y, start, end, n] {
            SLRSliceKey key(start, end);
            SLRSubtask(key, src, dst, x, y);
        };
        auto handler = ffrt::submit_h(func, {}, {}, ffrt::task_attr().qos(5)); // 5 max ffrt qos value
        if (ffrtHandles.size() < FFRT_THREAD_LIMIT) {
            ffrtHandles.emplace_back(handler);
        } else {
            ffrtHandles1.emplace_back(handler);
        }
    }

    for (int i = (maxThread - stepMod) * step; i < m; i++) {
        for (int j = 0; j < n; j++) {
            SLRSliceKey key(i, j);
            SLRBox(key, src, dst, x, y);
        }
    }

    ffrt::wait(ffrtHandles);
    ffrt::wait(ffrtHandles1);
    return true;
#else
    return SLRProc::Serial(src, dst, x, y);
#endif
}
} // namespace Media
} // namespace OHOS
