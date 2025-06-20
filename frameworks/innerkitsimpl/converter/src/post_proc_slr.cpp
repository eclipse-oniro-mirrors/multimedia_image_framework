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
    int a = std::max(2, static_cast<int>(std::floor(tao))); // 2 max SLR box size
    SLRWeightMat weights = std::make_shared<SLRWeightVec>(n, std::vector<float>(2 * a, 0));
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
        for (int j = 0; j < 2 * a; j++) { // 2 max SLR box size
            rowSum[i] += (*weights)[i][j];
        }
        if (std::fabs(rowSum[i]) < EPSILON) {
            rowSum[i] = 1.0f; // 1.0f default weight
        }
        for (int j = 0; j < 2 * a; j++) { // 2 max SLR box size
            (*weights)[i][j] /= rowSum[i];
        }
    }
    return weights;
}

bool SLRCheck(const SLRMat &src, const SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    CHECK_ERROR_RETURN_RET(x == nullptr || y == nullptr, false);
    CHECK_ERROR_RETURN_RET(src.size_.width == 0 || src.size_.height == 0, false);
    CHECK_ERROR_RETURN_RET(dst.size_.width == 0 || dst.size_.height == 0, false);
    return true;
}

inline uint32_t SLRCast(float v)
{
    v = std::clamp(v, 0.0f, 255.0f); // 255.0f rgba max value
    uint32_t uv = static_cast<uint32_t>(v);
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
    int aX = std::max(2, static_cast<int>(std::floor(taoX)));
    int aY = std::max(2, static_cast<int>(std::floor(taoY))); // 2 default size
    if (static_cast<int>((*x).size()) < key.y || static_cast<int>((*x)[0].size()) < 2 * aY) { // 2 max slr box size
        IMAGE_LOGE("SLRBoxCheck h_y error:%{public}zu, %{public}d", (*x).size(), aY);
        return false;
    }
    if (static_cast<int>((*y).size()) < key.x || static_cast<int>((*y)[0].size()) < 2 * aX) { // 2 max slr box size
        IMAGE_LOGE("SLRBoxCheck h_x error:%{public}zu, %{public}d", (*y).size(), aX);
        return false;
    }
    int dstIndex = key.x * dst.rowStride_ + key.y;
    int maxDstSize = dstM * dst.rowStride_; // the rowStride_ here represents pixel
    CHECK_ERROR_RETURN_RET_LOG(dstIndex >= maxDstSize, false,
        "SLRBoxCheck dst index error:%{public}d, %{public}d", dstIndex, maxDstSize);
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
    int aX = std::max(2, static_cast<int>(std::floor(taoX)));
    int aY = std::max(2, static_cast<int>(std::floor(taoY))); // 2 default size
    int etaI = static_cast<int>((key.x + 0.5) * taoX - 0.5); // 0.5 middle index
    int etaJ = static_cast<int>((key.y + 0.5) * taoY - 0.5); // 0.5 middle index
    int rStart = etaI - aX + 1;
    int rEnd = etaI + aX;
    int cStart = etaJ - aY + 1;
    int cEnd = etaJ + aY;
    float rgba[4]{ .0f, .0f, .0f, .0f };
    int maxSrcSize = srcM * src.rowStride_; // the rowStride_ here represents pixel
    for (int r = rStart; r <= rEnd; ++r) {
        int nR = min(max(0, r), srcM - 1);
        for (int c = cStart; c <= cEnd; ++c) {
            int nC = min(max(0, c), srcN - 1);
            auto w = (*x)[key.y][c - cStart];
            w *= (*y)[key.x][r - rStart];
            int srcIndex = nR *  src.rowStride_ + nC;
            if (srcIndex < 0 || srcIndex >= maxSrcSize) {
                IMAGE_LOGE("SLRBox src index error:%{public}d, %{public}d", srcIndex, maxSrcSize);
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
    dstArr[key.x * dst.rowStride_ + key.y] = (r << 24) | (g << 16) | (b << 8) | a; // 24 16 8 rgba
}

void SLRProc::Laplacian(SLRMat &srcMat, void* data, float alpha)
{
    IMAGE_LOGD("Laplacian pixelMap SLR:width=%{public}d,height=%{public}d,alpha=%{public}f", srcMat.size_.width,
        srcMat.size_.height, alpha);
    CHECK_ERROR_RETURN_LOG(data == nullptr, "SLRProc::Laplacian create memory failed");
    const int m = srcMat.size_.height;
    const int n = srcMat.size_.width;
    const int stride = srcMat.rowStride_;
    uint32_t* srcArr = static_cast<uint32_t*>(srcMat.data_);
    uint32_t* dstArr = static_cast<uint32_t*>(data);
  
    auto getPixel = [&](int i, int j) ->uint32_t {
        i = std::clamp(i, 0, m - 1);
        j = std::clamp(j, 0, n - 1);
        return *(srcArr + i * stride + j);
    };

    auto extract = [](uint32_t color, int shift) -> uint32_t {
        return (color >> shift) & 0xFF;
    };
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
            dstArr[i * stride + j] =
                (SLRCast(cr + alpha * delta(cr, 24)) << 24) | // 24 r
                (SLRCast(cg + alpha * delta(cg, 16)) << 16) | // 16 g
                (SLRCast(cb + alpha * delta(cb, 8))  << 8)  | // 8 b
                ca;
        }
    }
}
 
void SLRProc::Serial(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    CHECK_ERROR_RETURN_LOG(!SLRCheck(src, dst, x, y), "SLRProc::Serial param error");

    int m = dst.size_.height;
    int n = dst.size_.width;
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            SLRSliceKey key(i, j);
            SLRBox(key, src, dst, x, y);
        }
    }
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

void SLRProc::Parallel(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    CHECK_ERROR_RETURN_LOG(!SLRCheck(src, dst, x, y), "SLRProc::Parallel param error");
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
#else
    SLRProc::Serial(src, dst, x, y);
#endif
}
} // namespace Media
} // namespace OHOS
