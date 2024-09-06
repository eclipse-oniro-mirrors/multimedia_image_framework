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

namespace OHOS {
namespace Media {
using namespace std;

constexpr float PI = 3.14159265;
constexpr float EPSILON = 1e-6;

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
    if (std::fabs(coeff) < EPSILON || coeff < .0f || n <= 0) {
        return nullptr;
    }
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
        int etaf = (i + 0.5) / coeff - 0.5;
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
    if (x == nullptr || y == nullptr) {
        return false;
    }
    if (src.size_.width == 0 || src.size_.height == 0) {
        return false;
    }
    if (dst.size_.width == 0 || dst.size_.height == 0) {
        return false;
    }
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

void SLRBox(const SLRSliceKey &key, const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    if (key.x < 0 || key.y < 0) {
        return;
    }

    uint32_t* srcArr = static_cast<uint32_t*>(src.data_);
    uint32_t* dstArr = static_cast<uint32_t*>(dst.data_);
    if (srcArr == nullptr || dstArr == nullptr) {
        return;
    }
    int srcM = src.size_.height, srcN = src.size_.width, dstM = dst.size_.height, dstN = dst.size_.width;
    float coeffX = static_cast<float>(dstM) / srcM, coeffY = static_cast<float>(dstN) / srcN;
    float taoX = 1 / coeffX, taoY = 1 / coeffY;
    int aX = std::max(2, static_cast<int>(std::floor(taoX)));
    int aY = std::max(2, static_cast<int>(std::floor(taoY))); // 2 default size

    int etaI = static_cast<int>((key.x + 0.5) * taoX - 0.5); // 0.5 middle index
    int etaJ = static_cast<int>((key.y + 0.5) * taoY - 0.5); // 0.5 middle index
    int rStart = etaI - aX + 1, rEnd = etaI + aX;
    int cStart = etaJ - aY + 1, cEnd = etaJ + aY;
    if (static_cast<int>((*x).size()) < key.y || static_cast<int>((*x)[0].size()) < 2 * aY) { // 2 max slr box size
        IMAGE_LOGE("SLRBox h_y Error:%{public}zu, %{public}d", (*x).size(), aY);
        return;
    }
    if (static_cast<int>((*y).size()) < key.x || static_cast<int>((*y)[0].size()) < 2 * aX) { // 2 max slr box size
        IMAGE_LOGE("SLRBox h_x Error:%{public}zu, %{public}d", (*y).size(), aX);
        return;
    }

    float rgba[4]{ .0f, .0f, .0f, .0f };
    for (int r = rStart; r <= rEnd; ++r) {
        int nR = min(max(0, r), srcM - 1);
        for (int c = cStart; c <= cEnd; ++c) {
            int nC = min(max(0, c), srcN - 1);
            auto w = (*x)[key.y][c - cStart];
            w *= (*y)[key.x][r - rStart];
            uint32_t color = *(srcArr + (nR *  src.rowStride_ + nC));
            rgba[0] += ((color >> 24) & 0xFF) * w; // 24 rgba r
            rgba[1] += ((color >> 16) & 0xFF) * w; // 16 rgba g
            rgba[2] += ((color >> 8) & 0xFF) * w;  // 2 8 rgba b
            rgba[3] += (color & 0xFF) * w;         // 3 rgba a
        }
    }
    uint32_t r = SLRCast(rgba[0]), g = SLRCast(rgba[1]), b = SLRCast(rgba[2]), a = SLRCast(rgba[3]); // 2 3 rgba
    dstArr[key.x * dst.rowStride_ + key.y] = (r << 24) | (g << 16) | (b << 8) | a; // 24 16 8 rgba
}

void SLRProc::Serial(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y)
{
    if (!SLRCheck(src, dst, x, y)) {
        IMAGE_LOGE("SLRProc::Serial param error");
        return;
    }

    int m = dst.size_.height, n = dst.size_.width;
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
    if (!SLRCheck(src, dst, x, y)) {
        IMAGE_LOGE("SLRProc::Parallel param error");
        return;
    }
    const int maxThread = 16; // 16 max thread size
    int m = dst.size_.height, n = dst.size_.width;
    int step = m / maxThread;
    int stepMod = (m % maxThread == 0) ? 1 : 0;
    std::vector<ffrt::dependence> ffrtHandles;
    for (int k = 0; k < maxThread - stepMod; k++) {
        int start = k * step;
        int end = (k + 1) * step;
        auto func = [&src, &dst, &x, &y, start, end, n] {
            SLRSliceKey key(start, end);
            SLRSubtask(key, src, dst, x, y);
        };
        auto handler = ffrt::submit_h(func, {}, {}, ffrt::task_attr().qos(5)); // 5 max ffrt qos value
        ffrtHandles.emplace_back(handler);
    }

    for (int i = (maxThread - stepMod) * step; i < m; i++) {
        for (int j = 0; j < n; j++) {
            SLRSliceKey key(i, j);
            SLRBox(key, src, dst, x, y);
        }
    }

    ffrt::wait(ffrtHandles);
#else
    SLRProc::Serial(src, dst, x, y);
#endif
}
} // namespace Media
} // namespace OHOS