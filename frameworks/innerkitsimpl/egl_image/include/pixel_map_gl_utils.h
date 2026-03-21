/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_UTILS_H

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "image_type.h"

namespace OHOS {
namespace Media {
namespace PixelMapGlUtils {
constexpr int MAX_SLR_WIN_SIZE = 12;
constexpr float PI = 3.1415926f;
constexpr int32_t MAX_CONTEXT_EXPIRED_TIME_SEC = 120;
constexpr int32_t MIN_CONTEXT_EXPIRED_TIME_SEC = 10;

struct DmaTransferMode {
    AllocatorType outputAllocType = AllocatorType::HEAP_ALLOC;
    bool isSourceDma = false;
    bool isTargetDma = false;
    bool isDma = false;
};

inline bool IsInt32MulOverflow(int32_t lhs, int32_t rhs)
{
    if (lhs <= 0 || rhs <= 0) {
        return true;
    }
    return lhs > std::numeric_limits<int32_t>::max() / rhs;
}

inline bool IsRectInBounds(const Rect &rect, int32_t width, int32_t height)
{
    if (width <= 0 || height <= 0 || rect.left < 0 || rect.top < 0 || rect.width <= 0 || rect.height <= 0) {
        return false;
    }
    if (rect.left >= width || rect.top >= height) {
        return false;
    }
    return rect.width <= width - rect.left && rect.height <= height - rect.top;
}

inline bool ComputeRowBytes(int32_t width, int32_t pixelBytes, size_t &rowBytes)
{
    if (width <= 0 || pixelBytes <= 0) {
        return false;
    }
    if (IsInt32MulOverflow(width, pixelBytes)) {
        return false;
    }
    rowBytes = static_cast<size_t>(width) * static_cast<size_t>(pixelBytes);
    return true;
}

inline bool ComputePackedBufferSize(const Size &size, int32_t pixelBytes, size_t &contiguousSize)
{
    if (size.width <= 0 || size.height <= 0) {
        return false;
    }
    size_t rowBytes = 0;
    if (!ComputeRowBytes(size.width, pixelBytes, rowBytes)) {
        return false;
    }
    if (IsInt32MulOverflow(static_cast<int32_t>(rowBytes), size.height)) {
        return false;
    }
    contiguousSize = rowBytes * static_cast<size_t>(size.height);
    return true;
}

inline bool ValidateImageLayout(const Size &size, int32_t stride, int32_t pixelBytes,
    size_t &rowBytes, size_t &contiguousSize)
{
    if (!ComputePackedBufferSize(size, pixelBytes, contiguousSize) ||
        !ComputeRowBytes(size.width, pixelBytes, rowBytes)) {
        return false;
    }
    if (stride <= 0 || static_cast<size_t>(stride) < rowBytes) {
        return false;
    }
    return true;
}

inline float GeSLRFactor(float x, int a)
{
    if (x >= a || x < -a) {
        return 0.0f;
    }
    if (std::abs(x) < 1e-16f) {
        return 0.0f;
    }
    x *= PI;
    if (std::abs(x * x) < 1e-6f || x * x == 0.0f || std::abs(static_cast<float>(a)) < 1e-6f || a == 0) {
        return 0.0f;
    }
    return a * std::sin(x) * std::sin(x / a) / (x * x);
}

inline std::vector<float> BuildSlrWeights(float coeff, int count)
{
    if (count <= 0) {
        return {};
    }
    if (IsInt32MulOverflow(count, MAX_SLR_WIN_SIZE)) {
        return {};
    }
    if (!std::isfinite(coeff) || std::abs(coeff) < 1e-6f) {
        coeff = 1.0f;
    }

    const float tao = 1.0f / coeff;
    const int a = std::max(2, static_cast<int>(std::floor(tao)));
    const int width = std::min(2 * a, MAX_SLR_WIN_SIZE);
    std::vector<float> weights(static_cast<size_t>(count) * MAX_SLR_WIN_SIZE, 0.0f);
    for (int i = 0; i < count; ++i) {
        const float eta = (i + 0.5f) / coeff - 0.5f;
        const int etaInt = static_cast<int>(std::floor(eta));
        const int start = etaInt - a + 1;
        float sum = 0.0f;
        for (int j = 0; j < width; ++j) {
            const float factor = GeSLRFactor(coeff * (eta - (start + j)), a);
            weights[static_cast<size_t>(i) * MAX_SLR_WIN_SIZE + j] = factor;
            sum += factor;
        }
        if (std::abs(sum) < 1e-6f) {
            weights[static_cast<size_t>(i) * MAX_SLR_WIN_SIZE] = 1.0f;
            continue;
        }
        for (int j = 0; j < width; ++j) {
            weights[static_cast<size_t>(i) * MAX_SLR_WIN_SIZE + j] /= sum;
        }
    }
    return weights;
}

inline int32_t GetContextExpireDelaySec(int32_t instanceCount, int32_t maxInstanceCount)
{
    if (instanceCount <= 1) {
        return MAX_CONTEXT_EXPIRED_TIME_SEC;
    }
    return MIN_CONTEXT_EXPIRED_TIME_SEC * std::max(1, maxInstanceCount + 1 - instanceCount);
}

inline DmaTransferMode ResolveDmaTransferMode(AllocatorType sourceAllocType, uint64_t noPaddingUsage)
{
    DmaTransferMode mode;
    mode.isSourceDma = sourceAllocType == AllocatorType::DMA_ALLOC;
    const bool disableDmaWriteBack = mode.isSourceDma && noPaddingUsage != 0;
    mode.outputAllocType = disableDmaWriteBack ? AllocatorType::HEAP_ALLOC : sourceAllocType;
    mode.isTargetDma = mode.outputAllocType == AllocatorType::DMA_ALLOC;
    mode.isDma = mode.isSourceDma || mode.isTargetDma;
    return mode;
}

inline float ComputeLapSharpenAlpha(float scaleCoeff)
{
    if (scaleCoeff > 0.8f) {
        return 0.0f;
    }
    if (scaleCoeff > 0.6f) {
        return 0.06f;
    }
    if (scaleCoeff > 0.5f) {
        return 0.1f;
    }
    return 0.15f;
}
} // namespace PixelMapGlUtils
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_UTILS_H
