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
#ifndef FAST_MANAGER_TEST_H
#define FAST_MANAGER_TEST_H

#include <dlfcn.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace fast::image {
enum class FastErrCode {
    OK,
    INVALID_PTR,
    ILLEGAL_INPUT,
    DECODE_ERROR,
    OOM,
};

enum class IMAGE_ErrorCode {
    SUCCESS,
    SUCCESS_PARTIAL,
    ILLEGAL_INPUT,
    INVALID_PTR,
    UNSUPPORTED,
};

enum class YUVFormat {
    NV12,
    NV21,
};

enum class RGBFormat {
    RGB888,
    RGBA8888,
    BGRA8888,
    RGB565,
};

enum class AlphaType {
    UNKNOWN,
    OPAQUE,
    PREMUL,
    UNPREMUL,
};

struct TransferFunction {
    float g;
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
};

struct Matrix3x3 {
    float vals[3][3];
};

struct ColorSpace {
    TransferFunction fTransferFn;
    Matrix3x3 fToXYZD50;
};

struct ColorInfo {
    ColorSpace colorSpace;
    RGBFormat formatType;
    AlphaType fAlphaType = AlphaType::UNKNOWN;
};
}

namespace OHOS {
namespace ImagePlugin {

class FASTManager {
public:
    static FASTManager& GetInstance();

    bool IsInitialized() const { return isInitialized_; }

    bool IsGamutAvailable() const { return isInitialized_ && ColorSpaceConvert != nullptr; }

    fast::image::FastErrCode (*DecodeImage)(const uint8_t*, size_t, uint8_t*, uint32_t,
        uint32_t, size_t, fast::image::RGBFormat) = nullptr;
    fast::image::FastErrCode (*DecodeImageYUV)(const uint8_t*, size_t, uint8_t*, uint8_t*, uint32_t,
        uint32_t, size_t, size_t, fast::image::YUVFormat) = nullptr;
    fast::image::IMAGE_ErrorCode (*ColorSpaceConvert)(uint8_t*, uint32_t, fast::image::ColorInfo,
        uint8_t*, uint32_t, fast::image::ColorInfo, uint32_t, uint32_t) = nullptr;

private:
    FASTManager();
    ~FASTManager();
    FASTManager(const FASTManager&) = delete;
    FASTManager(const FASTManager&&) = delete;
    FASTManager& operator=(const FASTManager&) = delete;
    FASTManager& operator=(const FASTManager&&) = delete;

    void* FASTHandle_ = nullptr;
    bool isInitialized_ = false; // initialization flag
};
}
}
#endif
