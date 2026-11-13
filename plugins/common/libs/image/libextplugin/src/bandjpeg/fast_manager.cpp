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

#include "bandjpeg/fast_manager.h"
#include "image_log.h"
#include <sys/stat.h>
#include <iostream>

namespace OHOS {
namespace ImagePlugin {
constexpr const char* FAST_LIB = "libfast_image.so";
FASTManager& FASTManager::GetInstance()
{
    static FASTManager instance;
    return instance;
}

bool FASTManager::ResolveDecodeEntries()
{
    // DecodeImage/DecodeImageYUV now live in fast::image::bandjpeg and return
    // IMAGE_ErrorCode; the legacy FastErrCode exports are no longer provided.
    // Resolve the current ABI first, then fall back to legacy so an older
    // libfast_image.so keeps working.
    DecodeImage = reinterpret_cast<fast::image::IMAGE_ErrorCode (*)(const uint8_t*, size_t, uint8_t*,
        uint32_t, uint32_t, size_t, fast::image::RGBFormat)>(dlsym(FASTHandle_,
        "_ZN4fast5image8bandjpeg11DecodeImageEPKhmPhjjmNS0_9RGBFormatE"));
    DecodeImageYUV = reinterpret_cast<fast::image::IMAGE_ErrorCode (*)(const uint8_t*, size_t, uint8_t*,
        uint8_t*, uint32_t, uint32_t, size_t, size_t, fast::image::YUVFormat)>(dlsym(FASTHandle_,
        "_ZN4fast5image8bandjpeg14DecodeImageYUVEPKhmPhS4_jjmmNS0_9YUVFormatE"));
    if (DecodeImage == nullptr) {
        DecodeImageLegacy = reinterpret_cast<fast::image::FastErrCode (*)(const uint8_t*, size_t, uint8_t*,
            uint32_t, uint32_t, size_t, fast::image::RGBFormat)>(dlsym(FASTHandle_,
            "_ZN4fast5image11DecodeImageEPKhmPhjjmNS0_9RGBFormatE"));
    }
    if (DecodeImageYUV == nullptr) {
        DecodeImageYUVLegacy = reinterpret_cast<fast::image::FastErrCode (*)(const uint8_t*, size_t, uint8_t*,
            uint8_t*, uint32_t, uint32_t, size_t, size_t, fast::image::YUVFormat)>(dlsym(FASTHandle_,
            "_ZN4fast5image14DecodeImageYUVEPKhmPhS3_jjmmNS0_9YUVFormatE"));
    }
    // Only a missing RGB entry point is fatal; YUV/color-space/region entries
    // degrade individually instead of taking the whole singleton down.
    if (DecodeImage == nullptr && DecodeImageLegacy == nullptr) {
        IMAGE_LOGE("FAST DecodeImage not found: %{public}s", dlerror());
        return false;
    }
    if (DecodeImageYUV == nullptr && DecodeImageYUVLegacy == nullptr) {
        IMAGE_LOGW("FAST DecodeImageYUV not found: %{public}s", dlerror());
    }
    return true;
}

void FASTManager::ResolveOptionalEntries()
{
    ColorSpaceConvert = reinterpret_cast<fast::image::IMAGE_ErrorCode (*)(uint8_t*, uint32_t,
        fast::image::ColorInfo, uint8_t*, uint32_t, fast::image::ColorInfo, uint32_t, uint32_t)>(
        dlsym(FASTHandle_, "_ZN4fast5image17ColorSpaceConvertEPhjNS0_9ColorInfoES1_jS2_jj"));
    if (ColorSpaceConvert == nullptr) {
        IMAGE_LOGW("FAST ColorSpaceConvert not found: %{public}s", dlerror());
    }
    DecodeImageRegion = reinterpret_cast<fast::image::IMAGE_ErrorCode (*)(
        const fast::image::bandjpeg::RegionDecodeParams&)>(
        dlsym(FASTHandle_, "_ZN4fast5image8bandjpeg17DecodeImageRegionERKNS1_18RegionDecodeParamsE"));
    if (DecodeImageRegion == nullptr) {
        IMAGE_LOGW("FAST DecodeImageRegion not found: %{public}s", dlerror());
    }
}

FASTManager::FASTManager()
{
    FASTHandle_ = dlopen(FAST_LIB, RTLD_NOW | RTLD_NODELETE);
    CHECK_ERROR_RETURN_LOG(FASTHandle_ == nullptr, "FASTManager dlopen FAST_LIB is failed: %{public}s", dlerror());

    if (!ResolveDecodeEntries()) {
        dlclose(FASTHandle_);
        FASTHandle_ = nullptr;
        DecodeImageYUV = nullptr;
        DecodeImageYUVLegacy = nullptr;
        isInitialized_ = false;
        return;
    }
    ResolveOptionalEntries();

    isInitialized_ = true;
    IMAGE_LOGI("FASTManager initialized successfully");
}

FASTManager::~FASTManager()
{
    if (FASTHandle_) {
        dlclose(FASTHandle_);
        FASTHandle_ = nullptr;
        DecodeImage = nullptr;
        DecodeImageYUV = nullptr;
        DecodeImageLegacy = nullptr;
        DecodeImageYUVLegacy = nullptr;
        ColorSpaceConvert = nullptr;
        DecodeImageRegion = nullptr;
        isInitialized_ = false;
    }
}

} // namespace ImagePlugin
} // namespace OHOS
