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
FASTManager& FASTManager::GetInstance()
{
    static FASTManager instance;
    return instance;
}

FASTManager::FASTManager()
{
    FASTHandle_ = dlopen(FASTLib_, RTLD_NOW);
    CHECK_ERROR_RETURN_LOG(FASTHandle_ == nullptr, "FASTManager dlopen FASTlib is failed: %{public}s", dlerror());

    DecodeImage = reinterpret_cast<fast::image::FastErrCode (*)(const uint8_t*, size_t, uint8_t*, uint32_t, uint32_t,
        size_t, fast::image::RGBFormat)>(dlsym(FASTHandle_, "_ZN4fast5image11DecodeImageEPKhmPhjjmNS0_9RGBFormatE"));
    if (DecodeImage == nullptr) {
        IMAGE_LOGE("FAST DecodeImage not found: %{public}s", dlerror());
        dlclose(FASTHandle_);
        FASTHandle_ = nullptr;
        DecodeImageYUV = nullptr;
        isInitialized_ = false;
        return;
    }
    DecodeImageYUV = reinterpret_cast<fast::image::FastErrCode (*)(const uint8_t*, size_t, uint8_t*, uint8_t*,
        uint32_t, uint32_t, size_t, size_t, fast::image::YUVFormat)>
        (dlsym(FASTHandle_, "_ZN4fast5image14DecodeImageYUVEPKhmPhS3_jjmmNS0_9YUVFormatE"));
    if (DecodeImageYUV == nullptr) {
        IMAGE_LOGE("FAST DecodeImageYUV not found: %{public}s", dlerror());
        dlclose(FASTHandle_);
        FASTHandle_ = nullptr;
        DecodeImage = nullptr;
        isInitialized_ = false;
        return;
    }
    
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
        isInitialized_ = false;
    }
}

} // namespace ImagePlugin
} // namespace OHOS
