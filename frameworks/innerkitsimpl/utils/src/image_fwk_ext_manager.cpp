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

#include "image_fwk_ext_manager.h"

#include <dlfcn.h>
#include <string>
#include "image_log.h"
#include "image_func_timer.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageFwkExtManager"

static const std::string IMAGE_FWK_EXT_NATIVE_SO = "libimage_codec_ext_native.so";

namespace OHOS {
namespace Media {
ImageFwkExtManager::ImageFwkExtManager()
{
#if !defined(_WIN32) && !defined(_APPLE)
    doHardWareEncodeFunc_ = nullptr;
    hevcSoftwareDecodeFunc_ = nullptr;
    isImageFwkExtNativeSoOpened_ = false;
    extNativeSoHandle_ = nullptr;
#endif
}

ImageFwkExtManager::~ImageFwkExtManager()
{
#if !defined(_WIN32) && !defined(_APPLE)
    if (!isImageFwkExtNativeSoOpened_ || extNativeSoHandle_ == nullptr) {
        IMAGE_LOGD("image fwk ext native so is not open when dlclose");
        return;
    }
    if (dlclose(extNativeSoHandle_)) {
        IMAGE_LOGD("extNativeSoHandle dlclose failed: %{public}s", IMAGE_FWK_EXT_NATIVE_SO.c_str());
    } else {
        IMAGE_LOGD("extNativeSoHandle dlclose success: %{public}s", IMAGE_FWK_EXT_NATIVE_SO.c_str());
    }
#endif
}

bool ImageFwkExtManager::LoadImageFwkExtNativeSo()
{
#if !defined(_WIN32) && !defined(_APPLE)
    ImageFuncTimer imageFuncTimer(__func__);
    if (!isImageFwkExtNativeSoOpened_) {
        extNativeSoHandle_ = dlopen(IMAGE_FWK_EXT_NATIVE_SO.c_str(), RTLD_LAZY);
        if (extNativeSoHandle_ == nullptr) {
            IMAGE_LOGE("%{public}s dlopen falied", IMAGE_FWK_EXT_NATIVE_SO.c_str());
            return false;
        }
        doHardWareEncodeFunc_ = reinterpret_cast<DoHardWareEncodeFunc>(dlsym(extNativeSoHandle_, "DoHardwareEncode"));
        hevcSoftwareDecodeFunc_ =
            reinterpret_cast<HevcSoftwareDecodeFunc>(dlsym(extNativeSoHandle_, "HevcSoftwareDecode"));
        if (doHardWareEncodeFunc_ == nullptr || hevcSoftwareDecodeFunc_ == nullptr) {
            IMAGE_LOGE("DoHardwareEncode dlsym falied");
            dlclose(extNativeSoHandle_);
            extNativeSoHandle_ = nullptr;
            return false;
        }
        doHardwareEncodePictureFunc_ = reinterpret_cast<DoHardwareEncodePictureFunc>(dlsym(extNativeSoHandle_,
            "DoHardwareEncodePicture"));
        if (doHardwareEncodePictureFunc_ == nullptr) {
            IMAGE_LOGE("DoHardwareEncodePicture dlsym falied");
            dlclose(extNativeSoHandle_);
            extNativeSoHandle_ = nullptr;
            return false;
        }
        isImageFwkExtNativeSoOpened_ = true;
    }
    return true;
#else
    return false;
#endif
}
} // namespace Media
} // namespace OHOS