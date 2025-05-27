/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "image_common.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "picture_taihe.h"
#include "pixel_map_taihe.h"
#include "media_errors.h"
#include "message_parcel.h"

using namespace ANI::Image;

namespace ANI::Image {

PictureImpl::PictureImpl() : nativePicture_(nullptr), isRelease(false) {}

PictureImpl::PictureImpl(std::shared_ptr<OHOS::Media::Picture> picture)
{
    nativePicture_ = picture;
}

PictureImpl::~PictureImpl()
{
    Release();
}

int64_t PictureImpl::GetImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

std::shared_ptr<OHOS::Media::Picture> PictureImpl::GetNativePtr()
{
    return nativePicture_;
}

PixelMap PictureImpl::GetMainPixelmap()
{
    if (nativePicture_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Native picture is nullptr!");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    auto pixelmap = nativePicture_->GetMainPixel();
    if (pixelmap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Get main pixelmap failed, pixelmap is nullptr!");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    return PixelMapImpl::CreatePixelMap(pixelmap);
}

void PictureImpl::Marshalling(uintptr_t sequence)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ani_env *env = ::taihe::get_env();
    if (env == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Ani unwarp messageParcel failed.");
        return;
    }
    ani_object sequenceObj = reinterpret_cast<ani_object>(sequence);
    ani_long nativePtr;
    if (ANI_OK != env->Object_GetFieldByName_Long(sequenceObj, "nativePtr", &nativePtr)) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Marshalling picture unwrap failed.");
        return;
    }
    OHOS::MessageParcel* messageParcel = reinterpret_cast<OHOS::MessageParcel*>(nativePtr);
    if (messageParcel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Marshalling picture to parcel failed.");
        return;
    }
    bool st = nativePicture_->Marshalling(*messageParcel);
    if (!st) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Marshalling picture to parcel failed.");
    }
#endif
}

void PictureImpl::Release()
{
    if (!isRelease) {
        if (nativePicture_ != nullptr) {
            nativePicture_ = nullptr;
        }
        isRelease = true;
    }
}

Picture CreatePictureByPixelMap(weak::PixelMap mainPixelmap)
{
    IMAGE_LOGI("CreatePicture IN");
    PixelMapImpl* pixelMapImpl = reinterpret_cast<PixelMapImpl*>(mainPixelmap->GetImplPtr());
    if (pixelMapImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Pixelmap instance is nullptr!");
        return make_holder<PictureImpl, Picture>();
    }
    auto nativePixelMap = pixelMapImpl->GetNativePtr();
    if (nativePixelMap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get native pixelmap failed!");
        return make_holder<PictureImpl, Picture>();
    }
    auto picture = OHOS::Media::Picture::Create(nativePixelMap);
    if (picture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Create picture failed!");
        return make_holder<PictureImpl, Picture>();
    }
    IMAGE_LOGI("CreatePicture OUT");
    return make_holder<PictureImpl, Picture>(std::move(picture));
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreatePictureByPixelMap(CreatePictureByPixelMap);