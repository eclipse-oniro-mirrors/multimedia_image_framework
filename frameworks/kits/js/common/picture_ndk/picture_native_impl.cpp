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
#include "picture_native_impl.h"
#include "picture.h"

#ifdef __cplusplus
extern "C" {
#endif

OH_PictureNative::OH_PictureNative(std::shared_ptr<OHOS::Media::Picture> picture)
{
    picture_ = picture;
}

OH_PictureNative::OH_PictureNative(std::shared_ptr<OHOS::Media::PixelMap> pixelmap)
{
    if (pixelmap == nullptr) {
        picture_ = nullptr;
        return;
    }
    auto pictureTmp = OHOS::Media::Picture::Create(pixelmap);
    picture_ = std::move(pictureTmp);
}

std::shared_ptr<OHOS::Media::Picture> OH_PictureNative::GetInnerPicture()
{
    return picture_;
}

OH_PictureNative::~OH_PictureNative() {}

OH_AuxiliaryPictureNative::OH_AuxiliaryPictureNative(std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxiliaryPicture)
{
    auxiliaryPicture_ = auxiliaryPicture;
}

OH_AuxiliaryPictureNative::OH_AuxiliaryPictureNative(std::shared_ptr<OHOS::Media::PixelMap> &content,
    OHOS::Media::AuxiliaryPictureType type, OHOS::Media::Size size)
{
    auto auxiliaryPictureTmp = OHOS::Media::AuxiliaryPicture::Create(content, type, size);
    auxiliaryPicture_ = std::move(auxiliaryPictureTmp);
}

std::shared_ptr<OHOS::Media::AuxiliaryPicture> OH_AuxiliaryPictureNative::GetInnerAuxiliaryPicture()
{
    return auxiliaryPicture_;
}

OH_AuxiliaryPictureNative::~OH_AuxiliaryPictureNative() {}

OH_AuxiliaryPictureInfo::OH_AuxiliaryPictureInfo()
{
    auxiliaryPictureInfo_ = std::make_shared<OHOS::Media::AuxiliaryPictureInfo>();
}

OH_AuxiliaryPictureInfo::OH_AuxiliaryPictureInfo(OHOS::Media::AuxiliaryPictureInfo const &auxiliaryPictureInfo)
{
    auxiliaryPictureInfo_ = std::make_shared<OHOS::Media::AuxiliaryPictureInfo>(auxiliaryPictureInfo);
}

std::shared_ptr<OHOS::Media::AuxiliaryPictureInfo> OH_AuxiliaryPictureInfo::GetInnerAuxiliaryPictureInfo()
{
    return auxiliaryPictureInfo_;
}

OH_AuxiliaryPictureInfo::~OH_AuxiliaryPictureInfo() {}

#ifdef __cplusplus
};
#endif