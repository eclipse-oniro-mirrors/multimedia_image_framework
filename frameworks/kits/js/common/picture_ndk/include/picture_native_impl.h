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
#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_NATIVE_IMPL_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_NATIVE_IMPL_H
#include <stdint.h>
#include "picture.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_PictureNative {
public:
    OH_PictureNative(std::shared_ptr<OHOS::Media::Picture> picture);
    OH_PictureNative(std::shared_ptr<OHOS::Media::PixelMap> pixelmap);
    ~OH_PictureNative();
    std::shared_ptr<OHOS::Media::Picture> GetInnerPicture();

private:
    std::shared_ptr<OHOS::Media::Picture> picture_;
};

struct OH_AuxiliaryPictureNative {
public:
    OH_AuxiliaryPictureNative(std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxiliaryPicture);
    OH_AuxiliaryPictureNative(std::shared_ptr<OHOS::Media::PixelMap> &content,
        OHOS::Media::AuxiliaryPictureType type, OHOS::Media::Size size);
    ~OH_AuxiliaryPictureNative();
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> GetInnerAuxiliaryPicture();

private:
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxiliaryPicture_;
};

struct OH_AuxiliaryPictureInfo {
public:
    OH_AuxiliaryPictureInfo();
    OH_AuxiliaryPictureInfo(OHOS::Media::AuxiliaryPictureInfo const &auxiliaryPictureInfo);
    std::shared_ptr<OHOS::Media::AuxiliaryPictureInfo> GetInnerAuxiliaryPictureInfo();
    ~OH_AuxiliaryPictureInfo();

private:
    std::shared_ptr<OHOS::Media::AuxiliaryPictureInfo> auxiliaryPictureInfo_;
};

#ifdef __cplusplus
};
#endif
/** @} */
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_NATIVE_IMPL_H