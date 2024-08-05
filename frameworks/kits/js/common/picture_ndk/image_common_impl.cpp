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
#include "image_common_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

OH_PictureMetadata::OH_PictureMetadata(std::shared_ptr<OHOS::Media::ImageMetadata> metadata)
{
    metadatas_ = metadata;
}

std::shared_ptr<OHOS::Media::ImageMetadata> OH_PictureMetadata::GetInnerAuxiliaryMetadata()
{
    return metadatas_;
}

OH_PictureMetadata::~OH_PictureMetadata() {}

#ifdef __cplusplus
};
#endif