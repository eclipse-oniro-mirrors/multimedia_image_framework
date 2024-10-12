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
#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_METADATA_IMPL_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_METADATA_IMPL_H
#include <stdint.h>
#include "metadata.h"
#include <memory>
#ifdef __cplusplus
extern "C" {
#endif

struct OH_PictureMetadata {
public:
    OH_PictureMetadata(std::shared_ptr<OHOS::Media::ImageMetadata> metadata);
    std::shared_ptr<OHOS::Media::ImageMetadata> GetInnerAuxiliaryMetadata();
    ~OH_PictureMetadata();
private:
    std::shared_ptr<OHOS::Media::ImageMetadata> metadatas_;
};

#ifdef __cplusplus
};
#endif
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_PICUTRE_METADATA_IMPL_H