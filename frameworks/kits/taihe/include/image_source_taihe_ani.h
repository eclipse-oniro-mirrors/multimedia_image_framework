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

#ifndef FRAMEWORK_KITS_TAIHE_INCLUDE_IMAGE_SOURCE_TAIHE_ANI_H
#define FRAMEWORK_KITS_TAIHE_INCLUDE_IMAGE_SOURCE_TAIHE_ANI_H

#include <ani.h>
#include "image_source.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {

class ImageSourceTaiheAni {
public:
    static ani_object CreateEtsImageSource(ani_env *env, std::shared_ptr<ImageSource> imageSource);
    std::shared_ptr<ImageSource> nativeImgSrc;
};

} // namespace Media
} // namespace OHOS

#endif