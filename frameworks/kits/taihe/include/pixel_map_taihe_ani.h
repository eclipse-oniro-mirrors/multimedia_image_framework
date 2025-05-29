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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_PIXEL_MAP_TAIHE_ANI_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_PIXEL_MAP_TAIHE_ANI_H

#include <ani.h>
#include "pixel_map.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {

class PixelMapTaiheAni {
public:
    static ani_object CreateEtsPixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap);
    static std::shared_ptr<PixelMap> GetNativePixelMap([[maybe_unused]] ani_env* env, ani_object obj);
    std::shared_ptr<PixelMap> nativePixelMap_;
};

} // namespace Media
} // namespace OHOS

#endif