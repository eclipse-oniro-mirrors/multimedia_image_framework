/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "image_system_properties.h"

#include <parameter.h>
#include <parameters.h>

#include "hilog/log_cpp.h"
#include "image_log.h"

namespace OHOS {
namespace Media {
    bool ImageSystemProperties::GetSkiaEnabled()
    {
        return system::GetBoolParameter("persist.multimedia.image.skdecode.enabled", true);
    }
    bool ImageSystemProperties::GetSurfaceBufferEnabled()
    {
        return system::GetBoolParameter("persist.multimedia.image.surfacebuffer.enabled", false);
    }
} // namespace Media
} // namespace OHOS