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

#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
#include <string>

#include <parameter.h>
#include <parameters.h>
#endif

#include "hilog/log_cpp.h"
#include "image_log.h"

extern "C" {
extern char* __progname;
}
namespace OHOS {
namespace Media {
bool ImageSystemProperties::GetSkiaEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.skdecode.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetSurfaceBufferEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.surfacebuffer.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetDmaEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    static bool isPhone = system::GetParameter("const.product.devicetype", "pc") == "phone";
    bool isFeatureSupported = false;
    if (isPhone) {
        if (strncmp(__progname, "mos.photo", strlen("mos.photo")) == 0 ||
            strncmp(__progname, "myapplication", strlen("myapplication")) == 0) {
            isFeatureSupported = true;
        }
    }
    return system::GetBoolParameter("persist.multimedia.image.dma.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetAntiAliasingEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    static bool isDeviceSupportsAA =
        system::GetParameter("const.product.devicetype", "pc") == "pc" ||
        system::GetParameter("const.product.devicetype", "pc") == "tablet";
    return isDeviceSupportsAA && system::GetBoolParameter("persist.multimedia.image.AntiAliasing.enabled", true);
#else
    return false;
#endif
}
} // namespace Media
} // namespace OHOS
