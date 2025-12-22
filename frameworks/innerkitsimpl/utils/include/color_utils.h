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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_COLOR_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_COLOR_UTILS_H

#include <cstdlib>
#include <cstdio>
#include <string>
#include "image_type.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/cm_color_space.h"
#endif

namespace OHOS {
namespace Media {

class ColorUtils {
public:
    template <typename T>
    static ColorManager::ColorSpaceName CicpToColorSpace(T primaries, T transfer,
        T matrix, uint8_t range);
    template <typename T>
    static void ColorSpaceGetCicp(ColorManager::ColorSpaceName name, T& primaries, T& transfer,
        T& matrix, uint8_t& range);
    static uint16_t GetPrimaries(ColorManager::ColorSpaceName name);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    static HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType ConvertToCMColor(ColorManager::ColorSpaceName name);
    static std::map<ColorManager::ColorSpaceName,
        OHOS::HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo> COLORSPACE_NAME_TO_COLORINFO_MAP;
    static HDI::Display::Graphic::Common::V1_0::CM_ColorPrimaries ConvertCicpToCMColor(uint16_t name);
    static uint16_t ConvertCMColorToCicp(uint16_t name);

    static bool GetColorSpaceName(const skcms_ICCProfile* profile, OHOS::ColorManager::ColorSpaceName &name);
    static bool MatchColorSpaceName(const uint8_t* buf, uint32_t size, OHOS::ColorManager::ColorSpaceName &name);
    static OHOS::ColorManager::ColorSpaceName GetSrcColorSpace(const skcms_ICCProfile* profile);


#endif
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_COLOR_UTILS_H