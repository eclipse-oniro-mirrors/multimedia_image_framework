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

namespace OHOS {
namespace Media {

class ColorUtils {
public:
    static ColorManager::ColorSpaceName CicpToColorSpace(uint16_t primaries, uint16_t transfer,
        uint16_t matrix, uint8_t range);
    static void ColorSpaceGetCicp(ColorManager::ColorSpaceName name, uint16_t& primaries, uint16_t& transfer,
        uint16_t& matrix, uint8_t& range);
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_COLOR_UTILS_H