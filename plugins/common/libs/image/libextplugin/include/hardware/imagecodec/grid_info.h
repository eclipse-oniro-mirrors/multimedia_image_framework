/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMAGE_CODEC_GRID_INFO_H
#define IMAGE_CODEC_GRID_INFO_H

#include <cinttypes>

namespace OHOS {
namespace ImagePlugin {
struct GridInfo {
    uint32_t displayWidth = 0;
    uint32_t displayHeight = 0;
    bool enableGrid = false;
    uint32_t cols = 0;
    uint32_t rows = 0;
    uint32_t tileWidth = 0;
    uint32_t tileHeight = 0;

    bool IsValid() const;
};
}
}
#endif //IMAGE_CODEC_GRID_INFO_H
