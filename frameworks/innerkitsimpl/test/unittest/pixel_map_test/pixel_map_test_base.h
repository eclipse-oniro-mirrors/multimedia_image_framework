/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef PIXEL_MAP_TEST_BASE_H
#define PIXEL_MAP_TEST_BASE_H

#define protected public
#define private public
#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_convert.h"
#include "pixel_map.h"
#include "pixel_convert_adapter.h"
#include "securec.h"

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <fcntl.h>
#include <unistd.h>
#endif

#define IMAGE_YUV_PATH  "/data/local/tmp/image/P010.yuv"

namespace OHOS {
namespace Multimedia {
using Rect = OHOS::Media::Rect;
constexpr int8_t ARGB_8888_BYTES = 4;
constexpr uint32_t SIZE_WIDTH = 2;
constexpr uint32_t SIZE_HEIGHT = 2;

class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};

std::unique_ptr<OHOS::Media::PixelMap> ConstructPixelMap(int32_t width, int32_t height, OHOS::Media::PixelFormat format,
    OHOS::Media::AlphaType alphaType, OHOS::Media::AllocatorType type);

}
}

#endif // PIXEL_MAP_TEST_BASE_H
