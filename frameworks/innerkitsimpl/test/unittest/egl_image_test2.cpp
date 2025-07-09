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

#include <gtest/gtest.h>
#include <sys/mman.h>

#include "native_window.h"
#include "pixel_map_from_surface.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int DEFAULT_WIDTH = 1280;
static constexpr int DEFAULT_HEIGHT = 800;

class EglImageTest : public testing::Test {
public:
    EglImageTest() {}
    ~EglImageTest() {}
};

/**
 * @tc.name: PixelMapFromSurfaceTest001
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest001, TestSize.Level3)
{
    Rect srcRect = {0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    // pass an invalid surfaceId to expect to get an invalid result.
    auto pixelMap = CreatePixelMapFromSurfaceId(0, srcRect);
    EXPECT_EQ(pixelMap, nullptr);
}
}
}
