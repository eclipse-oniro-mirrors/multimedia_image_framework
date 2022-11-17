/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <fstream>
#include <fcntl.h>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "pixel_map_rosen_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";

class PixelMapRosenUtilsTest : public testing::Test {
public:
    PixelMapRosenUtilsTest() {}
    ~PixelMapRosenUtilsTest() {}
};

/**
 * @tc.name: PixelMapRosenUtilsTest001
 * @tc.desc: UploadToGpu
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapRosenUtilsTest, PixelMapRosenUtilsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapRosenUtilsTest: PixelMapRosenUtilsTest001 start";
    PixelMapRosenUtils rUtils;
    GrContext* context = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::shared_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);

    bool buildMips = false;
    bool limitToMaxTextureSize = false;
    bool ret = rUtils.UploadToGpu(pixelMap, context, buildMips, limitToMaxTextureSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelMapRosenUtilsTest: PixelMapRosenUtilsTest001 end";
}

/**
 * @tc.name: PixelMapRosenUtilsTest002
 * @tc.desc: UploadToGpu
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapRosenUtilsTest, PixelMapRosenUtilsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapRosenUtilsTest: PixelMapRosenUtilsTest002 start";
    PixelMapRosenUtils rUtils;
    GrContext* context = nullptr;
    std::shared_ptr<PixelMap> pixelMap = nullptr;

    bool buildMips = false;
    bool limitToMaxTextureSize = false;
    bool ret = rUtils.UploadToGpu(pixelMap, context, buildMips, limitToMaxTextureSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelMapRosenUtilsTest: PixelMapRosenUtilsTest002 end";
}
}
}