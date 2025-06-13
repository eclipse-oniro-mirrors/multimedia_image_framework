/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_source_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceGifTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
class ImageSourceGifTest : public testing::Test {
public:
    ImageSourceGifTest() {}
    ~ImageSourceGifTest() {}
};

/**
 * @tc.name: GifImageDecode002
 * @tc.desc: Create image source by correct gif file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.gif", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get the number of image, compatibility test.
     * @tc.expected: step2. check the number of image equals the actual number.
     */
    int32_t imageCount = imageSource->GetSourceInfo(errorCode).topLevelImageNum;
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(1, imageCount);
}

/**
 * @tc.name: GifImageDecode003
 * @tc.desc: Create image source by wrong file path and correct format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct png file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/gif";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/gif/test.gif", opts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    ASSERT_EQ(imageSource.get(), nullptr);
}
} // namespace Multimedia
} // namespace OHOS