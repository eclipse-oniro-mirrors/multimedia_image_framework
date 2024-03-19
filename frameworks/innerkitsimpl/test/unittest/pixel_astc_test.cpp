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
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_astc.h"
#include "pixel_convert_adapter.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.astc";
class PixelAstcTest : public testing::Test {
public:
    PixelAstcTest() {}
    ~PixelAstcTest() {}
};

static void ConstructPixelAstc(std::unique_ptr<PixelMap>& pixelMap)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
}

/**
 * @tc.name: PixelAstcTest001
 * @tc.desc: PixelAstc scale
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest001 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    ASSERT_NE(pixelAstc.get(), nullptr);
    // 2.0 means scale width value
    float xAxis = 2.0;
    // 2.0 means scale height value
    float yAxis = 2.0;
    pixelAstc->scale(xAxis, yAxis);
    TransformData transformData;
    pixelAstc->GetTransformData(transformData);
    ASSERT_EQ(transformData.scaleX, 2.0); // 2.0 means scale width value
    ASSERT_EQ(transformData.scaleY, 2.0); // 2.0 means scale height value
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest001 end";
}

/**
 * @tc.name: PixelAstcTest002
 * @tc.desc: PixelAstc translate
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest002 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    ASSERT_NE(pixelAstc.get(), nullptr);
    // 2.0 means x_coordinate value
    float xAxis = 2.0;
    // 2.0 means y_coordinate value
    float yAxis = 2.0;
    pixelAstc->translate(xAxis, yAxis);
    TransformData transformData;
    pixelAstc->GetTransformData(transformData);
    ASSERT_EQ(transformData.translateX, 2.0); // 2.0 means x_coordinate value
    ASSERT_EQ(transformData.translateY, 2.0); // 2.0 means y_coordinate value
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest002 end";
}

/**
 * @tc.name: PixelAstcTest003
 * @tc.desc: PixelAstc flip
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest003 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    ASSERT_NE(pixelAstc.get(), nullptr);
    bool xAxis = false;
    bool yAxis = true;
    pixelAstc->flip(xAxis, yAxis);
    TransformData transformData;
    pixelAstc->GetTransformData(transformData);
    ASSERT_EQ(transformData.flipX, false);
    ASSERT_EQ(transformData.flipY, true);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest003 end";
}

/**
 * @tc.name: PixelAstcTest004
 * @tc.desc: PixelAstc rotate
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest004 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    ASSERT_NE(pixelAstc.get(), nullptr);
    // 2.0 means rotate angle value
    float degrees = 2.0;
    pixelAstc->rotate(degrees);
    TransformData transformData;
    pixelAstc->GetTransformData(transformData);
    ASSERT_EQ(transformData.rotateD, 2.0); // 2.0 means rotate angle value

    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest004 end";
}

/**
 * @tc.name: PixelAstcTest005
 * @tc.desc: PixelAstc crop
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest005 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    Rect rect;
    // -1 means to the left of the distance rect
    rect.left = -1;
    rect.top = 1;
    rect.width = 1;
    rect.height = 1;
    uint32_t ret = pixelAstc->crop(rect);
    EXPECT_EQ(ERR_IMAGE_CROP, ret);

    // -1 means to the top of the distance rect
    rect.left = 1;
    rect.top = -1;
    ret = pixelAstc->crop(rect);
    EXPECT_EQ(ERR_IMAGE_CROP, ret);

    // -1 means width of the crop part
    rect.top = 1;
    rect.width = -1;
    ret = pixelAstc->crop(rect);
    EXPECT_EQ(ERR_IMAGE_CROP, ret);

    // -1 means height of the crop part
    rect.width = 1;
    rect.height = -1;
    ret = pixelAstc->crop(rect);
    EXPECT_EQ(ERR_IMAGE_CROP, ret);

    rect.height = 1;
    ret = pixelAstc->crop(rect);
    EXPECT_EQ(SUCCESS, ret);
    TransformData transformData;
    pixelAstc->GetTransformData(transformData);
    ASSERT_EQ(transformData.cropLeft, 1);
    ASSERT_EQ(transformData.cropTop, 1);
    ASSERT_EQ(transformData.cropWidth, 1);
    ASSERT_EQ(transformData.cropHeight, 1);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest005 end";
}

/**
 * @tc.name: PixelAstcTest006
 * @tc.desc: PixelAstc SetAlpha
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest006 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    // 0.5 means transparency
    float percent = 0.5;
    uint32_t ret = pixelAstc->SetAlpha(percent);
    EXPECT_EQ(ERR_IMAGE_DATA_UNSUPPORT, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest006 end";
}

/**
 * @tc.name: PixelAstcTest008
 * @tc.desc: PixelAstc GetARGB32ColorA
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest008 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    // 1 means ARGB color value
    uint32_t color = 1;
    uint8_t ret = pixelAstc->GetARGB32ColorA(color);
    EXPECT_EQ(0, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest008 end";
}

/**
 * @tc.name: PixelAstcTest009
 * @tc.desc: PixelAstc GetARGB32ColorR
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest009 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    // 1 means ARGB color value
    uint32_t color = 1;
    uint8_t ret = pixelAstc->GetARGB32ColorR(color);
    EXPECT_EQ(0, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest009 end";
}


/**
 * @tc.name: PixelAstcTest010
 * @tc.desc: PixelAstc GetARGB32ColorG
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest010 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    // 1 means ARGB color value
    uint32_t color = 1;
    uint8_t ret = pixelAstc->GetARGB32ColorG(color);
    EXPECT_EQ(0, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest010 end";
}

/**
 * @tc.name: PixelAstcTest011
 * @tc.desc: PixelAstc GetARGB32ColorB
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest011 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    // 1 means ARGB color value
    uint32_t color = 1;
    uint8_t ret = pixelAstc->GetARGB32ColorB(color);
    EXPECT_EQ(0, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest011 end";
}

/**
 * @tc.name: PixelAstcTest012
 * @tc.desc: PixelAstc IsSameImage
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest012 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    PixelMap pixelmap;
    bool ret = pixelAstc->IsSameImage(pixelmap);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest012 end";
}

/**
 * @tc.name: PixelAstcTest013
 * @tc.desc: PixelAstc IsSameImage
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest013 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    PixelMap pixelmap;
    bool ret = pixelAstc->IsSameImage(pixelmap);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest013 end";
}

/**
 * @tc.name: PixelAstcTest014
 * @tc.desc: PixelAstc ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest014 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    const uint64_t bufferSize = 0;
    const uint32_t offset = 0;
    const uint32_t stride = 0;
    Rect region;
    uint8_t dst;
    uint32_t ret = pixelAstc->ReadPixels(bufferSize, offset, stride, region, &dst);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest014 end";
}

/**
 * @tc.name: PixelAstcTest015
 * @tc.desc: PixelAstc ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest015 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    const uint64_t bufferSize = 0;
    uint8_t dst;
    uint32_t ret = pixelAstc->ReadPixels(bufferSize, &dst);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest015 end";
}

/**
 * @tc.name: PixelAstcTest016
 * @tc.desc: PixelAstc ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest016 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    Position pos;
    uint32_t dst;
    uint32_t ret = pixelAstc->ReadPixel(pos, dst);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest016 end";
}

/**
 * @tc.name: PixelAstcTest017
 * @tc.desc: PixelAstc ResetConfig
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest017 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    Size size;
    PixelFormat format = PixelFormat::RGBA_8888;
    uint32_t ret = pixelAstc->ResetConfig(size, format);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest017 end";
}

/**
 * @tc.name: PixelAstcTest018
 * @tc.desc: PixelAstc SetAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest018 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    const AlphaType alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    bool ret = pixelAstc->SetAlphaType(alphaType);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest018 end";
}

/**
 * @tc.name: PixelAstcTest019
 * @tc.desc: PixelAstc WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest019 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    Position pos;
    const uint32_t dst = 0;
    uint32_t ret = pixelAstc->WritePixel(pos, dst);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest019 end";
}

/**
 * @tc.name: PixelAstcTest020
 * @tc.desc: PixelAstc WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest020 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    uint8_t *source = nullptr;
    const uint64_t bufferSize = 0;
    const uint32_t offset = 0;
    const uint32_t stride = 0;
    Rect region;
    uint32_t ret = pixelAstc->WritePixels(source, bufferSize, offset, stride, region);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest020 end";
}

/**
 * @tc.name: PixelAstcTest021
 * @tc.desc: PixelAstc WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest021 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    const uint32_t color = 0;
    bool ret = pixelAstc->WritePixels(color);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest021 end";
}

/**
 * @tc.name: PixelAstcTest022
 * @tc.desc: PixelAstc WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest022 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    uint8_t *source = nullptr;
    const uint64_t bufferSize = 0;
    uint32_t ret = pixelAstc->WritePixels(source, bufferSize);
    EXPECT_EQ(ERR_IMAGE_INVALID_PARAMETER, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest022 end";
}

/**
 * @tc.name: PixelAstcTest023
 * @tc.desc: PixelAstc SetTransformered
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest023 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    bool isTransFormered = false;
    pixelAstc->SetTransformered(isTransFormered);
    bool ret = pixelAstc->IsTransformered();
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest023 end";
}

/**
 * @tc.name: PixelAstcTest024
 * @tc.desc: PixelAstc SetRowStride
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest024 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    int32_t ret = pixelAstc->GetRowStride();
    EXPECT_EQ(0, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest024 end";
}

/**
 * @tc.name: PixelAstcTest025
 * @tc.desc: PixelAstc IsSourceAsResponse
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest025 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    bool ret = pixelAstc->IsSourceAsResponse();
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest025 end";
}

/**
 * @tc.name: PixelAstcTest026
 * @tc.desc: PixelAstc GetWritablePixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcTest, PixelAstcTest026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest026 start";
    std::unique_ptr<PixelMap> pixelAstc = std::unique_ptr<PixelMap>();
    ConstructPixelAstc(pixelAstc);
    EXPECT_EQ(nullptr, pixelAstc->GetWritablePixels());
    GTEST_LOG_(INFO) << "PixelAstcTest: PixelAstcTest026 end";
}
}
}