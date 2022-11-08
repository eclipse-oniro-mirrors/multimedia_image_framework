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
#include "pixel_convert.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class PixelConvertTest : public testing::Test {
public:
    PixelConvertTest() {}
    ~PixelConvertTest() {}
};

/**
 * @tc.name: PixelConvertTest001
 * @tc.desc: Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest001 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_NE(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest001 end";
}

/**
 * @tc.name: PixelConvertTest002
 * @tc.desc: Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest002 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::UNKNOWN;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_EQ(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest002 end";
}

/**
 * @tc.name: PixelConvertTest003
 * @tc.desc: Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest003 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::UNKNOWN;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_EQ(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest003 end";
}

/**
 * @tc.name: PixelConvertTest004
 * @tc.desc: Convert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest004 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    uint8_t source[2] = { 0xA0, 0x64 };
    uint32_t destination[3] = { 0 };

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 1);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest004 end";
}

/**
 * @tc.name: PixelConvertTest005
 * @tc.desc: Convert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest005 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    uint8_t *source = nullptr;
    uint32_t destination[3] = { 0 };

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 1);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest005 end";
}

/**
 * @tc.name: PixelConvertTest006
 * @tc.desc: Convert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest006 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    uint8_t source[2] = { 0xA0, 0x64 };
    void *destination = nullptr;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 1);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest006 end";
}
}
}