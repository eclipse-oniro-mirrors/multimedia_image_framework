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
#if __BYTE_ORDER == __LITTLE_ENDIAN
constexpr bool IS_LITTLE_ENDIAN = true;
#else
constexpr bool IS_LITTLE_ENDIAN = false;
#endif
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

/**
 * @tc.name: PixelConvertTest007
 * @tc.desc: Create srcImageInfo.alphaType is IMAGE_ALPHA_TYPE_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest007 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::UNKNOWN;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_EQ(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest007 end";
}

/**
 * @tc.name: PixelConvertTest008
 * @tc.desc: Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest008 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    dstImageInfo.pixelFormat = PixelFormat::UNKNOWN;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_EQ(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest008 end";
}

/**
 * @tc.name: PixelConvertTest009
 * @tc.desc: GRAY_BIT to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest009 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(GRAY_BIT);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest009 start";
}

/**
 * @tc.name: PixelConvertTest0010
 * @tc.desc: GRAY_BIT to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0010 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(GRAY_BIT);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0010 start";
}

/**
 * @tc.name: PixelConvertTest0011
 * @tc.desc: GRAY_BIT to ALPHA_8 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0011 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(GRAY_BIT);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ALPHA_8;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0011 start";
}

/**
 * @tc.name: PixelConvertTest0012
 * @tc.desc: ALPHA_8 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0012 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::ALPHA_8;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0012 start";
}

/**
 * @tc.name: PixelConvertTest0013
 * @tc.desc: ALPHA_8 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0013 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::ALPHA_8;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0013 start";
}

/**
 * @tc.name: PixelConvertTest0014
 * @tc.desc: GRAY_ALPHA to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0014 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(GRAY_ALPHA);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0014 start";
}

/**
 * @tc.name: PixelConvertTest0015
 * @tc.desc: GRAY_ALPHA to ALPHA_8 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0015 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(GRAY_ALPHA);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ALPHA_8;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0015 start";
}

/**
 * @tc.name: PixelConvertTest0016
 * @tc.desc: RGB_888 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0016 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0016 start";
}

/**
 * @tc.name: PixelConvertTest0017
 * @tc.desc: RGB_888 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0017 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0017 start";
}

/**
 * @tc.name: PixelConvertTest0018
 * @tc.desc: RGB_888 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0018 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0018 start";
}

/**
 * @tc.name: PixelConvertTest0019
 * @tc.desc: RGB_888 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0019 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0019 start";
}

/**
 * @tc.name: PixelConvertTest0020
 * @tc.desc: BGR_888 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0020 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(BGR_888);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0020 start";
}

/**
 * @tc.name: PixelConvertTest0021
 * @tc.desc: BGR_888 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0021 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(BGR_888);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0021 start";
}

/**
 * @tc.name: PixelConvertTest0022
 * @tc.desc: BGR_888 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0022 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(BGR_888);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0022 start";
}

/**
 * @tc.name: PixelConvertTest0023
 * @tc.desc: BGR_888 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0023 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(BGR_888);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0023 start";
}

/**
 * @tc.name: PixelConvertTest0099
 * @tc.desc: RGB_161616 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0099, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0099 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGB_161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0099 start";
}

/**
 * @tc.name: PixelConvertTest0024
 * @tc.desc: RGB_161616 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0024 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGB_161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0024 start";
}

/**
 * @tc.name: PixelConvertTest0025
 * @tc.desc: RGB_161616 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0025 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGB_161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0025 start";
}

/**
 * @tc.name: PixelConvertTest0026
 * @tc.desc: RGB_161616 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0026 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGB_161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0026 start";
}

/**
 * @tc.name: PixelConvertTest0027
 * @tc.desc: RGB_565 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0027 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0027 start";
}

/**
 * @tc.name: PixelConvertTest0028
 * @tc.desc: RGB_565 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0028 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0028 start";
}

/**
 * @tc.name: PixelConvertTest0029
 * @tc.desc: RGB_565 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0029 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGB_565;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0029 start";
}

/**
 * @tc.name: PixelConvertTest0030
 * @tc.desc: RGBA_8888 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0030 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0030 start";
}

/**
 * @tc.name: PixelConvertTest0031
 * @tc.desc: RGBA_8888 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0031 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0031 start";
}

/**
 * @tc.name: PixelConvertTest0032
 * @tc.desc: RGBA_8888 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0032 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0032 start";
}

/**
 * @tc.name: PixelConvertTest0033
 * @tc.desc: RGBA_8888 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0033 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0033 start";
}

/**
 * @tc.name: PixelConvertTest0034
 * @tc.desc: BGRA_8888 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0034 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0034 start";
}

/**
 * @tc.name: PixelConvertTest0035
 * @tc.desc: BGRA_8888 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0035 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0035 start";
}

/**
 * @tc.name: PixelConvertTest0036
 * @tc.desc: BGRA_8888 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0036 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0036 start";
}

/**
 * @tc.name: PixelConvertTest0037
 * @tc.desc: BGRA_8888 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0037 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0037 start";
}

/**
 * @tc.name: PixelConvertTest0038
 * @tc.desc: BGRA_8888 to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0038 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0038 start";
}

/**
 * @tc.name: PixelConvertTest0039
 * @tc.desc: ARGB_8888 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0039 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0039 start";
}

/**
 * @tc.name: PixelConvertTest0040
 * @tc.desc: RGBA_16161616 to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0040, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0040 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGBA_16161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0040 start";
}

/**
 * @tc.name: PixelConvertTest0041
 * @tc.desc: RGBA_16161616 to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0041, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0041 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGBA_16161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0041 start";
}

/**
 * @tc.name: PixelConvertTest0042
 * @tc.desc: RGBA_16161616 to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0042, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0042 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGBA_16161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0042 start";
}

/**
 * @tc.name: PixelConvertTest0043
 * @tc.desc: RGBA_16161616 to ABGR_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0043, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0043 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGBA_16161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = static_cast<PixelFormat>(ABGR_8888);

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0043 start";
}

/**
 * @tc.name: PixelConvertTest0044
 * @tc.desc: CMKY to ARGB_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0044, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0044 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(CMKY);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0044 start";
}

/**
 * @tc.name: PixelConvertTest0045
 * @tc.desc: CMKY to RGBA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0045, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0045 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(CMKY);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0045 start";
}

/**
 * @tc.name: PixelConvertTest0046
 * @tc.desc: CMKY to BGRA_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0046, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0046 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(CMKY);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::BGRA_8888;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0046 start";
}

/**
 * @tc.name: PixelConvertTest0047
 * @tc.desc: CMKY to ABGR_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0047, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0047 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(CMKY);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = static_cast<PixelFormat>(ABGR_8888);

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0047 start";
}

/**
 * @tc.name: PixelConvertTest0048
 * @tc.desc: CMKY to RGB_565 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0048, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0048 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(CMKY);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = PixelFormat::RGB_565;

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0048 start";
}

/**
 * @tc.name: PixelConvertTest0049
 * @tc.desc: Create srcImageInfo.alphaType is IMAGE_ALPHA_TYPE_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0049, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0049 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_NE(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0049 end";
}

/**
 * @tc.name: PixelConvertTest0050
 * @tc.desc: Create dstImageInfo.alphaType is IMAGE_ALPHA_TYPE_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0050, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0050 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_NE(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0050 end";
}

/**
 * @tc.name: PixelConvertTest0051
 * @tc.desc: Create ImageInfo.alphaType is IMAGE_ALPHA_TYPE_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0051, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0051 start";
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;

    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    EXPECT_NE(colorConverterPointer, nullptr);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0051 end";
}

/**
 * @tc.name: PixelConvertTest0052
 * @tc.desc: RGB_161616 to ABGR_8888 UNPREMUL to UNPREMUL.
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertTest, PixelConvertTest0052, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0052 start";
    /**
     * @tc.steps: step1. set parameters to build object.
     * @tc.expected: step1. set parameters success.
     */
    ImageInfo srcImageInfo;
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    srcImageInfo.pixelFormat = static_cast<PixelFormat>(RGB_161616);

    ImageInfo dstImageInfo;
    dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    dstImageInfo.pixelFormat = static_cast<PixelFormat>(ABGR_8888);

    uint8_t source[50] = { 0 };
    uint32_t destination[8] = { 0 };
    uint32_t result[3] = { 0 };
    if (IS_LITTLE_ENDIAN) {
        result[0] = 0x80020408;
        result[1] = 0x40020408;
    } else {
        result[0] = 0x08040280;
        result[1] = 0x08040240;
    }
    /**
     * @tc.steps: step2. build pixel convert object.
     * @tc.expected: step2. The return value is the same as the result.
     */
    std::unique_ptr<PixelConvert> colorConverterPointer = PixelConvert::Create(srcImageInfo, dstImageInfo);
    colorConverterPointer->Convert(destination, source, 2);
    GTEST_LOG_(INFO) << "PixelConvertTest: PixelConvertTest0052 start";
}
}
}