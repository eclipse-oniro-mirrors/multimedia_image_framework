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
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>
#include "image/abs_image_decoder.h"
#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_source_util.h"
#include "incremental_source_stream.h"
#include "istream_source_stream.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "source_stream.h"
#include "image_source.h"
#include "buffer_source_stream.h"
#include "file_source_stream.h"
#include "memory_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_HDR_PIC1_PATH = "/data/local/tmp/image/hdr_1.jpg";
static const std::string IMAGE_INPUT_HDR_PIC2_PATH = "/data/local/tmp/image/hdr_2.jpg";
static const std::string IMAGE_INPUT_HDR_PIC3_PATH = "/data/local/tmp/image/hdr_3.jpg";
static const std::string IMAGE_INPUT_HDR_PIC4_PATH = "/data/local/tmp/image/hdr_4.jpg";
static const std::string IMAGE_INPUT_HDR_PIC5_PATH = "/data/local/tmp/image/hdr_5.jpg";
static const std::string IMAGE_INPUT_HDR_PIC6_PATH = "/data/local/tmp/image/hdr_6.jpg";
static const std::string IMAGE_INPUT_NON_HDR_PIC_PATH = "/data/local/tmp/image/non_hdr.jpg";

class ImageSourceAiTest : public testing::Test {
public:
    ImageSourceAiTest() {}
    ~ImageSourceAiTest() {}
};

class MockAbsImageFormatAgent : public ImagePlugin::AbsImageFormatAgent {
public:
    MockAbsImageFormatAgent() = default;
    virtual ~MockAbsImageFormatAgent() {}

    std::string GetFormatType() override
    {
        return returnString_;
    }
    uint32_t GetHeaderSize() override
    {
        return returnValue_;
    }
    bool CheckFormat(const void *headerData, uint32_t dataSize) override
    {
        return returnBool_;
    }
private:
    std::string returnString_ = "";
    uint32_t returnValue_ = 0;
    bool returnBool_ = false;
};

class MockDecodeListener : public DecodeListener {
public:
    MockDecodeListener() = default;
    ~MockDecodeListener() {}

    void OnEvent(int event) override
    {
        returnVoid_ = event;
    }
private:
    int returnVoid_;
};

/**
 * @tc.name: AisrTestLargerHigh
 * @tc.desc: set want larger size. HIGH:Decode module NOT zoom the size, SR module zoom the size.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestLargerHigh, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTestLargerHigh start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = jpegWidth + 400; // enable AISR by desired size
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.resolutionQuality = ResolutionQuality::HIGH; // decode module zoom to want size

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode); // aisr process change solution quality
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTest after CreatePixelMap(desiredSize)";
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestLargerMiddle
 * @tc.desc: set want larger size. Low/middle:Decode module zoom the size, SR module change to HIGH solution(default).
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestLargerMiddle, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTestLargerMiddle start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = jpegWidth + 400; // enable AISR by desired size
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.resolutionQuality = ResolutionQuality::MEDIUM;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTest after CreatePixelMap(desiredSize)";
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestLargerLow
 * @tc.desc: set want larger size. Low/middle:Decode module zoom the size, SR module change to HIGH solution(default).
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestLargerLow, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTestLargerLow start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = jpegWidth + 400; // enable AISR by desired size
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    GTEST_LOG_(INFO) << "ImageSourceAiTest: AisrTest after CreatePixelMap(desiredSize)";
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestSmallerHigh
 * @tc.desc: test jpg, set want smaller size + HIGH.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestSmallerHigh, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = 400; // enable AISR by desired size
    int32_t desiredHeight = 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.resolutionQuality = ResolutionQuality::HIGH; // decode zoom to want size

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode); // aisr process change solution quality
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestSmallerMiddle
 * @tc.desc: test jpg, set want smaller size + MEDIUM.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestSmallerMiddle, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = 400; // enable AISR by desired size
    int32_t desiredHeight = 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.resolutionQuality = ResolutionQuality::MEDIUM; // decode to old size

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode); // AiSr process zoom to want size
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestSmallerLow
 * @tc.desc: test jpg, set want smaller size + LOW.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestSmallerLow, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = 400; // enable AISR by desired size
    int32_t desiredHeight = 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.resolutionQuality = ResolutionQuality::LOW;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: AisrTestEqual
 * @tc.desc: test jpg, set want equal size, so NOT run AISR.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, AisrTestEqual, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();
    int32_t desiredWidth = jpegWidth; // bypass AISR by desired size
    int32_t desiredHeight = jpegHeight;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: HdrTestBase
 * @tc.desc: test jpg, keep old size, set dynamic range to HDR, to run AIHDR.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, HdrTestBase, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceAiTest: HdrTestBase start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth + 0;
    int32_t desiredHeight = jpegHeight + 0;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());

    GTEST_LOG_(INFO) << "ImageSourceAiTest: HdrTestBase end";
}

/**
 * @tc.name: HdrTest720p
 * @tc.desc: test size < 720p jpg, check result is: run AiHdr but return ERROR
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, HdrTest720p, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_NON_HDR_PIC_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth + 0;
    int32_t desiredHeight = jpegHeight + 0;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestLargerHigh
 * @tc.desc: Set larger want size + HIGH to run aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestLargerHigh, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth + 400;
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::HIGH;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestLargerMiddle
 * @tc.desc: Set larger want size + MEDIUM to turn on aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestLargerMiddle, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth + 400;
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::MEDIUM;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestLargerLow
 * @tc.desc: Set larger want size + LOW to run aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestLargerLow, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth + 400;
    int32_t desiredHeight = jpegHeight + 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::LOW;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestSmallerHigh
 * @tc.desc: Set smaller want size + HIGH to run aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestSmallerHigh, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth - 400;
    int32_t desiredHeight = jpegHeight - 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::HIGH;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestSmallerMiddle
 * @tc.desc: Set smaller want size + MEDIUM to run aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestSmallerMiddle, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth - 400;
    int32_t desiredHeight = jpegHeight - 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::MEDIUM;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: SrHdrTestSmallerLow
 * @tc.desc: Set smaller want size + LOW to run aisr;set HDR to run AIHDR. (AiSr/AiHdr both)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAiTest, SrHdrTestSmallerLow, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_HDR_PIC1_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 0;
    int32_t jpegHeight = 0;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    jpegWidth = pixelMap->GetWidth();
    jpegHeight = pixelMap->GetHeight();

    int32_t desiredWidth = jpegWidth - 400;
    int32_t desiredHeight = jpegHeight - 400;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    decodeOpts.resolutionQuality = ResolutionQuality::LOW;

    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}
} // namespace Multimedia
} // namespace OHOS