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
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "bmp_format_agent.h"
#include "gif_format_agent.h"
#include "heif_format_agent.h"
#include "jpeg_format_agent.h"
#include "png_format_agent.h"
#include "raw_format_agent.h"
#include "wbmp_format_agent.h"
#include "webp_format_agent.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_GIF_PATH = "/data/local/tmp/image/test.gif";
static const std::string IMAGE_INPUT_BMP_PATH = "/data/local/tmp/image/test.bmp";
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_PNG_PATH = "/data/local/tmp/image/test.png";
static const std::string IMAGE_INPUT_WEBP_PATH = "/data/local/tmp/image/test.webp";
static const std::string BMP_FORMAT_TYPE = "image/bmp";
static const std::string GIF_FORMAT_TYPE = "image/gif";
static const std::string JPEG_FORMAT_TYPE = "image/jpeg";
static const std::string PNG_FORMAT_TYPE = "image/png";
static const std::string RAW_FORMAT_TYPE = "image/x-raw";
static const std::string WBMP_FORMAT_TYPE = "image/vnd.wap.wbmp";
static const std::string WEBP_FORMAT_TYPE = "image/webp";
static constexpr uint8_t BMP_HEADER[] = { 0x42, 0x4D };
static const uint8_t GIF_STAMP_LEN = 6;
static constexpr uint8_t JPEG_HEADER[] = { 0xFF, 0xD8, 0xFF };
static constexpr uint8_t PNG_HEADER[] = { 137, 80, 78, 71, 13, 10, 26, 10 };
static constexpr uint32_t RAW_HEADER_SIZE = 0;
static constexpr uint32_t WBMP_HEADER_SIZE = 32;
static constexpr size_t WEBP_MINIMUM_LENGTH = 14;

class FormatAgentPluginTest : public testing::Test {
public:
    FormatAgentPluginTest() {}
    ~FormatAgentPluginTest() {}
};

/**
 * @tc.name: BmpFormatAgentPluginTest001
 * @tc.desc: bmp GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest001 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, BMP_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest001 end";
}

/**
 * @tc.name: BmpFormatAgentPluginTest002
 * @tc.desc: bmp GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest002 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, sizeof(BMP_HEADER));
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest002 end";
}

/**
 * @tc.name: BmpFormatAgentPluginTest003
 * @tc.desc: bmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest003 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest003 end";
}

/**
 * @tc.name: BmpFormatAgentPluginTest004
 * @tc.desc: bmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest004 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/bmp";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_BMP_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest004 end";
}

/**
 * @tc.name: BmpFormatAgentPluginTest005
 * @tc.desc: bmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest005 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    bool ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest005 end";
}

/**
 * @tc.name: BmpFormatAgentPluginTest006
 * @tc.desc: bmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, BmpFormatAgentPluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest006 start";
    ImagePlugin::BmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize() - 10;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/bmp";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_BMP_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: BmpFormatAgentPluginTest006 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest001
 * @tc.desc: Gif GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest001 start";
    ImagePlugin::GifFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, GIF_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest001 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest002
 * @tc.desc: Gif GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest002 start";
    ImagePlugin::GifFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, GIF_STAMP_LEN);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest002 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest003
 * @tc.desc: Gif CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest003 start";
    ImagePlugin::GifFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest003 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest004
 * @tc.desc: Gif CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest004 start";
    ImagePlugin::GifFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/gif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_GIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest004 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest005
 * @tc.desc: Gif CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest005 start";
    ImagePlugin::GifFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    bool ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest005 end";
}

/**
 * @tc.name: GifFormatAgentPluginTest006
 * @tc.desc: Gif CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, GifFormatAgentPluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest006 start";
    ImagePlugin::GifFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize() - 10;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/gif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_GIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: GifFormatAgentPluginTest006 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest001
 * @tc.desc: Jpeg GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest001 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, JPEG_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest001 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest002
 * @tc.desc: Jpeg GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest002 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, sizeof(JPEG_HEADER));
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest002 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest003
 * @tc.desc: Jpeg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest003 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest003 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest004
 * @tc.desc: Jpeg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest004 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest004 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest005
 * @tc.desc: Jpeg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest005 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    bool ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest005 end";
}

/**
 * @tc.name: JpegFormatAgentPluginTest006
 * @tc.desc: Jpeg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, JpegFormatAgentPluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest006 start";
    ImagePlugin::JpegFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize() - 10;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: JpegFormatAgentPluginTest006 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest001
 * @tc.desc: Png GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest001 start";
    ImagePlugin::PngFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, PNG_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest001 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest002
 * @tc.desc: Png GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest002 start";
    ImagePlugin::PngFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, sizeof(PNG_HEADER));
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest002 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest003
 * @tc.desc: Png CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest003 start";
    ImagePlugin::PngFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest003 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest004
 * @tc.desc: Png CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest004 start";
    ImagePlugin::PngFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_PNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest004 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest005
 * @tc.desc: Png CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest005 start";
    ImagePlugin::PngFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    bool ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest005 end";
}

/**
 * @tc.name: PngFormatAgentPluginTest006
 * @tc.desc: Png CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, PngFormatAgentPluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest006 start";
    ImagePlugin::PngFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize() - 10;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_PNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: PngFormatAgentPluginTest006 end";
}

/**
 * @tc.name: RawFormatAgentPluginTest001
 * @tc.desc: Raw GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, RawFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest001 start";
    ImagePlugin::RawFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, RAW_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest001 end";
}

/**
 * @tc.name: RawFormatAgentPluginTest002
 * @tc.desc: Raw GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, RawFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest002 start";
    ImagePlugin::RawFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, RAW_HEADER_SIZE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest002 end";
}

/**
 * @tc.name: RawFormatAgentPluginTest003
 * @tc.desc: Raw CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, RawFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest003 start";
    ImagePlugin::RawFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: RawFormatAgentPluginTest003 end";
}

/**
 * @tc.name: WbmpFormatAgentPluginTest001
 * @tc.desc: Wbmp GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WbmpFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest001 start";
    ImagePlugin::WbmpFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, WBMP_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest001 end";
}

/**
 * @tc.name: WbmpFormatAgentPluginTest002
 * @tc.desc: Wbmp GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WbmpFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest002 start";
    ImagePlugin::WbmpFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, WBMP_HEADER_SIZE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest002 end";
}

/**
 * @tc.name: WbmpFormatAgentPluginTest003
 * @tc.desc: Wbmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WbmpFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest003 start";
    ImagePlugin::WbmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest003 end";
}

/**
 * @tc.name: WbmpFormatAgentPluginTest005
 * @tc.desc: Wbmp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WbmpFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest005 start";
    ImagePlugin::WbmpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    bool ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WbmpFormatAgentPluginTest005 end";
}

/**
 * @tc.name: WebpFormatAgentPluginTest001
 * @tc.desc: Webp GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WebpFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest001 start";
    ImagePlugin::WebpFormatAgent formatAgent;
    std::string ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, WEBP_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest001 end";
}

/**
 * @tc.name: WebpFormatAgentPluginTest002
 * @tc.desc: Webp GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WebpFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest002 start";
    ImagePlugin::WebpFormatAgent formatAgent;
    uint32_t ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, WEBP_MINIMUM_LENGTH);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest002 end";
}

/**
 * @tc.name: WebpFormatAgentPluginTest003
 * @tc.desc: Webp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WebpFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest003 start";
    ImagePlugin::WebpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    bool ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest003 end";
}

/**
 * @tc.name: WebpFormatAgentPluginTest004
 * @tc.desc: Webp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WebpFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest004 start";
    ImagePlugin::WebpFormatAgent formatAgent;
    uint32_t datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/webp";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_WEBP_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest004 end";
}

/**
 * @tc.name: WebpFormatAgentPluginTest005
 * @tc.desc: Webp CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginTest, WebpFormatAgentPluginTest0045, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest005 start";
    ImagePlugin::WebpFormatAgent formatAgent;
    uint32_t datasize = 0;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/webp";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_WEBP_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    bool ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginTest: WebpFormatAgentPluginTest005 end";
}
}
}