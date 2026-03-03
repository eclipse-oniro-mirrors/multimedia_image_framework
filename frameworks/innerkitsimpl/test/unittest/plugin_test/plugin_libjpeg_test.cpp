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
#define IMAGE_COLORSPACE_FLAG
#define private public
#define protected public
#include <fcntl.h>
#include "buffer_packer_stream.h"
#include "buffer_source_stream.h"
#include "plugin_export.h"
#include "icc_profile_info.h"
#include "jpeg_decoder.h"
#include "jpeg_encoder.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_NULL_JPEG_PATH = "/data/local/tmp/image/test_null.jpg";
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_INPUT_TXT_PATH = "/data/local/tmp/image/test.txt";
constexpr uint32_t COMPONENT_NUM_RGBA = 4;
constexpr uint32_t COMPONENT_NUM_BGRA = 4;
constexpr uint32_t COMPONENT_NUM_RGB = 3;
constexpr uint32_t COMPONENT_NUM_GRAY = 1;
constexpr uint8_t COMPONENT_NUM_YUV420SP = 3;
static constexpr uint32_t NUM_1000 = 1000;
constexpr unsigned long LONG_FILELENGTH = 100;
constexpr int VALID_SIZE = 50;
constexpr int32_t OPTS_SIZE = 16;
static constexpr uint32_t TEST_IMAGE_WIDTH_SMALL = 16;
static constexpr uint32_t TEST_IMAGE_HEIGHT_SMALL = 16;
static constexpr uint32_t TEST_IMAGE_WIDTH_UNALIGNED = 15;
static constexpr uint32_t TEST_IMAGE_HEIGHT_UNALIGNED = 15;
static constexpr uint32_t TEST_IMAGE_WIDTH_LARGE = 32;
static constexpr uint32_t TEST_IMAGE_HEIGHT_LARGE = 32;
static constexpr uint32_t TEST_BUFFER_SIZE_SMALL = NUM_1000;
static constexpr uint32_t TEST_BUFFER_SIZE_LARGE = NUM_1000 * 10;
static constexpr uint32_t ARRAY_INDEX = 3;

class PluginLibJpegTest : public testing::Test {
public:
    PluginLibJpegTest() {}
    ~PluginLibJpegTest() {}
    void FinalizeEncodeTest(PixelFormat format);
};
void PluginLibJpegTest::FinalizeEncodeTest(PixelFormat format)
{
    uint32_t errorCode = 0;
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    ASSERT_NE(jpegEncoder, nullptr);
    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(NUM_1000);
    auto maxSize = NUM_1000;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    jpegEncoder->StartEncode(*(stream.get()), plOpts);
    Media::InitializationOptions opts;
    opts.pixelFormat = format;
    opts.size.width = OPTS_SIZE;
    opts.size.height = OPTS_SIZE;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);
    errorCode = jpegEncoder->AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = jpegEncoder->FinalizeEncode();
    ASSERT_EQ(errorCode, SUCCESS);
}

/**
 * @tc.name: PluginExternalCreateTest001
 * @tc.desc: PluginExternalCreate
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, PluginExternalCreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginExportTest: PluginExternalCreateTest001 start";
    string className = "";
    OHOS::MultimediaPlugin::PluginClassBase *result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    className = "#ImplClassType";
    result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "PluginExportTest: PluginExternalCreateTest001 end";
}

/**
 * @tc.name: getGrColorSpaceTest001
 * @tc.desc: getGrColorSpace
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, getGrColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IccProfileInfoTest: getGrColorSpaceTest001 start";
    ICCProfileInfo iccProfileInfo;
    iccProfileInfo.getGrColorSpace();
    ASSERT_EQ(iccProfileInfo.grColorSpace_.colorSpaceName, OHOS::ColorManager::ColorSpaceName::SRGB);
    GTEST_LOG_(INFO) << "IccProfileInfoTest: getGrColorSpaceTest001 end";
}

/**
 * @tc.name: PackingICCProfileTest001
 * @tc.desc: PackingICCProfile
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, PackingICCProfileTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IccProfileInfoTest: PackingICCProfileTest001 start";
    ICCProfileInfo iccProfileInfo;
    j_compress_ptr cinfo = nullptr;
    const SkImageInfo info;
    uint32_t result = iccProfileInfo.PackingICCProfile(cinfo, info);
    ASSERT_EQ(result, OHOS::Media::ERR_IMAGE_ENCODE_ICC_FAILED);
    GTEST_LOG_(INFO) << "IccProfileInfoTest: PackingICCProfileTest001 end";
}

/**
 * @tc.name: Jpeg_EncoderTest001
 * @tc.desc: GetEncodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, Jpeg_EncoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest001 start";
    auto Jpegencoder = std::make_shared<JpegEncoder>();
    PixelFormat format = PixelFormat::RGBA_F16;
    int32_t componentsNum = 1;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::RGBA_8888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::BGRA_8888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_BGRA);
    format = PixelFormat::ALPHA_8;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_GRAY);
    format = PixelFormat::RGB_565;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGB);
    format = PixelFormat::RGB_888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGB);
    format = PixelFormat::NV12;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_YUV420SP);
    format = PixelFormat::NV21;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_YUV420SP);
    format = PixelFormat::CMYK;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::UNKNOWN;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, 0);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest001 end";
}

/**
 * @tc.name: Jpeg_EncoderTest002
 * @tc.desc: AddImage
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, Jpeg_EncoderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest002 start";
    auto Jpegencoder = std::make_shared<JpegEncoder>();
    Media::PixelMap pixelmap;
    Jpegencoder->pixelMaps_.push_back(&pixelmap);
    uint32_t ret = Jpegencoder->AddImage(pixelmap);
    ASSERT_EQ(ret, ERR_IMAGE_ADD_PIXEL_MAP_FAILED);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest002 end";
}

/**
 * @tc.name: Jpeg_EncoderTest003
 * @tc.desc: FinalizeEncode
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, Jpeg_EncoderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest003 start";
    auto Jpegencoder = std::make_shared<JpegEncoder>();
    Media::PixelMap pixelmap;
    pixelmap.imageInfo_.pixelFormat = PixelFormat::BGRA_8888;
    pixelmap.data_ = nullptr;
    Jpegencoder->pixelMaps_.push_back(&pixelmap);
    uint32_t ret = Jpegencoder->FinalizeEncode();
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest003 end";
}

/**
 * @tc.name: Jpeg_EncoderTest004
 * @tc.desc: SetCommonConfig
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, Jpeg_EncoderTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest004 start";
    auto Jpegencoder = std::make_shared<JpegEncoder>();
    Media::PixelMap pixelmap;
    Jpegencoder->pixelMaps_.clear();
    uint32_t ret = Jpegencoder->SetCommonConfig();
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest004 end";
}

/**
 * @tc.name: PluginLibJpegTest_FinalizeEncodeTest001
 * @tc.desc: Verify that JpegEncoder encodes NV12 format image using FinalizeEncode.
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, FinalizeEncodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest001 start";
    FinalizeEncodeTest(PixelFormat::NV12);
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest001 end";
}

/**
 * @tc.name: PluginLibJpegTest_FinalizeEncodeTest002
 * @tc.desc: Verify that JpegEncoder encodes RGBA_F16 format image using FinalizeEncode.
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, FinalizeEncodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest002 start";
    FinalizeEncodeTest(PixelFormat::RGBA_F16);
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest002 end";
}

/**
 * @tc.name: PluginLibJpegTest_FinalizeEncodeTest003
 * @tc.desc: Verify that JpegEncoder encodes RGB_565 format image using FinalizeEncode.
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, FinalizeEncodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest003 start";
    FinalizeEncodeTest(PixelFormat::RGB_565);
    GTEST_LOG_(INFO) << "PluginLibJpegTest:PluginLibJpegTest_FinalizeEncodeTest003 end";
}

/**
 * @tc.name: PluginLibJpegTest_BranchCoverage001
 * @tc.desc: Test encoding NV21 format image
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, BranchCoverage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage001 start";
    uint32_t errorCode = 0;
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    ASSERT_NE(jpegEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(TEST_BUFFER_SIZE_SMALL);
    auto maxSize = TEST_BUFFER_SIZE_SMALL;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    jpegEncoder->StartEncode(*(stream.get()), plOpts);

    Media::InitializationOptions opts;
    opts.pixelFormat = PixelFormat::NV21;
    opts.size.width = TEST_IMAGE_WIDTH_SMALL;
    opts.size.height = TEST_IMAGE_HEIGHT_SMALL;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    errorCode = jpegEncoder->AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = jpegEncoder->FinalizeEncode();
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage001 end";
}

/**
 * @tc.name: PluginLibJpegTest_BranchCoverage002
 * @tc.desc: Test encoding when scanline processing exceeds image height
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, BranchCoverage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage002 start";
    uint32_t errorCode = 0;
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    ASSERT_NE(jpegEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(TEST_BUFFER_SIZE_LARGE);
    auto maxSize = TEST_BUFFER_SIZE_LARGE;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    jpegEncoder->StartEncode(*(stream.get()), plOpts);

    Media::InitializationOptions opts;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.size.width = TEST_IMAGE_WIDTH_SMALL;
    opts.size.height = TEST_IMAGE_HEIGHT_SMALL;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    errorCode = jpegEncoder->AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = jpegEncoder->FinalizeEncode();
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage002 end";
}

/**
 * @tc.name: PluginLibJpegTest_BranchCoverage003
 * @tc.desc: Test encoding NV12 image with non-block-aligned dimensions
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, BranchCoverage003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage003 start";
    uint32_t errorCode = 0;
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    ASSERT_NE(jpegEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(TEST_BUFFER_SIZE_SMALL);
    auto maxSize = TEST_BUFFER_SIZE_SMALL;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    jpegEncoder->StartEncode(*(stream.get()), plOpts);

    Media::InitializationOptions opts;
    opts.pixelFormat = PixelFormat::NV12;
    opts.size.width = TEST_IMAGE_WIDTH_UNALIGNED;
    opts.size.height = TEST_IMAGE_HEIGHT_UNALIGNED;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    errorCode = jpegEncoder->AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = jpegEncoder->FinalizeEncode();
    ASSERT_EQ(errorCode, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage003 end";
}

/**
 * @tc.name: PluginLibJpegTest_BranchCoverage004
 * @tc.desc: Test encoding with UV sampling row count exceeding threshold
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, BranchCoverage004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage004 start";
    uint32_t errorCode = 0;
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    ASSERT_NE(jpegEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(TEST_BUFFER_SIZE_LARGE);
    auto maxSize = TEST_BUFFER_SIZE_LARGE;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    jpegEncoder->StartEncode(*(stream.get()), plOpts);

    Media::InitializationOptions opts;
    opts.pixelFormat = PixelFormat::NV12;
    opts.size.width = TEST_IMAGE_WIDTH_LARGE;
    opts.size.height = TEST_IMAGE_HEIGHT_LARGE;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    errorCode = jpegEncoder->AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = jpegEncoder->FinalizeEncode();
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: BranchCoverage004 end";
}
} // namespace Multimedia
} // namespace OHOS