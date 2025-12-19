/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "sk_ohoscodec.h"
#include "pixel_map.h"
#include <fstream>

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static const uint8_t PNG_DATA[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00,
    0x1F, 0x15, 0xC4, 0x89,
    0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54,
    0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
    0x0D, 0x0A, 0x2D, 0xB4,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82
};
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_hw1.jpg";
static const std::string IMAGE_WITH_BAD_PROFILE = "/data/local/tmp/image/color_wheel_with_bad_profile.png";
static const std::string IMAGE_WITH_PROFILE = "/data/local/tmp/image/three_gainmap_hdr.jpg";
static const std::string IMAGE_INPUT_GIF_PATH = "/data/local/tmp/image/test_broken.gif";
static const std::string IMAGE_INPUT_WEBP_PATH = "/data/local/tmp/image/test.webp";
static const std::string IMAGE_INPUT_BMP_PATH = "/data/local/tmp/image/test.bmp";
static const long BMP_TRUNCATED_MIN_BYTES = 512;
static const long JPEG_TRUNCATED_MIN_BYTES = 4096;
static const long JPEG_TRUNCATED_MAX_BYTES = 2048;
static const long JPEG_TRUNCATED_BYTES = 1024;
static const int PNG_WIDTH = 128;
static const int PNG_HEIGHT = 128;
static const int WEBP_WIDTH = 286;
static const int WEBP_HEIGHT = 221;
static const int SAMPLE_SIZE_ONE = 1;
static const int SAMPLE_SIZE_TWO = 2;
static const int SAMPLE_SIZE_TEN = 10;
static const int SIZE_BIGGER_THAN_PNG = 200;
static const int HALF_PNG_SIZE = 64;
static const int SMALLER_THAN_HALF_PNG_SIZE = 63;
static const int BIGGER_THAN_HALF_PNG_SIZE = 65;
static const int BMP_TRUNCATED_RETAIN_NUM = 7;
static const int TRUNCATED_RETAIN_DEN = 10;
static const int JPEG_TRUNCATED_RETAIN_DEN = 6;
static const int NATIVE_SAMPLE_SIZE = 2;
static const int INFO_SIZE = 1;
static const int HALF_JPEG_WIDTH = 640;
static const int HALF_JPEG_HEIGHT = 384;
static const int BIGGER_THAN_HALF_JPEG_WIDTH = 641;
static const int BIGGER_THAN_HALF_JPEG_HEIGHT = 385;
static const int SMALLER_THAN_HALF_JPEG_HEIGHT = 383;
static const size_t INVALID_REQUEST_ROW_BYTES = 100;
static const size_t INVALID_ROW_BYTES = 8;

static bool LoadImageFile(const std::string &path, std::vector<uint8_t> &buf)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return false;
    }
    std::streamsize size = file.tellg();
    if (size <= 0) {
        return false;
    }
    buf.resize(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buf.data()), size);
    return file.good();
}

static std::unique_ptr<SkOHOSCodec> CreateSkOHOSCodec(const std::string &path)
{
    auto stream = std::make_unique<SkFILEStream>(path.c_str());
    if (!stream) {
        return nullptr;
    }
    auto codec = SkCodec::MakeFromStream(std::move(stream));
    if (!codec) {
        return nullptr;
    }
    return SkOHOSCodec::MakeFromCodec(std::move(codec));
}

static std::unique_ptr<SkOHOSSampledCodec> CreateSkOHOSSampledCodec(const std::string &path)
{
    auto stream = std::make_unique<SkFILEStream>(path.c_str());
    if (!stream) {
        return nullptr;
    }
    auto codec = SkCodec::MakeFromStream(std::move(stream));
    if (!codec) {
        return nullptr;
    }
    return std::make_unique<SkOHOSSampledCodec>(codec.release());
}

class SkOhoscodecTest : public testing::Test {
public:
    SkOhoscodecTest() {}
    ~SkOhoscodecTest() {}
};

/**
 * @tc.name: MakeFromCodecTest001
 * @tc.desc: Test MakeFromCodec, return nullptr when codec is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, MakeFromCodecTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: MakeFromCodecTest001 start";
    auto ohosCodec = SkOHOSCodec::MakeFromCodec(nullptr);
    ASSERT_EQ(ohosCodec, nullptr);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: MakeFromCodecTest001 end";
}

/**
 * @tc.name: MakeFromDataTest001
 * @tc.desc: Test MakeFromData, make successfully when data is not nullptr, otherwise return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, MakeFromDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: MakeFromDataTest001 start";
    auto ohosCodec = SkOHOSCodec::MakeFromData(nullptr, nullptr);
    ASSERT_EQ(ohosCodec, nullptr);

    sk_sp<SkData> data = SkData::MakeWithoutCopy(PNG_DATA, sizeof(PNG_DATA));
    ohosCodec = SkOHOSCodec::MakeFromData(std::move(data), nullptr);
    ASSERT_NE(ohosCodec, nullptr);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: MakeFromDataTest001 end";
}

/**
 * @tc.name: computeOutputColorTypeTest001
 * @tc.desc: Test computeOutputColorType, input valid colorType when alphaType is kOpaque_SkAlphaType.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeOutputColorTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorTypeTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkColorType colorType = kARGB_4444_SkColorType;
    auto ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);

    colorType = kN32_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);

    colorType = kAlpha_8_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);

    colorType = kGray_8_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);

    colorType = kRGB_565_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kRGB_565_SkColorType);

    colorType = kRGBA_F16_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kRGBA_F16_SkColorType);

    colorType = kUnknown_SkColorType;
    ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorTypeTest001 end";
}

/**
 * @tc.name: computeOutputColorTypeTest002
 * @tc.desc: Test computeOutputColorType, when alphaType is not kOpaque_SkAlphaType.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeOutputColorTypeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorTypeTest002 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkColorType colorType = kRGB_565_SkColorType;
    auto ret = skOHOSCodec->computeOutputColorType(colorType);
    ASSERT_EQ(ret, kN32_SkColorType);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorTypeTest002 end";
}

/**
 * @tc.name: computeOutputAlphaTypeTest001
 * @tc.desc: Test computeOutputAlphaType, return kUnpremul_SkAlphaType when alphaType is not kOpaque_SkAlphaType.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeOutputAlphaTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputAlphaTypeTest001 start";
    auto kUSkOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(kUSkOHOSCodec, nullptr);

    auto kURet = kUSkOHOSCodec->computeOutputAlphaType(true);
    ASSERT_EQ(kURet, kUnpremul_SkAlphaType);

    auto kOSkOHOSCodec = CreateSkOHOSCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(kOSkOHOSCodec, nullptr);

    auto kORet = kOSkOHOSCodec->computeOutputAlphaType(true);
    ASSERT_EQ(kORet, kOpaque_SkAlphaType);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputAlphaTypeTest001 end";
}

/**
 * @tc.name: computeOutputColorSpaceTest001
 * @tc.desc: Test computeOutputColorSpace, return the color space according to the input image without profile.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeOutputColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorSpaceTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(skOHOSCodec, nullptr);

    auto ret = skOHOSCodec->computeOutputColorSpace(kUnknown_SkColorType, nullptr);
    ASSERT_EQ(ret, nullptr);

    auto colorSpace = SkColorSpace::MakeSRGB();
    auto retSpace = skOHOSCodec->computeOutputColorSpace(kRGBA_F16_SkColorType, nullptr);
    ASSERT_EQ(SkColorSpace::Equals(retSpace.get(), colorSpace.get()), true);

    retSpace = skOHOSCodec->computeOutputColorSpace(kRGBA_F16_SkColorType, colorSpace);
    ASSERT_EQ(SkColorSpace::Equals(retSpace.get(), colorSpace.get()), true);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorSpaceTest001 end";
}

/**
 * @tc.name: computeOutputColorSpaceTest002
 * @tc.desc: Test computeOutputColorSpace, return the color space according to the input image with profile.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeOutputColorSpaceTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorSpaceTest002 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    auto ret = skOHOSCodec->computeOutputColorSpace(kRGBA_F16_SkColorType, nullptr);
    auto encodedProfile = skOHOSCodec->getICCProfile();
    auto expectedColorSpace = SkColorSpace::Make(*encodedProfile);
    ASSERT_EQ(SkColorSpace::Equals(ret.get(), expectedColorSpace.get()), true);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeOutputColorSpaceTest002 end";
}

/**
 * @tc.name: computeSampleSizeTest001
 * @tc.desc: Test computeSampleSize, return 1 when desiredSize is same as image size.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeSampleSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize desiredSize = {PNG_WIDTH, PNG_HEIGHT};
    auto ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_ONE);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest001 end";
}

/**
 * @tc.name: computeSampleSizeTest002
 * @tc.desc: Test computeSampleSize, return 1 when desiredSize is bigger than image size.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeSampleSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest002 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize desiredSize = {SIZE_BIGGER_THAN_PNG, SIZE_BIGGER_THAN_PNG};
    auto ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_ONE);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest002 end";
}

/**
 * @tc.name: computeSampleSizeTest003
 * @tc.desc: Test computeSampleSize, when desiredSize is smaller than image size.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeSampleSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest003 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize desiredSize = {0, HALF_PNG_SIZE};
    auto ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_TWO);

    desiredSize = {BIGGER_THAN_HALF_PNG_SIZE, 0};
    ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_ONE);

    desiredSize = {HALF_PNG_SIZE, HALF_PNG_SIZE};
    ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_TWO);

    desiredSize = {SMALLER_THAN_HALF_PNG_SIZE, SMALLER_THAN_HALF_PNG_SIZE};
    ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_TWO);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest003 end";
}

/**
 * @tc.name: computeSampleSizeTest004
 * @tc.desc: Test computeSampleSize, return 1 when the image is in WEBP format.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, computeSampleSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest004 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_INPUT_WEBP_PATH);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize desiredSize = {HALF_PNG_SIZE, HALF_PNG_SIZE};
    auto ret = skOHOSCodec->computeSampleSize(&desiredSize);
    ASSERT_EQ(ret, SAMPLE_SIZE_ONE);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: computeSampleSizeTest004 end";
}

/**
 * @tc.name: getSampledDimensionsTest001
 * @tc.desc: Test getSampledDimensions, return {0, 0} when input 0.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, getSampledDimensionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSampledDimensionsTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    auto ret = skOHOSCodec->getSampledDimensions(0);
    ASSERT_EQ(ret.width(), 0);
    ASSERT_EQ(ret.height(), 0);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSampledDimensionsTest001 end";
}

/**
 * @tc.name: getSupportedSubsetTest001
 * @tc.desc: Test getSupportedSubset, return false when desiredSubset is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, getSupportedSubsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSupportedSubsetTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    auto ret = skOHOSCodec->getSupportedSubset(nullptr);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSupportedSubsetTest001 end";
}

/**
 * @tc.name: getSampledSubsetDimensionsTest001
 * @tc.desc: Test getSampledSubsetDimensions, return {0, 0} when input invalid sampleSize or subset.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, getSampledSubsetDimensionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSampledSubsetDimensionsTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkIRect subset = SkIRect::MakeXYWH(0, 0, 0, 0);
    auto ret = skOHOSCodec->getSampledSubsetDimensions(0, subset);
    ASSERT_EQ(ret.width(), 0);
    ASSERT_EQ(ret.height(), 0);

    ret = skOHOSCodec->getSampledSubsetDimensions(SAMPLE_SIZE_ONE, subset);
    ASSERT_EQ(ret.width(), 0);
    ASSERT_EQ(ret.height(), 0);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getSampledSubsetDimensionsTest001 end";
}

/**
 * @tc.name: getOHOSPixelsTest001
 * @tc.desc: Test getOHOSPixels, when input nullptr or invalid parameter.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, getOHOSPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getOHOSPixelsTest001 start";
    auto skOHOSCodec = CreateSkOHOSCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize skiSize = {HALF_PNG_SIZE, HALF_PNG_SIZE};
    SkColorInfo colorInfo;
    SkImageInfo requestInfo(skiSize, colorInfo);
    SkCodec::Result ret = skOHOSCodec->getOHOSPixels(requestInfo, nullptr, 0, nullptr);
    ASSERT_EQ(ret, SkCodec::kInvalidParameters);

    PixelMap pixelMap;
    ASSERT_NE(&pixelMap, nullptr);
    ret = skOHOSCodec->getOHOSPixels(requestInfo, &pixelMap, 0, nullptr);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);

    ret = skOHOSCodec->getOHOSPixels(requestInfo, &pixelMap, INVALID_REQUEST_ROW_BYTES, nullptr);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);

    SkOHOSCodec::OHOSOptions ohosOptions;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, 0, 0);
    ohosOptions.fSubset = &subset;
    ret = skOHOSCodec->getOHOSPixels(requestInfo, &pixelMap, INVALID_REQUEST_ROW_BYTES, &ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidParameters);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: getOHOSPixelsTest001 end";
}

/**
 * @tc.name: accountForNativeScalingTest001
 * @tc.desc: Test accountForNativeScaling, when the image is in JPEG format.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, accountForNativeScalingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: accountForNativeScalingTest001 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    int sampleSize = SAMPLE_SIZE_TEN;
    int nativeSampleSize = NATIVE_SAMPLE_SIZE;

    auto ret = skOHOSSampledCodec->accountForNativeScaling(&sampleSize, &nativeSampleSize);
    ASSERT_EQ(ret.width(), PNG_WIDTH);
    ASSERT_EQ(ret.height(), PNG_HEIGHT);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: accountForNativeScalingTest001 end";
}

/**
 * @tc.name: accountForNativeScalingTest002
 * @tc.desc: Test accountForNativeScaling, when the image is in WEBP format.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, accountForNativeScalingTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: accountForNativeScalingTest002 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_WEBP_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    int sampleSize = SAMPLE_SIZE_TEN;
    int nativeSampleSize = NATIVE_SAMPLE_SIZE;

    auto ret = skOHOSSampledCodec->accountForNativeScaling(&sampleSize, &nativeSampleSize);
    ASSERT_EQ(ret.width(), WEBP_WIDTH);
    ASSERT_EQ(ret.height(), WEBP_HEIGHT);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: accountForNativeScalingTest002 end";
}

/**
 * @tc.name: onGetOHOSPixelsTest001
 * @tc.desc: Test onGetOHOSPixels, when the generator cannot convert to match the request.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, onGetOHOSPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: onGetOHOSPixelsTest001 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkISize skiSize = {INFO_SIZE, INFO_SIZE};
    SkColorInfo colorInfo;
    SkImageInfo requestInfo(skiSize, colorInfo);
    PixelMap pixelMap;
    ASSERT_NE(&pixelMap, nullptr);
    SkOHOSCodec::OHOSOptions ohosOptions;

    auto ret = skOHOSSampledCodec->onGetOHOSPixels(requestInfo, &pixelMap, INVALID_ROW_BYTES, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);

    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ret = skOHOSSampledCodec->onGetOHOSPixels(requestInfo, &pixelMap, INVALID_ROW_BYTES, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: onGetOHOSPixelsTest001 end";
}

/**
 * @tc.name: onGetOHOSPixelsTest002
 * @tc.desc: Test onGetOHOSPixels, when input info size is valid.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, onGetOHOSPixelsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: onGetOHOSPixelsTest002 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkISize skiSize = {HALF_PNG_SIZE, HALF_PNG_SIZE};
    SkColorInfo colorInfo;
    SkImageInfo requestInfo(skiSize, colorInfo);
    PixelMap pixelMap;
    ASSERT_NE(&pixelMap, nullptr);
    SkOHOSCodec::OHOSOptions ohosOptions;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;

    auto ret = skOHOSSampledCodec->onGetOHOSPixels(requestInfo, &pixelMap, INVALID_ROW_BYTES, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: onGetOHOSPixelsTest002 end";
}

/**
 * @tc.name: sampledDecodeTest001
 * @tc.desc: Test sampledDecode, return kInvalidConversion when ohosOptions.fSubset is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest001 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkISize skiSize = {HALF_PNG_SIZE, HALF_PNG_SIZE};
    SkColorInfo colorInfo;
    SkImageInfo requestInfo(skiSize, colorInfo);
    PixelMap pixelMap;
    ASSERT_NE(&pixelMap, nullptr);
    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, &pixelMap, INVALID_ROW_BYTES, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidConversion);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest001 end";
}

/**
 * @tc.name: sampledDecodeTest002
 * @tc.desc: Test sampledDecode, return kSuccess when input valid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest002 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kSuccess);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest002 end";
}

/**
 * @tc.name: sampledDecodeTest003
 * @tc.desc: Test sampledDecode, return kUnimplemented when the image is in GIF format.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest003 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_GIF_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kUnimplemented);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest003 end";
}

/**
 * @tc.name: sampledDecodeTest004
 * @tc.desc: Test sampledDecode, return kInvalidScale when the width recheck fails after incremental decode failure.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest004 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(BIGGER_THAN_HALF_JPEG_WIDTH, BIGGER_THAN_HALF_JPEG_HEIGHT,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ohosOptions.fSubset = nullptr;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidScale);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest004 end";
}

/**
 * @tc.name: sampledDecodeTest005
 * @tc.desc: Test sampledDecode, return kInvalidScale when the width recheck fails after incremental decode success.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest005 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, BIGGER_THAN_HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidScale);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest005 end";
}

/**
 * @tc.name: sampledDecodeTest006
 * @tc.desc: Test sampledDecode, return kInvalidScale when the height recheck fails after incremental decode failure.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest006 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_JPEG_WIDTH, SMALLER_THAN_HALF_JPEG_HEIGHT,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ohosOptions.fSubset = nullptr;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidScale);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest006 end";
}

/**
 * @tc.name: sampledDecodeTest007
 * @tc.desc: Test sampledDecode, return kInvalidScale when the height recheck fails after incremental decode success.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest007 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_WITH_BAD_PROFILE);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, BIGGER_THAN_HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kInvalidScale);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest007 end";
}

/**
 * @tc.name: sampledDecodeTest008
 * @tc.desc: Test sampledDecode, return kSuccess when subset matches requested size and the image is in JPEG format.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest008 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(PNG_WIDTH, PNG_HEIGHT,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, PNG_WIDTH, PNG_HEIGHT);
    ohosOptions.fSubset = &subset;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kSuccess);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest008 end";
}

/**
 * @tc.name: sampledDecodeTest009
 * @tc.desc: Test sampledDecode, return kIncompleteInput when top‑down scanline skip succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest009 start";
    std::vector<uint8_t> buf;
    ASSERT_TRUE(LoadImageFile(IMAGE_INPUT_JPEG_PATH, buf));
    long fullSize = static_cast<long>(buf.size());
    long truncatedSize = std::max<long>(JPEG_TRUNCATED_BYTES, fullSize / TRUNCATED_RETAIN_DEN);
    sk_sp<SkData> truncated = SkData::MakeWithoutCopy(buf.data(), truncatedSize);
    auto codec = SkCodec::MakeFromData(truncated);
    ASSERT_NE(codec, nullptr);
    auto skOHOSSampledCodec = std::make_unique<SkOHOSSampledCodec>(codec.release());
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_JPEG_WIDTH, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ohosOptions.fSubset = nullptr;

    auto ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kIncompleteInput);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest009 end";
}

/**
 * @tc.name: sampledDecodeTest010
 * @tc.desc: Test sampledDecode, return kIncompleteInput with more aggressively truncated JPEG.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest010 start";
    std::vector<uint8_t> buf;
    ASSERT_TRUE(LoadImageFile(IMAGE_INPUT_JPEG_PATH, buf));
    long fullSize = static_cast<long>(buf.size());
    long truncatedSize = std::min<long>(JPEG_TRUNCATED_MAX_BYTES, fullSize);
    sk_sp<SkData> truncated = SkData::MakeWithoutCopy(buf.data(), truncatedSize);
    auto codec = SkCodec::MakeFromData(truncated);
    ASSERT_NE(codec, nullptr);
    auto skOHOSSampledCodec = std::make_unique<SkOHOSSampledCodec>(codec.release());
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_JPEG_WIDTH, HALF_JPEG_HEIGHT,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ohosOptions.fSubset = nullptr;

    SkCodec::Result ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kIncompleteInput);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest010 end";
}

/**
 * @tc.name: sampledDecodeTest011
 * @tc.desc: Test sampledDecode, return kIncompleteInput when truncating JPEG with skip + sampling proceeds.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest011 start";
    std::vector<uint8_t> buf;
    ASSERT_TRUE(LoadImageFile(IMAGE_INPUT_JPEG_PATH, buf));
    long fullSize = static_cast<long>(buf.size());
    long truncatedSize = std::max<long>(JPEG_TRUNCATED_MIN_BYTES, fullSize / JPEG_TRUNCATED_RETAIN_DEN);
    sk_sp<SkData> truncated = SkData::MakeWithoutCopy(buf.data(), truncatedSize);
    auto codec = SkCodec::MakeFromData(truncated);
    ASSERT_NE(codec, nullptr);
    auto skOHOSSampledCodec = std::make_unique<SkOHOSSampledCodec>(codec.release());
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_JPEG_WIDTH, PNG_HEIGHT,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    ohosOptions.fSubset = nullptr;

    SkCodec::Result ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kIncompleteInput);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest011 end";
}

/**
 * @tc.name: sampledDecodeTest012
 * @tc.desc: Test sampledDecode, return kSuccess when input a bottom‑up BMP with all necessary scanlines decoded fully.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest012 start";
    auto skOHOSSampledCodec = CreateSkOHOSSampledCodec(IMAGE_INPUT_BMP_PATH);
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    SkCodec::Result ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kSuccess);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest012 end";
}

/**
 * @tc.name: sampledDecodeTest013
 * @tc.desc: Test sampledDecode, return kIncompleteInput when input a bottom‑up BMP with scanline loop breaks early.
 * @tc.type: FUNC
 */
HWTEST_F(SkOhoscodecTest, sampledDecodeTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest013 start";
    std::vector<uint8_t> buf;
    ASSERT_TRUE(LoadImageFile(IMAGE_INPUT_BMP_PATH, buf));
    long fullSize = static_cast<long>(buf.size());
    long truncatedSize = std::max<long>(BMP_TRUNCATED_MIN_BYTES,
        (fullSize * BMP_TRUNCATED_RETAIN_NUM) / TRUNCATED_RETAIN_DEN);
    sk_sp<SkData> truncated = SkData::MakeWithoutCopy(buf.data(), truncatedSize);
    auto codec = SkCodec::MakeFromData(truncated);
    ASSERT_NE(codec, nullptr);
    auto skOHOSSampledCodec = std::make_unique<SkOHOSSampledCodec>(codec.release());
    ASSERT_NE(skOHOSSampledCodec, nullptr);

    SkImageInfo requestInfo = SkImageInfo::Make(HALF_PNG_SIZE, HALF_PNG_SIZE,
        kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    size_t rowBytes = requestInfo.minRowBytes();
    std::vector<uint8_t> pixels(rowBytes * requestInfo.height());

    SkOHOSCodec::OHOSOptions ohosOptions;
    ohosOptions.fSampleSize = SAMPLE_SIZE_TWO;
    SkIRect subset = SkIRect::MakeXYWH(0, 0, HALF_PNG_SIZE, HALF_PNG_SIZE);
    ohosOptions.fSubset = &subset;

    SkCodec::Result ret = skOHOSSampledCodec->sampledDecode(requestInfo, pixels.data(), rowBytes, ohosOptions);
    ASSERT_EQ(ret, SkCodec::kIncompleteInput);
    GTEST_LOG_(INFO) << "SkOhoscodecTest: sampledDecodeTest013 end";
}
} // namespace ImagePlugin
} // namespace OHOS
