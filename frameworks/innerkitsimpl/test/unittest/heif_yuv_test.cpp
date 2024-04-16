/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <string>
#include <chrono>
#include "buffer_packer_stream.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_HEIF_PATH = "/data/local/tmp/image/";
static constexpr uint32_t MAXSIZE = 10000;
#define ORIGINAL_WIDTH 480
#define ORIGINAL_HEIGHT 360
class HeifYuvTest : public testing::Test {
public:
    HeifYuvTest() {}
    ~HeifYuvTest() {}

    void TestDecodeToSize(int width, int height);
    uint64_t GetNowTimeMicroSeconds();
    void DoTimeTest(std::string heifName);
    void DecodeToFormat(std::string srcHeif, PixelFormat outfmt, int width, int height);
    void DecodeToYuv(std::string srcHeif, PixelFormat outfmt, std::string outname, int& width, int& height);
};

void HeifYuvTest::TestDecodeToSize(int width, int height)
{
    const char* srcHeif[] = { "test.heic", "test_hw.heic", "test-10bit-1.heic", "test-10bit-2.heic"};
    const char* outNamePart1[] = { "test", "test_hw", "test-10bit-1", "test-10bit-2"};
    const char* outNamePart2[] = { "-nv12.yuv", "-nv21.yuv"};
    PixelFormat outfmt[] = { PixelFormat::NV12, PixelFormat::NV21};
    for (uint32_t k = 0; k < sizeof(srcHeif) / sizeof(char*); k++) {
        for (uint32_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
            std::string heifPath = IMAGE_INPUT_HEIF_PATH;
            heifPath.append(srcHeif[k]);
            std::string outname;
            outname.append(outNamePart1[k]);
            outname.append(outNamePart2[j]);
            int outWidth = width;
            int outHeight = height;
            DecodeToYuv(heifPath, outfmt[j], outname, outWidth, outHeight);
        }
    }
}

uint64_t HeifYuvTest::GetNowTimeMicroSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

void HeifYuvTest::DecodeToFormat(std::string srcHeif, PixelFormat outfmt, int width, int height)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcHeif, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = width;
    decodeOpts.desiredSize.height = height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
}

void HeifYuvTest::DoTimeTest(std::string heifName)
{
    GTEST_LOG_(INFO) << "HeifYuvTest:DoTimeTest for: " << heifName.c_str();
    const int testCount = 10;
    uint64_t startTick = GetNowTimeMicroSeconds();
    for (uint32_t k = 0; k < testCount; k++) {
        std::string heifPath = IMAGE_INPUT_HEIF_PATH;
        heifPath.append(heifName);
        DecodeToFormat(heifPath, PixelFormat::RGBA_8888, 0, 0);
    }
    uint64_t endTick = GetNowTimeMicroSeconds();
    uint64_t argbCost = endTick - startTick;
    GTEST_LOG_(INFO) << "HeifYuvTest:DoTimeTest time argbCost: " << argbCost;

    startTick = GetNowTimeMicroSeconds();
    for (uint32_t k = 0; k < testCount; k++) {
        std::string heifPath = IMAGE_INPUT_HEIF_PATH;
        heifPath.append(heifName);
        DecodeToFormat(heifPath, PixelFormat::NV12, 0, 0);
    }
    endTick = GetNowTimeMicroSeconds();
    uint64_t nv12Cost = endTick - startTick;
    GTEST_LOG_(INFO) << "HeifYuvTest:DoTimeTest time nv12Cost: " << nv12Cost;
}

void HeifYuvTest::DecodeToYuv(std::string srcHeif, PixelFormat outfmt, std::string outname, int& width, int& height)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: request size(" << width << ", " << height << ")";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcHeif, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = width;
    decodeOpts.desiredSize.height = height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    width = pixelMap->GetWidth();
    height = pixelMap->GetHeight();
    GTEST_LOG_(INFO) << "HeifYuvTest: ret size(" << width << ", " << height << ")";
    std::string outpath = "/tmp/";
    outpath.append(std::to_string(width));
    outpath.append("-");
    outpath.append(std::to_string(height));
    outpath.append("-");
    outpath.append(outname);
    FILE* outfile = fopen(outpath.c_str(), "wb");
    if (outfile) {
        fwrite(data, 1, size, outfile);
        int fret = fclose(outfile);
        if (fret != 0) {
            ASSERT_TRUE(false);
        }
    }
}

HWTEST_F(HeifYuvTest, HeifYuvTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest001 start";
    TestDecodeToSize(ORIGINAL_WIDTH, ORIGINAL_HEIGHT);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest001 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest002 start";
    int testWidth = 510;
    int testHeight = 460;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest002 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest003 start";
    int testWidth = 380;
    int testHeight = 211;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest003 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest004 start";
    int testWidth = 100;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest004 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest005 start";
    int testWidth = 2000;
    int testHeight = 2000;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest005 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest006 start";
    PixelFormat outfmt[] = { PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = { "-nv12.yuv", "-nv21.yuv"};
    for (uint32_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string heifPath = IMAGE_INPUT_HEIF_PATH;
        heifPath.append("test_hw.heic");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        int outWidth = 0;
        int outHeight = 0;
        DecodeToYuv(heifPath, outfmt[j], outname, outWidth, outHeight);
    }
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest006 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest007 start";
    std::string heifPath = IMAGE_INPUT_HEIF_PATH;
    heifPath.append("test.heic");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(heifPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest007 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest008 start";
    std::string heifPath = IMAGE_INPUT_HEIF_PATH;
    heifPath.append("test_bad.heic");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(heifPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest008 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest009 start";
    std::string heifPath = IMAGE_INPUT_HEIF_PATH;
    heifPath.append("test_null.jpg");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(heifPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest009 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest010 start";
    int testWidth = 1;
    int testHeight = 1;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest010 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest011 start";
    int testWidth = 1;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest011 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest012 start";
    float scale = 0.875;
    int outwidth = ORIGINAL_WIDTH * scale;
    int outheight = ORIGINAL_HEIGHT * scale;
    TestDecodeToSize(outwidth, outheight);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest012 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest013 start";
    float scalFactor = 2.5;
    float minscale = 0.05;
    float step = 0.01;
    for (; scalFactor >= minscale; scalFactor -= step) {
        std::string heifPath = IMAGE_INPUT_HEIF_PATH;
        heifPath.append("test.heic");

        uint32_t errorCode = 0;
        SourceOptions opts;
        opts.formatHint = "image/heif";
        std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(heifPath, opts, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(imageSource.get(), nullptr);
        DecodeOptions decodeOpts;
        decodeOpts.desiredPixelFormat = PixelFormat::NV12;
        decodeOpts.desiredSize.width = ORIGINAL_WIDTH * scalFactor;
        decodeOpts.desiredSize.height = ORIGINAL_HEIGHT * scalFactor;
        std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
    }
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest013 end";
}

HWTEST_F(HeifYuvTest, HeifYuvTest014, TestSize.Level3)
{
    DoTimeTest("test.heic");
}

HWTEST_F(HeifYuvTest, HeifYuvTest015, TestSize.Level3)
{
    DoTimeTest("test_hw.heic");
}

HWTEST_F(HeifYuvTest, HeifYuvTest016, TestSize.Level3)
{
    DoTimeTest("test-10bit-1.heic");
}

HWTEST_F(HeifYuvTest, HeifYuvTest017, TestSize.Level3)
{
    DoTimeTest("test-10bit-2.heic");
}

HWTEST_F(HeifYuvTest, HeifYuvTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest018 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string hw_heif_path = "/data/local/tmp/image/test_hw.heic";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(hw_heif_path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV21;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "HeifYuvTest: HeifYuvTest018 end";
}
}
}