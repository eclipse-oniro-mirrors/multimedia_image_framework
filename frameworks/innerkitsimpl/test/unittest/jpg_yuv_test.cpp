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
#include <fcntl.h>
#include <string>
#include <chrono>
#include "buffer_packer_stream.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/";
static constexpr uint32_t MAXSIZE = 10000;
#define TREE_ORIGINAL_WIDTH 480
#define TREE_ORIGINAL_HEIGHT 360
#define ODDTREE_ORIGINAL_WIDTH 481
#define ODDTREE_ORIGINAL_HEIGHT 361
class JpgYuvTest : public testing::Test {
public:
    JpgYuvTest() {}
    ~JpgYuvTest() {}

    void TestDecodeToSize(int width, int height);
    uint64_t GetNowTimeMicroSeconds();
    void DoTimeTest(std::string jpgname);
    void DecodeToFormat(std::string srcjpg, PixelFormat outfmt, int width, int height);
    void DecodeToYuv(std::string srcjpg, PixelFormat outfmt, std::string outname, int& width, int& height);
};

void JpgYuvTest::TestDecodeToSize(int width, int height)
{
    const char* srcjpg[] = { "test-tree-444.jpg", "test-tree-422.jpg", "test-tree-420.jpg",
        "test-tree-400.jpg", "test-tree-440.jpg", "test-tree-411.jpg"};
    const char* outNamePart1[] = { "tree-444", "tree-422", "tree-420", "tree-400", "tree-440", "tree-411"};
    const char* outNamePart2[] = { "-nv12.yuv", "-nv21.yuv"};
    PixelFormat outfmt[] = { PixelFormat::NV12, PixelFormat::NV21};
    for (uint32_t k = 0; k < sizeof(srcjpg) / sizeof(char*); k++) {
        for (uint32_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
            std::string jpgpath = IMAGE_INPUT_JPG_PATH;
            jpgpath.append(srcjpg[k]);
            std::string outname;
            outname.append(outNamePart1[k]);
            outname.append(outNamePart2[j]);
            int outWidth = width;
            int outHeight = height;
            DecodeToYuv(jpgpath, outfmt[j], outname, outWidth, outHeight);
        }
    }
}

uint64_t JpgYuvTest::GetNowTimeMicroSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

void JpgYuvTest::DecodeToFormat(std::string srcjpg, PixelFormat outfmt, int width, int height)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
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

void JpgYuvTest::DoTimeTest(std::string jpgname)
{
    GTEST_LOG_(INFO) << "JpgYuvTest:DoTimeTest for: " << jpgname.c_str();
    const int testCount = 100;
    uint64_t startTick = GetNowTimeMicroSeconds();
    for (uint32_t k = 0; k < testCount; k++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append(jpgname);
        DecodeToFormat(jpgpath, PixelFormat::RGBA_8888, 0, 0);
    }
    uint64_t endTick = GetNowTimeMicroSeconds();
    uint64_t argbCost = endTick - startTick;
    GTEST_LOG_(INFO) << "JpgYuvTest:DoTimeTest time argbCost: " << argbCost;

    startTick = GetNowTimeMicroSeconds();
    for (uint32_t k = 0; k < testCount; k++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append(jpgname);
        DecodeToFormat(jpgpath, PixelFormat::NV12, 0, 0);
    }
    endTick = GetNowTimeMicroSeconds();
    uint64_t nv12Cost = endTick - startTick;
    GTEST_LOG_(INFO) << "JpgYuvTest:DoTimeTest time nv12Cost: " << nv12Cost;
}

void JpgYuvTest::DecodeToYuv(std::string srcjpg, PixelFormat outfmt, std::string outname, int& width, int& height)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << width << ", " << height << ")";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
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
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << width << ", " << height << ")";
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

HWTEST_F(JpgYuvTest, JpgYuvTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest001 start";
    TestDecodeToSize(TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest001 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest002 start";
    int testWidth = 510;
    int testHeight = 460;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest002 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest003 start";
    int testWidth = 380;
    int testHeight = 211;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest003 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest004 start";
    int testWidth = 100;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest004 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest005 start";
    int testWidth = 2000;
    int testHeight = 2000;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest005 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest006 start";
    PixelFormat outfmt[] = { PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = { "-nv12.yuv", "-nv21.yuv"};
    for (uint32_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test_hw.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        int outWidth = 0;
        int outHeight = 0;
        DecodeToYuv(jpgpath, outfmt[j], outname, outWidth, outHeight);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest006 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest007 start";
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append("test-tree-311.jpg");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(jpgpath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest007 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest008 start";
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append("test-bad.jpg");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(jpgpath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest008 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest009 start";
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append("test_null.jpg");

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(jpgpath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    decodeOpts.desiredSize.width = 0;
    decodeOpts.desiredSize.height = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest009 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest010 start";
    const char* srcjpg[] = { "test-treeodd-444.jpg", "test-treeodd-422.jpg", "test-treeodd-420.jpg",
        "test-treeodd-400.jpg", "test-treeodd-440.jpg", "test-treeodd-411.jpg"};
    const char* outNamePart1[] = { "treeodd-444", "treeodd-422", "treeodd-420",
        "treeodd-400", "treeodd-440", "treeodd-411"};
    const char* outNamePart2[] = { "-nv12.yuv", "-nv21.yuv"};
    PixelFormat outfmt[] = { PixelFormat::NV12, PixelFormat::NV21};
    for (uint32_t k = 0; k < sizeof(srcjpg) / sizeof(char*); k++) {
        for (uint32_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
            std::string jpgpath = IMAGE_INPUT_JPG_PATH;
            jpgpath.append(srcjpg[k]);
            std::string outname;
            outname.append(outNamePart1[k]);
            outname.append(outNamePart2[j]);
            int outWidth = ODDTREE_ORIGINAL_WIDTH;
            int outHeight = ODDTREE_ORIGINAL_HEIGHT;
            DecodeToYuv(jpgpath, outfmt[j], outname, outWidth, outHeight);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest010 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest011 start";
    int testWidth = 1;
    int testHeight = 1;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest011 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest012 start";
    int testWidth = 1;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest012 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest013 start";
    float scale = 0.875;
    int outwidth = TREE_ORIGINAL_WIDTH * scale;
    int outheight = TREE_ORIGINAL_HEIGHT * scale;
    TestDecodeToSize(outwidth, outheight);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest013 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest014 start";
    float scalFactor = 2.5;
    float minscale = 0.05;
    float step = 0.01;
    for (; scalFactor >= minscale; scalFactor -= step) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-tree-444.jpg");

        uint32_t errorCode = 0;
        SourceOptions opts;
        opts.formatHint = "image/jpeg";
        std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(jpgpath, opts, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(imageSource.get(), nullptr);
        DecodeOptions decodeOpts;
        decodeOpts.desiredPixelFormat = PixelFormat::NV12;
        decodeOpts.desiredSize.width = TREE_ORIGINAL_WIDTH * scalFactor;
        decodeOpts.desiredSize.height = TREE_ORIGINAL_HEIGHT * scalFactor;
        std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest014 end";
}

HWTEST_F(JpgYuvTest, JpgYuvTest015, TestSize.Level3)
{
    DoTimeTest("test-tree-444.jpg");
}

HWTEST_F(JpgYuvTest, JpgYuvTest016, TestSize.Level3)
{
    DoTimeTest("test-tree-440.jpg");
}

HWTEST_F(JpgYuvTest, JpgYuvTest017, TestSize.Level3)
{
    DoTimeTest("test-tree-422.jpg");
}

HWTEST_F(JpgYuvTest, JpgYuvTest018, TestSize.Level3)
{
    DoTimeTest("test-tree-420.jpg");
    DoTimeTest("test-treeodd-420.jpg");
}

HWTEST_F(JpgYuvTest, JpgYuvTest019, TestSize.Level3)
{
    DoTimeTest("test-tree-411.jpg");
}

HWTEST_F(JpgYuvTest, JpgYuvTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest020 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string hw_jpg_path = "/data/local/tmp/image/test_hw.jpg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(hw_jpg_path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::NV21;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgYuvTest020 end";
}
}
}