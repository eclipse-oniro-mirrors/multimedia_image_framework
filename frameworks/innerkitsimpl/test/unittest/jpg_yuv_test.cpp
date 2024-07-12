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
#include "color_space.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_yuv.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/";
static const std::string IMAGE_OUTPUT_JPG_PATH = "/data/local/tmp/";
static const std::string IMAGE_INPUT_YUV_PATH3 = "/data/local/tmp/image/P010.yuv";
static const std::string IMAGE_INPUT_YUV_PATH4 = "/data/local/tmp/image/RGBA1010102.rgba";
static constexpr uint32_t MAXSIZE = 10000;
#define TREE_ORIGINAL_WIDTH 480
#define TREE_ORIGINAL_HEIGHT 360
#define ODDTREE_ORIGINAL_WIDTH 481
#define ODDTREE_ORIGINAL_HEIGHT 361
#define P101TREE_ORIGINAL_WIDTH 1920
#define P101TREE_ORIGINAL_HEIGHT 1080
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

struct Coordinate {
    float xAxis = 0;
    float yAxis = 0;
};

class JpgYuvTest : public testing::Test {
public:
    JpgYuvTest() {}
    ~JpgYuvTest() {}

    void TestDecodeToSize(int width, int height);
    uint64_t GetNowTimeMicroSeconds();
    void DoTimeTest(std::string jpgname);
    bool ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum);
    void DecodeToFormat(std::string srcjpg, PixelFormat outfmt, int width, int height);
    void DecodeToYuv(std::string srcjpg, PixelFormat outfmt, std::string outname, int &width, int &height);
    void YuvWriteToFile(std::string outpath, ImageSize &imageSize, std::string outname, uint8_t *data, uint32_t &size);
    void YuvCrop(std::string srcjpg, PixelFormat outfmt, std::string outname, ImageSize &imageSize);
    void YuvP010Crop(PixelFormat outfmt, std::string outname, ImageSize &imageSize);
    void YuvRotate(std::string srcjpg, PixelFormat outfmt, std::string outname, ImageSize &imageSize, float degrees);
    void YuvP010Rotate(PixelFormat outfmt, std::string outname, ImageSize &imageSize, float degrees);
    void YuvWriteConvert(std::string srcjpg, PixelFormat outfmt, std::string outname, ImageSize &imageSize);
    void ScaleYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        ImageSize &imageSize, AntiAliasingOption option);
    void ScaleYuv420P010(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, AntiAliasingOption option);
    void ResizeYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname, ImageSize &imageSize);
    void ResizeYuv420P010(PixelFormat outfmt, std::string &outname, ImageSize &imageSize);
    void GetFlipAxis(size_t i, bool &xAxis, bool &yAxis);
    void FlipYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        ImageSize &imageSize, size_t i);
    void FlipYuv420P010(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, size_t i);
    void ApplyColorSpaceYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        ImageSize &imageSize, const OHOS::ColorManager::ColorSpace &grColorSpace);
    void TranslateYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        ImageSize &imageSize, Coordinate &coordinate);
    void TranslateYuv420P010(PixelFormat outfmt, std::string &outname,
        ImageSize &imageSize, Coordinate &coordinate);
    void ReadYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        Position &pos, ImageSize &imageSize);
    void WriteYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
        Position &pos, ImageSize &imageSize);
    void WritesYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname, ImageSize &imageSize);
    void RGBA1010102Crop(PixelFormat outfmt, std::string outname, ImageSize &imageSize);
    void RGBA1010102Rotate(PixelFormat outfmt, std::string outname, ImageSize &imageSize, float degrees);
    void RGBA1010102Scale(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, AntiAliasingOption option);
    void RGBA1010102Resize(PixelFormat outfmt, std::string &outname, ImageSize &imageSize);
    void RGBA1010102Flip(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, size_t size);
    void RGBA1010102Translate(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, Coordinate &coordinate);
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
    const int testCount = 100;
    for (uint32_t k = 0; k < testCount; k++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append(jpgname);
        DecodeToFormat(jpgpath, PixelFormat::RGBA_8888, 0, 0);
    }

    for (uint32_t k = 0; k < testCount; k++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append(jpgname);
        DecodeToFormat(jpgpath, PixelFormat::NV12, 0, 0);
    }
}

void JpgYuvTest::DecodeToYuv(std::string srcjpg, PixelFormat outfmt, std::string outname, int& width, int& height)
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

void JpgYuvTest::YuvWriteToFile(std::string outpath, ImageSize &imageSize, std::string outname,
    uint8_t *data, uint32_t &size)
{
    std::filesystem::path dir(outpath);
    std::filesystem::create_directory(dir);
    outpath.append(std::to_string(imageSize.width));
    outpath.append("-");
    outpath.append(std::to_string(imageSize.height));
    outpath.append("-");
    outpath.append(outname);
    FILE *outfile = fopen(outpath.c_str(), "wb");
    if (outfile) {
        fwrite(data, 1, size, outfile);
        int32_t fret = fclose(outfile);
        if (fret != 0) {
            ASSERT_TRUE(false);
        }
    }
}

void JpgYuvTest::YuvRotate(std::string srcjpg, PixelFormat outfmt, std::string outname,
    ImageSize &imageSize, float degrees)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->rotate(degrees);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetWidth() * pixelMap->GetHeight() + ((pixelMap->GetWidth() + 1) / NUM_2) *
        ((pixelMap->GetHeight() + 1) / NUM_2) * NUM_2;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "YuvRotate/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::YuvCrop(std::string srcjpg, PixelFormat outfmt, std::string outname, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    Rect rect = {0, 0, 100, 100};
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(pixelMap->crop(rect), SUCCESS);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetWidth() * pixelMap->GetHeight() + ((pixelMap->GetWidth() + 1) / NUM_2) *
        ((pixelMap->GetHeight() + 1) / NUM_2) * NUM_2;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "YuvCrop/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::YuvWriteConvert(std::string srcjpg, PixelFormat outfmt, std::string outname, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.editable = true;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    Rect region = {10, 10, 100, 100}; // The size of the crop
    size_t bufferSize = (region.width * region.height + ((region.width + 1) / NUM_2) *
        ((region.height + 1) / NUM_2) * NUM_2);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(bufferSize);
    int stride = static_cast<uint32_t>(region.width) * NUM_3 / NUM_2;
    ASSERT_EQ(pixelMap->ReadPixels(bufferSize, 0, stride, region, dst.get()), SUCCESS);

    Rect rect = {50, 50, 100, 100}; // The location and size of the write
    stride = static_cast<uint32_t>(rect.width) * NUM_3 / NUM_2;
    ASSERT_EQ(pixelMap->WritePixels(dst.get(), bufferSize, 0, stride, rect), SUCCESS);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetWidth() * pixelMap->GetHeight() + ((pixelMap->GetWidth() + 1) / NUM_2) *
        ((pixelMap->GetHeight() + 1) / NUM_2) * NUM_2;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "WriteConvert/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::ScaleYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, AntiAliasingOption option)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->scale(imageSize.dstWidth, imageSize.dstHeight, option);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "scale/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::ResizeYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->resize(imageSize.dstWidth, imageSize.dstHeight);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "resize/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::GetFlipAxis(size_t i, bool &xAxis, bool &yAxis)
{
    if (i & 1) {
        yAxis = false;
    } else {
        yAxis = true;
    }
    if ((i >> 1) & 1) {
        xAxis = false;
    } else {
        xAxis = true;
    }
}

void JpgYuvTest::FlipYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, size_t i)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    bool xAxis;
    bool yAxis;
    GetFlipAxis(i, xAxis, yAxis);
    pixelMap->flip(xAxis, yAxis);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "flip/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::TranslateYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, Coordinate &coordinate)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->translate(coordinate.xAxis, coordinate.yAxis);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "translate/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::ReadYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    Position &pos, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->ReadPixel(pos, imageSize.dst);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "read/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::WriteYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    Position &pos, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->WritePixel(pos, imageSize.color);

    pixelMap->ReadPixel(pos, imageSize.dst);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "write/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

void JpgYuvTest::WritesYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname, ImageSize &imageSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    uint32_t res = pixelMap->WritePixels(imageSize.color);
    ASSERT_EQ(res, 1);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "Writes";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

bool JpgYuvTest::ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum)
{
    FILE* const fileOrg = fopen(path.c_str(), "rb");
    if (fileOrg == NULL) {
        GTEST_LOG_(INFO) << "Cannot open" << path.c_str();
        return false;
    }
    if (srcNum == 0) {
        size_t bytesOrg = fread(chOrg, sizeof(uint8_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            GTEST_LOG_(INFO) << "Read fail";
            return false;
        }
    } else {
        size_t bytesOrg = fread(chOrg, sizeof(uint16_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            GTEST_LOG_(INFO) << "Read fail " << bytesOrg << " totalsize" << totalsize;
            return false;
        }
    }
    return true;
}

void JpgYuvTest::YuvP010Crop(PixelFormat outfmt, std::string outname, ImageSize &imageSize)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat =outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    Rect rect = {0, 0, 100, 100};
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(srcPixelMap->crop(rect), SUCCESS);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = (srcPixelMap->GetWidth() * srcPixelMap->GetHeight() + ((srcPixelMap->GetWidth() + 1) / NUM_2) *
        ((srcPixelMap->GetHeight() + 1) / NUM_2) * NUM_2) * NUM_2;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "YuvP010Crop/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::YuvP010Rotate(PixelFormat outfmt, std::string outname, ImageSize &imageSize, float degrees)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    srcPixelMap->rotate(degrees);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = (srcPixelMap->GetWidth() * srcPixelMap->GetHeight() + ((srcPixelMap->GetWidth() + 1) / NUM_2) *
        ((srcPixelMap->GetHeight() + 1) / NUM_2) * NUM_2) * NUM_2;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "YuvP010Rotate/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::ScaleYuv420P010(PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, AntiAliasingOption option)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    srcPixelMap->scale(imageSize.dstWidth, imageSize.dstHeight, option);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "P010scale/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::ResizeYuv420P010(PixelFormat outfmt, std::string &outname, ImageSize &imageSize)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    srcPixelMap->resize(imageSize.dstWidth, imageSize.dstHeight);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "P010resize/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::FlipYuv420P010(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, size_t i)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    bool xAxis;
    bool yAxis;
    GetFlipAxis(i, xAxis, yAxis);
    srcPixelMap->flip(xAxis, yAxis);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "P010flip/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::TranslateYuv420P010(PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, Coordinate &coordinate)
{
    GTEST_LOG_(INFO) << "jpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2);
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    srcPixelMap->translate(coordinate.xAxis, coordinate.yAxis);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "jpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "translate/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Crop(PixelFormat outfmt, std::string outname, ImageSize &imageSize)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat =outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    Rect rect = {0, 0, 100, 100};
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(srcPixelMap->crop(rect), SUCCESS);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBACrop/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Rotate(PixelFormat outfmt, std::string outname, ImageSize &imageSize, float degrees)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    srcPixelMap->rotate(degrees);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBARotate/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Scale(PixelFormat outfmt, std::string &outname, ImageSize &imageSize,
    AntiAliasingOption option)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    srcPixelMap->scale(imageSize.dstWidth, imageSize.dstHeight, option);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBAScale/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Resize(PixelFormat outfmt, std::string &outname, ImageSize &imageSize)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    srcPixelMap->resize(imageSize.dstWidth, imageSize.dstHeight);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBAResize/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Flip(PixelFormat outfmt, std::string &outname, ImageSize &imageSize, size_t i)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    bool xAxis;
    bool yAxis;
    GetFlipAxis(i, xAxis, yAxis);
    srcPixelMap->flip(xAxis, yAxis);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "JpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBAFlip/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

void JpgYuvTest::RGBA1010102Translate(PixelFormat outfmt, std::string &outname, ImageSize &imageSize,
    Coordinate &coordinate)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: request size(" << imageSize.width << ", " << imageSize.height << ")";
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = outfmt;
    opts.pixelFormat = outfmt;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    srcPixelMap->translate(coordinate.xAxis, coordinate.yAxis);

    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = srcPixelMap->GetWidth() * srcPixelMap->GetHeight() * NUM_4;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data8, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = srcPixelMap->GetWidth();
    imageSize.height = srcPixelMap->GetHeight();
    GTEST_LOG_(INFO) << "jpgYuvTest: ret size(" << imageSize.width << ", " << imageSize.height << ")";
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "translate/";
    YuvWriteToFile(outpath, imageSize, outname, data8, size);
}

HWTEST_F(JpgYuvTest, JpgYuvTest001, TestSize.Level3)
{
    TestDecodeToSize(TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT);
}

HWTEST_F(JpgYuvTest, JpgYuvTest002, TestSize.Level3)
{
    int testWidth = 510;
    int testHeight = 460;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest003, TestSize.Level3)
{
    int testWidth = 380;
    int testHeight = 211;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest004, TestSize.Level3)
{
    int testWidth = 100;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest005, TestSize.Level3)
{
    int testWidth = 2000;
    int testHeight = 2000;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest006, TestSize.Level3)
{
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
}

HWTEST_F(JpgYuvTest, JpgYuvTest007, TestSize.Level3)
{
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
    ASSERT_EQ(errorCode, SUCCESS);
}

HWTEST_F(JpgYuvTest, JpgYuvTest008, TestSize.Level3)
{
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
}

HWTEST_F(JpgYuvTest, JpgYuvTest009, TestSize.Level3)
{
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
}

HWTEST_F(JpgYuvTest, JpgYuvTest010, TestSize.Level3)
{
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
}

HWTEST_F(JpgYuvTest, JpgYuvTest011, TestSize.Level3)
{
    int testWidth = 1;
    int testHeight = 1;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest012, TestSize.Level3)
{
    int testWidth = 1;
    int testHeight = 100;
    TestDecodeToSize(testWidth, testHeight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest013, TestSize.Level3)
{
    float scale = 0.875;
    int outwidth = TREE_ORIGINAL_WIDTH * scale;
    int outheight = TREE_ORIGINAL_HEIGHT * scale;
    TestDecodeToSize(outwidth, outheight);
}

HWTEST_F(JpgYuvTest, JpgYuvTest014, TestSize.Level3)
{
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
}

HWTEST_F(JpgYuvTest, JpgYuvTest021, TestSize.Level3)
{
    const char *srcjpg[] = {"test-treeodd-444.jpg"};
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append(srcjpg[0]);
    float degrees[] = {90, 180, 270};
    int k = 0;
    const char *outFileName[] = {"90-nv12.yuv", "180-nv12.yuv", "270-nv12.yuv",
                                    "90-nv21.yuv", "180-nv21.yuv", "270-nv21.yuv"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(PixelFormat); ++i) {
        for (int j = 0; j < sizeof(degrees) / sizeof(float); ++j) {
            std::string outname;
            outname.append(outFileName[k++]);
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            YuvRotate(jpgpath, outfmt[i], outname, imageSize, degrees[j]);
        }
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest022, TestSize.Level3)
{
    const char *srcjpg[] = {"test-treeodd-444.jpg"};
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append(srcjpg[0]);
    const char *outFileName[] = {"-nv12.yuv", "-nv21.yuv"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(outfmt[0]); ++i) {
        std::string outname;
        outname.append(outFileName[i]);
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        YuvCrop(jpgpath, outfmt[i], outname, imageSize);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest023, TestSize.Level3)
{
    const char *srcjpg[] = {"test-treeodd-444.jpg"};
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append(srcjpg[0]);
    const char *outFileName[] = {"-nv12.yuv", "-nv21.yuv"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(outfmt[0]); ++i)
    {
        std::string outname;
        outname.append(outFileName[i]);
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        YuvWriteConvert(jpgpath, outfmt[i], outname, imageSize);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest024, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char *outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    AntiAliasingOption options[] = {AntiAliasingOption::NONE, AntiAliasingOption::LOW,
                                    AntiAliasingOption::MEDIUM, AntiAliasingOption::HIGH};
    std::filesystem::path dir("scale");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(options) / sizeof(AntiAliasingOption); i++) {
            std::string jpgpath = IMAGE_INPUT_JPG_PATH;
            jpgpath.append("test-treeodd-444.jpg");
            std::string outname;
            outname.append("testhw");
            switch (options[i]) {
                case AntiAliasingOption::NONE:
                    outname.append("-NONE-");
                    break;
                case AntiAliasingOption::LOW:
                    outname.append("-LOW-");
                    break;
                case AntiAliasingOption::MEDIUM:
                    outname.append("-MEDIUM-");
                    break;
                case AntiAliasingOption::HIGH:
                    outname.append("-HIGH-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
            ScaleYuv420(jpgpath, outfmt[j], outname, imageSize, options[i]);
        }
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest025, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char *outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    std::filesystem::path dir("resize");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-treeodd-444.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
        ResizeYuv420(jpgpath, outfmt[j], outname, imageSize);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest026, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char *outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    bool flips[4][2] = {{true, true}, {true, false}, {false, true}, {false, false}};
    std::filesystem::path dir("flip");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(flips) / (sizeof(bool) * 2); i++) {
            std::string jpgpath = IMAGE_INPUT_JPG_PATH;
            jpgpath.append("test-treeodd-444.jpg");
            std::string outname;
            outname.append("testhw");
            switch (i) {
                case 0:
                    outname.append("-xy-");
                    break;
                case 1:
                    outname.append("-x-");
                    break;
                case 2:
                    outname.append("-y-");
                    break;
                case 3:
                    outname.append("-no-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            FlipYuv420(jpgpath, outfmt[j], outname, imageSize, i);
        }
    }
}

#ifdef IMAGE_COLORSPACE_FLAG
// using namespace OHOS::ColorManager;
void JpgYuvTest::ApplyColorSpaceYuv420(std::string &srcjpg, PixelFormat outfmt, std::string &outname,
    ImageSize &imageSize, const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcjpg, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    pixelMap->ApplyColorSpace(grColorSpace);

    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(pixelMap->GetPixelFormat(), outfmt);
    ASSERT_EQ(ret, false);
    imageSize.width = pixelMap->GetWidth();
    imageSize.height = pixelMap->GetHeight();
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "applyCorlorSpace/";
    YuvWriteToFile(outpath, imageSize, outname, data, size);
}

HWTEST_F(JpgYuvTest, JpgYuvTest027, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char *outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    OHOS::ColorManager::ColorSpace colorSpaces[] = {
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB),
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::ADOBE_RGB),
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::DISPLAY_P3),
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::BT2020)};
    std::filesystem::path dir("applyCorlorSpace");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(colorSpaces) / sizeof(OHOS::ColorManager::ColorSpace); i++) {
            std::string jpgpath = IMAGE_INPUT_JPG_PATH;
            jpgpath.append("test-treeodd-444.jpg");
            std::string outname;
            outname.append("testhw");
            switch (colorSpaces[i].GetColorSpaceName()) {
                case OHOS::ColorManager::ColorSpaceName::SRGB:
                    outname.append("-SRGB-");
                    break;
                case OHOS::ColorManager::ColorSpaceName::ADOBE_RGB:
                    outname.append("-ADOBE_RGB-");
                    break;
                case OHOS::ColorManager::ColorSpaceName::DISPLAY_P3:
                    outname.append("-DISPLAY_P3-");
                    break;
                case OHOS::ColorManager::ColorSpaceName::BT2020:
                    outname.append("-BT2020-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            ApplyColorSpaceYuv420(jpgpath, outfmt[j], outname, imageSize, colorSpaces[i]);
        }
    }
}
#endif

HWTEST_F(JpgYuvTest, JpgYuvTest028, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    std::filesystem::path dir("translate");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-treeodd-444.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        Coordinate coordinate = {1, 1};
        TranslateYuv420(jpgpath, outfmt[j], outname, imageSize, coordinate);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest029, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    std::filesystem::path dir("read");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-treeodd-444.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        Position pos;
        pos.x = 1;
        pos.y = 1;
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        ReadYuv420(jpgpath, outfmt[j], outname, pos, imageSize);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest030, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    std::filesystem::path dir("write");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-treeodd-444.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        Position pos;
        pos.x = 1;
        pos.y = 1;
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        WriteYuv420(jpgpath, outfmt[j], outname, pos, imageSize);
    }
}

HWTEST_F(JpgYuvTest, JpgYuvTest031, TestSize.Level3)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    const char* outNamePart2[] = {"-nv12.yuv", "-nv21.yuv"};
    std::filesystem::path dir("writePixels");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string jpgpath = IMAGE_INPUT_JPG_PATH;
        jpgpath.append("test-treeodd-444.jpg");
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        WritesYuv420(jpgpath, outfmt[j], outname, imageSize);
    }
}

HWTEST_F(JpgYuvTest, P010JpgYuvTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest001 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    const char *outFileName[] = {"-ycbcr_p010.yuv", "-ycrcb_p010.yuv"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(outfmt[0]); ++i) {
        std::string outname;
        outname.append(outFileName[i]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        YuvP010Crop(outfmt[i], outname, imageSize);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest001 end";
}

HWTEST_F(JpgYuvTest, P010JpgYuvTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest002 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    float degrees[] = {90, 180, 270};
    int k = 0;
    const char *outFileName[] = {"90-ycbcr_p010.yuv", "180-ycbcr_p010.yuv", "270-ycbcr_p010.yuv",
                                    "90-ycrcb_p010.yuv", "180-ycrcb_p010.yuv", "270-ycrcb_p010.yuv"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(PixelFormat); ++i) {
        for (int j = 0; j < sizeof(degrees) / sizeof(float); ++j) {
            std::string outname;
            outname.append(outFileName[k++]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            YuvP010Rotate(outfmt[i], outname, imageSize, degrees[j]);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest002 end";
}
HWTEST_F(JpgYuvTest, P010JpgYuvTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest003 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    const char *outNamePart2[] = {"-ycbcr_p010.yuv", "-ycrcb_p010.yuv"};
    AntiAliasingOption options[] = {AntiAliasingOption::NONE, AntiAliasingOption::LOW,
                                    AntiAliasingOption::MEDIUM, AntiAliasingOption::HIGH};
    std::filesystem::path dir("scale");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(options) / sizeof(AntiAliasingOption); i++) {
            std::string outname;
            outname.append("p010");
            switch (options[i]) {
                case AntiAliasingOption::NONE:
                    outname.append("-NONE-");
                    break;
                case AntiAliasingOption::LOW:
                    outname.append("-LOW-");
                    break;
                case AntiAliasingOption::MEDIUM:
                    outname.append("-MEDIUM-");
                    break;
                case AntiAliasingOption::HIGH:
                    outname.append("-HIGH-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
            ScaleYuv420P010(outfmt[j], outname, imageSize, options[i]);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest003 end";
}

HWTEST_F(JpgYuvTest, P010JpgYuvTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest004 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    const char *outNamePart2[] = {"-ycbcr_p010.yuv", "-ycrcb_p010.yuv"};
    std::filesystem::path dir("resize");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string outname;
        outname.append("p010");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
        ResizeYuv420P010(outfmt[j], outname, imageSize);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest004 end";
}

HWTEST_F(JpgYuvTest, P010JpgYuvTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest005 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    const char *outNamePart2[] = {"-ycbcr_p010.yuv", "-ycrcb_p010.yuv"};
    bool flips[4][2] = {{true, true}, {true, false}, {false, true}, {false, false}};
    std::filesystem::path dir("flip");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(flips) / (sizeof(bool) * 2); i++) {
            std::string outname;
            outname.append("testhw");
            switch (i) {
                case 0:
                    outname.append("-xy-");
                    break;
                case 1:
                    outname.append("-x-");
                    break;
                case 2:
                    outname.append("-y-");
                    break;
                case 3:
                    outname.append("-no-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            FlipYuv420P010(outfmt[j], outname, imageSize, i);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest005 end";
}

HWTEST_F(JpgYuvTest, P010JpgYuvTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest006 start";
    PixelFormat outfmt[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    const char *outNamePart2[] = {"-ycbcr_p010.yuv", "-ycrcb_p010.yuv"};
    std::filesystem::path dir("translate");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        Coordinate coordinate = {1, 1};
        TranslateYuv420P010(outfmt[j], outname, imageSize, coordinate);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: P010JpgYuvTest006 end";
}

HWTEST_F(JpgYuvTest, JpgRgbaTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest001 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    const char *outFileName[] = {"-RGBA_1010102.rgba"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(outfmt[0]); ++i) {
        std::string outname;
        outname.append(outFileName[i]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        RGBA1010102Crop(outfmt[i], outname, imageSize);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest001 end";
}

HWTEST_F(JpgYuvTest, JpgRgbaTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest002 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    float degrees[] = {90, 180, 270};
    int k = 0;
    const char *outFileName[] = {"90-rgba_1010102.rgba", "180-rgba_1010102.rgba", "270-rgba_1010102.rgba"};
    for (int i = 0; i < sizeof(outfmt) / sizeof(PixelFormat); ++i) {
        for (int j = 0; j < sizeof(degrees) / sizeof(float); ++j) {
            std::string outname;
            outname.append(outFileName[k++]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            RGBA1010102Rotate(outfmt[i], outname, imageSize, degrees[j]);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest002 end";
}
HWTEST_F(JpgYuvTest, JpgRgbaTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest003 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    const char *outNamePart2[] = {"-rgba_1010102.rgba"};
    AntiAliasingOption options[] = {AntiAliasingOption::NONE, AntiAliasingOption::LOW,
                                    AntiAliasingOption::MEDIUM, AntiAliasingOption::HIGH};
    std::filesystem::path dir("scale");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(options) / sizeof(AntiAliasingOption); i++) {
            std::string outname;
            outname.append("p010");
            switch (options[i]) {
                case AntiAliasingOption::NONE:
                    outname.append("-NONE-");
                    break;
                case AntiAliasingOption::LOW:
                    outname.append("-LOW-");
                    break;
                case AntiAliasingOption::MEDIUM:
                    outname.append("-MEDIUM-");
                    break;
                case AntiAliasingOption::HIGH:
                    outname.append("-HIGH-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
            RGBA1010102Scale(outfmt[j], outname, imageSize, options[i]);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest003 end";
}

HWTEST_F(JpgYuvTest, JpgRgbaTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest004 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    const char *outNamePart2[] = {"-rgba_1010102.rgba"};
    std::filesystem::path dir("resize");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string outname;
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, NUM_2, NUM_2, 0, 0};
        RGBA1010102Resize(outfmt[j], outname, imageSize);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest004 end";
}

HWTEST_F(JpgYuvTest, JpgRgbaTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest005 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    const char *outNamePart2[] = {"-rgba_1010102.rgba"};
    bool flips[4][2] = {{true, true}, {true, false}, {false, true}, {false, false}};
    std::filesystem::path dir("flip");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(flips) / (sizeof(bool) * 2); i++) {
            std::string outname;
            outname.append("testhw");
            switch (i) {
                case 0:
                    outname.append("-xy-");
                    break;
                case 1:
                    outname.append("-x-");
                    break;
                case 2:
                    outname.append("-y-");
                    break;
                case 3:
                    outname.append("-no-");
                    break;
                default:
                    break;
            }
            outname.append(outNamePart2[j]);
            ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
            RGBA1010102Flip(outfmt[j], outname, imageSize, i);
        }
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest005 end";
}

HWTEST_F(JpgYuvTest, JpgRgbaTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest006 start";
    PixelFormat outfmt[] = {PixelFormat::RGBA_1010102};
    const char *outNamePart2[] = {"-rgba_1010102.rgba"};
    std::filesystem::path dir("translate");
    if (!std::filesystem::exists(dir)) {
        ASSERT_EQ(std::filesystem::create_directory(dir), true);
    }
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        std::string outname;
        outname.append("testhw");
        outname.append(outNamePart2[j]);
        ImageSize imageSize = {P101TREE_ORIGINAL_WIDTH, P101TREE_ORIGINAL_HEIGHT, 0, 0, 0, 0};
        Coordinate coordinate = {1, 1};
        RGBA1010102Translate(outfmt[j], outname, imageSize, coordinate);
    }
    GTEST_LOG_(INFO) << "JpgYuvTest: JpgRgbaTest006 end";
}
}
}