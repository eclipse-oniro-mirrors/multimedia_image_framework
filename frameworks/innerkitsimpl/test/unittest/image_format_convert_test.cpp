/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define private public
#define protected public
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <iostream>
#include <unistd.h>

#include "buffer_packer_stream.h"
#include "hilog/log.h"
#include "hilog/log_cpp.h"
#include "image_format_convert.h"
#include "image_format_convert_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::mt;
using namespace testing::ext;
namespace OHOS {
namespace Media {
constexpr int32_t TREE_ORIGINAL_WIDTH = 800;
constexpr int32_t TREE_ORIGINAL_HEIGHT = 500;
constexpr int32_t ODDTREE_ORIGINAL_WIDTH = 951;
constexpr int32_t ODDTREE_ORIGINAL_HEIGHT = 595;
constexpr int32_t P010_ORIGINAL_WIDTH = 1920;
constexpr int32_t P010_ORIGINAL_HEIGHT = 1080;
constexpr uint32_t BYTES_PER_PIXEL_RGB565 = 2;
constexpr uint32_t BYTES_PER_PIXEL_RGB = 3;
constexpr uint32_t BYTES_PER_PIXEL_RGBA = 4;
constexpr uint32_t BYTES_PER_PIXEL_BGRA = 4;
constexpr uint32_t EVEN_ODD_DIVISOR = 2;
constexpr uint32_t TWO_SLICES = 2;
constexpr int32_t NUM_2 = 2;
constexpr int32_t NUM_4 = 4;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

static const std::string IMAGE_INPUT_JPG_PATH1 = "/data/local/tmp/image/800-500.jpg";
static const std::string IMAGE_INPUT_JPG_PATH2 = "/data/local/tmp/image/951-595.jpg";
static const std::string IMAGE_OUTPUT_JPG_PATH = "/data/local/tmp/";
static const std::string IMAGE_INPUT_YUV_PATH3 = "/data/local/tmp/image/P010.yuv";
static const std::string IMAGE_INPUT_RGBA_PATH4 = "/data/local/tmp/image/RGBA1010102.rgba";
class ImageFormatConvertTest : public testing::Test {
public:
    ImageFormatConvertTest() {}
    ~ImageFormatConvertTest() {}
    static ConvertFunction TestGetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat);
    void WriteToFile(const std::string &outpath, Size &imageSize, const std::string &outname, const uint8_t *data,
        const uint32_t size);
    bool ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum);
    void RgbConvertToYuv(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize);
    void RgbConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize);
    void Rgba1010102ConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
        uint32_t destBuffersize);
    void YuvConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize, uint32_t destBuffersize);
    void YuvP010ConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize, uint32_t destBuffersize);
    void RgbConvertToYuvByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
        PixelFormat &destFormat, Size &srcSize);
    void RgbConvertToYuvP010ByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
        PixelFormat &destFormat, Size &srcSize);
    void *GetOrignData(PixelFormat srcFormat, Size imageSize);
    void PixelMapFormatConvert(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
        uint32_t destBuffersize);
    void PixelMap10bitConvert(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
        uint32_t destBuffersize);
};

ConvertFunction ImageFormatConvertTest::TestGetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat)
{
    return ImageFormatConvert::GetConvertFuncByFormat(srcFormat, destFormat);
}

static const string GetNamedPixelFormat(const PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case PixelFormat::UNKNOWN:
            return "UNKNOWN";
        case PixelFormat::RGB_565:
            return "RGB_565";
        case PixelFormat::RGB_888:
            return "RGB_888";
        case PixelFormat::NV21:
            return "NV21";
        case PixelFormat::NV12:
            return "NV12";
        case PixelFormat::RGBA_8888:
            return "RGBA_8888";
        case PixelFormat::BGRA_8888:
            return "BGRA_8888";
        case PixelFormat::RGBA_F16:
            return "RGBA_F16";
        case PixelFormat::RGBA_1010102:
            return "RGBA_1010102";
        case PixelFormat::YCBCR_P010:
            return "YCBCR_P010";
        case PixelFormat::YCRCB_P010:
            return "YCRCB_P010";
        default:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

void ImageFormatConvertTest::WriteToFile(const std::string &outpath, Size &imageSize, const std::string &outname,
    const uint8_t *data, const uint32_t size)
{
    std::filesystem::path dir(outpath);
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directory(dir);
    }

    std::string filepath =
        outpath + "/" + std::to_string(imageSize.width) + "-" + std::to_string(imageSize.height) + "-" + outname;

    std::ofstream outfile(filepath, std::ios::out | std::ios::binary);
    if (outfile.is_open()) {
        outfile.write(reinterpret_cast<const char *>(data), size);
        outfile.close();
    } else {
        ASSERT_TRUE(false);
    }
}

void ImageFormatConvertTest::RgbConvertToYuv(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    auto yuvDataInfoTemp = srcPixelMap->yuvDataInfo_;
    auto imageInfoTemp = srcPixelMap->imageInfo_;
    srcPixelMap->yuvDataInfo_.yWidth = 0;
    srcPixelMap->imageInfo_.size.width = 0;
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_NE(ret, SUCCESS);

    srcPixelMap->yuvDataInfo_.yWidth = 1;
    srcPixelMap->yuvDataInfo_.yHeight = 0;
    ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_NE(ret, SUCCESS);

    srcPixelMap->yuvDataInfo_.yHeight= PIXEL_MAP_MAX_RAM_SIZE;
    srcPixelMap->yuvDataInfo_.yWidth = 2; // 2:Special case, anomalous branching
    ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_NE(ret, SUCCESS);

    srcPixelMap->yuvDataInfo_ = yuvDataInfoTemp;
    srcPixelMap->imageInfo_ = imageInfoTemp;
    ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    uint8_t *data = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data, nullptr);

    ImageInfo destImageInfo;
    srcPixelMap->GetImageInfo(destImageInfo);
    uint32_t buffersize = static_cast<size_t>(destImageInfo.size.width * destImageInfo.size.height +
        ((destImageInfo.size.width + 1) / TWO_SLICES) * ((destImageInfo.size.height + 1) / TWO_SLICES) * TWO_SLICES);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);

    Size size = destImageInfo.size;
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBToYUV/";
    WriteToFile(outpath, size, outname, data, buffersize);
}

void ImageFormatConvertTest::YuvConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    uint8_t *data = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data, nullptr);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);

    Size size;
    size.width = srcPixelMap->GetWidth();
    size.height = srcPixelMap->GetHeight();
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".rgb";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "YUVToRGB/";
    WriteToFile(outpath, size, outname, data, destBuffersize);
}

bool ImageFormatConvertTest::ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum)
{
    FILE* const fileOrg = fopen(path.c_str(), "rb");
    if (fileOrg == NULL) {
        GTEST_LOG_(INFO) << "Cannot open" << path.c_str();
        GTEST_LOG_(INFO) << "fopen";
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

void ImageFormatConvertTest::YuvP010ConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    ImageSize imageSize;
    imageSize.width = srcSize.width;
    imageSize.height = srcSize.height;
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / NUM_2) * ((imageSize.height + 1) / NUM_2);
    const size_t totalSize = (ySize + NUM_2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    ASSERT_EQ(result, true);

    const uint32_t dataLength = totalSize * NUM_2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = srcFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);

    Size size;
    size.width = srcPixelMap->GetWidth();
    size.height = srcPixelMap->GetHeight();

    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "P010ToRgba1010102/";
    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data8, nullptr);
    WriteToFile(outpath, size, outname, data8, destBuffersize);
}

void ImageFormatConvertTest::Rgba1010102ConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    ImageSize imageSize;
    imageSize.width = srcSize.width;
    imageSize.height = srcSize.height;
    int32_t ySize = imageSize.width * imageSize.height;
    const size_t totalSize = ySize * NUM_4;
    uint8_t* const chOrg = new uint8_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_RGBA_PATH4, totalSize, 0);
    ASSERT_EQ(result, true);

    const uint32_t dataLength = totalSize;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = srcFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);
    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);

    Size size;
    size.width = srcPixelMap->GetWidth();
    size.height = srcPixelMap->GetHeight();

    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "Rgba1010102ToP010/";
    uint8_t *data8 = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data8, nullptr);
    WriteToFile(outpath, size, outname, data8, destBuffersize);
}

void ImageFormatConvertTest::RgbConvertToYuvByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
    PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    auto rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = tempFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;
    srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    auto yuvDataInfoTemp = srcPixelMap->yuvDataInfo_;
    auto imageInfoTemp = srcPixelMap->imageInfo_;
    srcPixelMap->yuvDataInfo_.yWidth = 0;
    srcPixelMap->imageInfo_.size.width = 0;
    uint32_t tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    ASSERT_NE(tmpRet, SUCCESS);

    srcPixelMap->yuvDataInfo_.yWidth = 1;
    srcPixelMap->yuvDataInfo_.yHeight = 0;
    tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    ASSERT_NE(tmpRet, SUCCESS);

    srcPixelMap->yuvDataInfo_.yHeight= PIXEL_MAP_MAX_RAM_SIZE;
    srcPixelMap->yuvDataInfo_.yWidth = 2; // 2:Special case, anomalous branching
    tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    ASSERT_NE(tmpRet, SUCCESS);

    srcPixelMap->yuvDataInfo_ = yuvDataInfoTemp;
    srcPixelMap->imageInfo_ = imageInfoTemp;
    tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    ASSERT_EQ(tmpRet, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), srcFormat);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);
    uint8_t *data = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data, nullptr);

    ImageInfo destImageInfo;
    srcPixelMap->GetImageInfo(destImageInfo);
    uint32_t buffersize = static_cast<size_t>(destImageInfo.size.width * destImageInfo.size.height +
        ((destImageInfo.size.width + 1) / TWO_SLICES) * ((destImageInfo.size.height + 1) / TWO_SLICES) * TWO_SLICES);

    Size size = destImageInfo.size;
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBToYUV/";
    WriteToFile(outpath, size, outname, data, buffersize);
}

void ImageFormatConvertTest::RgbConvertToYuvP010ByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
    PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    auto rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = tempFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;
    srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    ASSERT_EQ(tmpRet, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), srcFormat);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);
    uint8_t *data = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data, nullptr);

    ImageInfo destImageInfo;
    srcPixelMap->GetImageInfo(destImageInfo);
    uint32_t buffersize = static_cast<size_t>((destImageInfo.size.width * destImageInfo.size.height +
        ((destImageInfo.size.width + 1) / TWO_SLICES) * ((destImageInfo.size.height + 1) / TWO_SLICES)
        * TWO_SLICES) * TWO_SLICES);
    Size size = destImageInfo.size;
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + "P010.yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBToYUVP010/";
    WriteToFile(outpath, size, outname, data, buffersize);
}

void ImageFormatConvertTest::RgbConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    ASSERT_EQ(ret, SUCCESS);
    uint8_t *data = const_cast<uint8_t *>(srcPixelMap->GetPixels());
    ASSERT_NE(data, nullptr);

    ImageInfo destImageInfo;
    srcPixelMap->GetImageInfo(destImageInfo);
    uint32_t buffersize = static_cast<size_t>((destImageInfo.size.width * destImageInfo.size.height +
        ((destImageInfo.size.width + 1) / TWO_SLICES) * ((destImageInfo.size.height + 1) / TWO_SLICES)
        * TWO_SLICES) * TWO_SLICES);
    ASSERT_EQ(srcPixelMap->GetPixelFormat(), destFormat);

    Size size = destImageInfo.size;
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + "P010.yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "RGBToYUVP010/";
    WriteToFile(outpath, size, outname, data, buffersize);
}

void *ImageFormatConvertTest::GetOrignData(PixelFormat srcFormat, Size imageSize)
{
    if (srcFormat == PixelFormat::YCBCR_P010 ||
        srcFormat == PixelFormat::YCRCB_P010) {
        int32_t ySize = imageSize.width * imageSize.height;
        int32_t uvSize = ((imageSize.width + 1) / NUM_2) * ((imageSize.height + 1) / NUM_2);
        const size_t totalSize = (ySize + NUM_2 * uvSize);
        uint16_t* const chOrg = new uint16_t[totalSize];
        bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
        return result == true ? chOrg : nullptr;
    } else if (srcFormat == PixelFormat::RGBA_1010102) {
        int32_t ySize = imageSize.width * imageSize.height;
        const size_t totalSize = ySize * NUM_4;
        uint8_t* const chOrg = new uint8_t[totalSize];
        bool result = ReadFile(chOrg, IMAGE_INPUT_RGBA_PATH4, totalSize, 0);
        return result == true ? chOrg : nullptr;
    } else {
        return nullptr;
    }
}

void ImageFormatConvertTest::PixelMapFormatConvert(PixelFormat &srcFormat, PixelFormat &destFormat,
    Size &srcSize, uint32_t destBuffersize)
{
    uint32_t errorCode = 0;
    SourceOptions srcopts;
    srcopts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, srcopts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t *data = (uint32_t *)srcPixelMap->GetPixels();
    const uint32_t dataLength = srcPixelMap->GetByteCount();
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = destFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = srcSize.width;
    opts.size.height = srcSize.height;

    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    Size size;
    size.width = pixelMap->GetWidth();
    size.height = pixelMap->GetHeight();
    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "PixelConvert/";
    uint8_t *data8 = const_cast<uint8_t *>(pixelMap->GetPixels());
    ASSERT_NE(data8, nullptr);
    WriteToFile(outpath, size, outname, data8, destBuffersize);
}

void ImageFormatConvertTest::PixelMap10bitConvert(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    uint32_t *data = (uint32_t *)GetOrignData(srcFormat, srcSize);
    const uint32_t dataLength = ImageFormatConvert::GetBufferSizeByFormat(srcFormat, srcSize);
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = destFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = srcSize.width;
    opts.size.height = srcSize.height;

    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);
    Size size;
    size.width = pixelMap->GetWidth();
    size.height = pixelMap->GetHeight();

    std::string formatName = GetNamedPixelFormat(srcFormat) + "To" + GetNamedPixelFormat(destFormat) + ".yuv";
    std::string outname = size.width % EVEN_ODD_DIVISOR == 0 ? "Tree_" + formatName : "Odd_" + formatName;
    std::string outpath = IMAGE_OUTPUT_JPG_PATH + "PixelConvert/";
    uint8_t *data8 = const_cast<uint8_t *>(pixelMap->GetPixels());
    ASSERT_NE(data8, nullptr);
    WriteToFile(outpath, size, outname, data8, destBuffersize);
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV21_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV21_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV12_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV12_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV21_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV21_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV12_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV12_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV21_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV21_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV12_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV12_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV12_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12_001: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV12_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12_002: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV21_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21_001: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV21_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21_002: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV21_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21_001: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21_001: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV21_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21_002: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV12_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12_001: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV12_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12_002: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGB_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_001: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_001: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGB_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_002: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12_002: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGBA_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGBA_001: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGBA_001: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGBA_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGBA_002: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGBA_002: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToBGRA_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToBGRA_001: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToBGRA_001: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToBGRA_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToBGRA_002: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToBGRA_002: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGB565_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGB565_001: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGB565_001: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGB565_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGB565_002: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV21ToRGB565_002: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToNV12_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12_001 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToNV12_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12_002 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToNV21_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToNV21_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGB565_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB565_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB565_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGB565_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB565_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB565_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGBAF16_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToRGBAF16_Test_001 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToRGBAF16_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGBAF16_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToRGBAF16_002 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToRGBAF16_002 end";
}
HWTEST_F(ImageFormatConvertTest, NV12ToRGBAF16_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBAF16_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBAF16_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGBAF16_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBAF16_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBAF16_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGBA_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBA_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBA_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGBA_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBA_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGBA_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToBGRA_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToBGRA_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToBGRA_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToBGRA_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToBGRA_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToBGRA_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGB_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGB_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToRGB_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToNV12P010_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12P010_001 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12P010_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToNV12P010_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12P010_002 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV12P010_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToNV12_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV12_003 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV12_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToNV12P010_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV12P010_001 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES)  * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV12P010_001 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToNV12P010_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV12P010_002 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV12P010_002 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToNV21_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV21_003 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV21_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToNV21P010_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV21P010_003 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV21P010_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToRGB565_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToRGB565_003: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToRGB565_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToRGBA_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToRGBA_003: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToRGBA_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToBGRA_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToBGRA_003: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.NV12P010ToBGRA_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToRGB_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGB_003 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGB_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToRGBAF16_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGBAF16_003 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGBAF16_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToNV21P010_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV21P010_003 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21ToNV21P010_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToNV12_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToNV12_003 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToNV12_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToNV21P010_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21P010_003 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12ToNV21P010_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12ToRGBA1010102_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: end";
}

HWTEST_F(ImageFormatConvertTest, NV21ToRGBA1010102_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToNV21_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToNV21_003 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToNV21_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToNV12P010_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV12P010_003 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToNV12P010_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToRGB565_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGB565_003: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGB565_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToRGBA_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBA_003: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBA_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToBGRA_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToBGRA_003: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToBGRA_003: end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToRGB_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGB_003 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGB_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToRGBAF16_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBAF16_003 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBAF16_003 end";
}

HWTEST_F(ImageFormatConvertTest, NV12P010ToRGBA_1010102_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGBA_1010102_004 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV12P010ToRGBA_1010102_004 end";
}

HWTEST_F(ImageFormatConvertTest, NV21P010ToRGBA_1010102_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBA_1010102_004 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: NV21P010ToRGBA_1010102_004 end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV12P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12P010_001: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV12P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12P010_002: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV12P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV21P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21P010_001: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGB565ToNV21P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21P010_002: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGB565ToNV21P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV12P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV12P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV12P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV21P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAToNV21P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21P010_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAToNV21P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV12P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12P010_001: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV12P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12P010_002: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV12P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV21P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21P010_001: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, BGRAToNV21P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21P010_002: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010(srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.BGRAToNV21P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV12P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV12P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12P010_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV12P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV21P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBToNV21P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21P010_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBToNV21P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV12P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV12P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12P010_002: start";
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV12P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV21P010_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21P010_001: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21P010_001: end";
}

HWTEST_F(ImageFormatConvertTest, RGBAF16ToNV21P010_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21P010_002: start";
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21P010_002: end";
}

HWTEST_F(ImageFormatConvertTest, RGBA_1010102ToNV12_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV12_003: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    Rgba1010102ConvertToYuvP010(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV12_003: end";
}

HWTEST_F(ImageFormatConvertTest, RGBA_1010102ToNV21_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV21_003: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    Rgba1010102ConvertToYuvP010(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBAF16ToNV21P010_003: end";
}

HWTEST_F(ImageFormatConvertTest, RGBA_1010102ToNV12P010_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV12P010_003: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    Rgba1010102ConvertToYuvP010(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV12P010_003: end";
}

HWTEST_F(ImageFormatConvertTest, RGBA_1010102ToNV21P010_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV21P010_003: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    Rgba1010102ConvertToYuvP010(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.RGBA_1010102ToNV21P010_003: end";
}

HWTEST_F(ImageFormatConvertTest, GetConvertFuncByFormat_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetConvertFuncByFormat_Test_001 start";
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::NV12;
    ConvertFunction cvtFunc = ImageFormatConvertTest::TestGetConvertFuncByFormat(srcFormat, destFormat);

    const_uint8_buffer_type srcBuffer = nullptr;
    RGBDataInfo size = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint8_buffer_type destBuffer = nullptr;
    size_t destBufferSize = 0;
    ColorSpace colorspace = ColorSpace::UNKNOWN;

    EXPECT_EQ(cvtFunc(srcBuffer, size, &destBuffer, destBufferSize, colorspace), false);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetConvertFuncByFormat_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, GetConvertFuncByFormat_Test_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetConvertFuncByFormat_Test_004 start";
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::UNKNOWN;
    ConvertFunction cvtFunc = ImageFormatConvertTest::TestGetConvertFuncByFormat(srcFormat, destFormat);

    EXPECT_EQ(cvtFunc, nullptr);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetConvertFuncByFormat_Test_004 end";
}

HWTEST_F(ImageFormatConvertTest, ConvertImageFormat_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_001 start";
    PixelFormat destFormat = PixelFormat::NV12;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, ConvertImageFormat_Test_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_002 start";
    PixelFormat destFormat = PixelFormat::UNKNOWN;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;
    uint32_t errorCode = 0;
    DecodeOptions decodeOpts;

    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH1, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    EXPECT_EQ(ret, ERR_MEDIA_FORMAT_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_002 end";
}

HWTEST_F(ImageFormatConvertTest, ConvertImageFormat_Test_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_003 start";
    PixelFormat destFormat = PixelFormat::RGB_888;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;
    uint32_t errorCode = 0;
    DecodeOptions decodeOpts;

    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH1, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(rImageSource.get(), nullptr);

    srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(srcPixelMap.get(), nullptr);

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_003 end";
}

HWTEST_F(ImageFormatConvertTest, CheckConvertDataInfo_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: CheckConvertDataInfo_Test_001 start";
    ConvertDataInfo convertDataInfo;
    convertDataInfo.buffer = nullptr;
    bool cvtFunc = ImageFormatConvert::CheckConvertDataInfo(convertDataInfo);
    EXPECT_EQ(cvtFunc, false);
    uint8_t data = 0;
    convertDataInfo.buffer = &data;
    EXPECT_NE(convertDataInfo.buffer, nullptr);
    convertDataInfo.pixelFormat = PixelFormat::UNKNOWN;
    cvtFunc = ImageFormatConvert::CheckConvertDataInfo(convertDataInfo);
    EXPECT_EQ(cvtFunc, false);
    convertDataInfo.pixelFormat = PixelFormat::ARGB_8888;
    convertDataInfo.imageSize = {0, 0};
    cvtFunc = ImageFormatConvert::CheckConvertDataInfo(convertDataInfo);
    EXPECT_EQ(cvtFunc, false);
    convertDataInfo.imageSize = {1, 1};
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(convertDataInfo.pixelFormat, convertDataInfo.imageSize), 4);
    convertDataInfo.bufferSize = 1;
    cvtFunc = ImageFormatConvert::CheckConvertDataInfo(convertDataInfo);
    EXPECT_EQ(cvtFunc, false);
    convertDataInfo.bufferSize = 4;
    cvtFunc = ImageFormatConvert::CheckConvertDataInfo(convertDataInfo);
    EXPECT_EQ(cvtFunc, true);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: CheckConvertDataInfo_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, GetBufferSizeByFormat_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetBufferSizeByFormat_Test_001 start";
    Size size = {1, 1};
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGB_565, size), 2);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGB_888, size), 3);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::ARGB_8888, size), 4);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGBA_8888, size), 4);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::BGRA_8888, size), 4);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGBA_F16, size), 8);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::NV21, size), 3);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::NV12, size), 3);
    EXPECT_EQ(ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::UNKNOWN, size), 0);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: GetBufferSizeByFormat_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, YUVGetConvertFuncByFormat_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: YUVGetConvertFuncByFormat_Test_001 start";
    PixelFormat srcFormat = PixelFormat::UNKNOWN;
    PixelFormat destFormat = PixelFormat::ARGB_8888;
    EXPECT_EQ(ImageFormatConvert::YUVGetConvertFuncByFormat(srcFormat, destFormat), nullptr);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: YUVGetConvertFuncByFormat_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, MakeDestPixelMap_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: MakeDestPixelMap_Test_001 start";
    std::shared_ptr<PixelMap> destPixelMap = nullptr;
    uint8_buffer_type destBuffer = nullptr;
    const size_t destBufferSize = 0;
    ImageInfo info;
    AllocatorType allcatorType = AllocatorType::DEFAULT;
    info.size = {0, 0};
    EXPECT_EQ(ImageFormatConvert::MakeDestPixelMap(destPixelMap, destBuffer, destBufferSize, info, allcatorType),
      false);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: MakeDestPixelMap_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, YUVConvertImageFormatOption_Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: YUVConvertImageFormatOption_Test_001 start";
    std::shared_ptr<PixelMap> srcPiexlMap = std::make_shared<PixelMap>();
    PixelFormat srcFormat = PixelFormat::UNKNOWN;
    PixelFormat destFormat = PixelFormat::ARGB_8888;
    EXPECT_EQ(ImageFormatConvert::YUVConvertImageFormatOption(srcPiexlMap, srcFormat, destFormat),
    ERR_IMAGE_INVALID_PARAMETER);
    srcFormat = PixelFormat::NV21;
    destFormat = PixelFormat::RGB_888;
    EXPECT_EQ(ImageFormatConvert::YUVConvertImageFormatOption(srcPiexlMap, srcFormat, destFormat),
    ERR_IMAGE_PIXELMAP_CREATE_FAILED);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: YUVConvertImageFormatOption_Test_001 end";
}

HWTEST_F(ImageFormatConvertTest, ConvertImageFormat_Test_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_004 start";
    std::shared_ptr<PixelMap> srcPixelMap = std::make_shared<PixelMap>();
    PixelFormat destFormat = PixelFormat::RGB_888;
    srcPixelMap->imageInfo_.pixelFormat = PixelFormat::NV21;
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    EXPECT_EQ(ret, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
    srcPixelMap->imageInfo_.pixelFormat = PixelFormat::RGB_565;
    destFormat = PixelFormat::NV21;
    ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    EXPECT_EQ(ret, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_004 end";
}

HWTEST_F(ImageFormatConvertTest, ConvertImageFormat_Test_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_005 start";
    ConvertDataInfo srcDataInfo;
    ConvertDataInfo destDataInfo;
    srcDataInfo.buffer = nullptr;
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcDataInfo, destDataInfo);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    uint8_t data = 0;
    srcDataInfo.buffer = &data;
    srcDataInfo.pixelFormat = PixelFormat::ARGB_8888;
    srcDataInfo.imageSize = {1, 1};
    srcDataInfo.bufferSize = 4;
    destDataInfo.pixelFormat = PixelFormat::UNKNOWN;
    ret = ImageFormatConvert::ConvertImageFormat(srcDataInfo, destDataInfo);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    srcDataInfo.pixelFormat = PixelFormat::UNKNOWN;
    destDataInfo.pixelFormat = PixelFormat::ARGB_8888;
    ret = ImageFormatConvert::ConvertImageFormat(srcDataInfo, destDataInfo);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    srcDataInfo.pixelFormat = PixelFormat::RGB_565;
    destDataInfo.pixelFormat = PixelFormat::NV21;
    ret = ImageFormatConvert::ConvertImageFormat(srcDataInfo, destDataInfo);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: ConvertImageFormat_Test_005 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_001 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_001 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_002 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_002 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_003 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_003 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_004 start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_004 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_005 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_005 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_006 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_006 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_007 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_007 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_008 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_008 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_009 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_009 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_010: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_010: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_011: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_011: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_012: start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_012: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_013 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_013 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_014 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_014 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_015 start";
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_015 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_016 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_016 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_017: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_017: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_018: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_018: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_019: start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_019: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_020 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_020 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_021 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_021 end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_022 start";
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest: PixelMapFormatConvert_022 end";
}


HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_023: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_023: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_024: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_024: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_025: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_025: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_026: start";
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_026: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_027: start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_027: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_028: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_029: start";
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_029: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_030: start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_030: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_031: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_031: end";
}

HWTEST_F(ImageFormatConvertTest, PixelMapFormatConvert_032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_032: start";
    PixelFormat srcFormat = PixelFormat::RGBA_1010102;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    PixelMap10bitConvert(srcFormat, destFormat, srcSize, destBuffersize);
    GTEST_LOG_(INFO) << "ImageFormatConvertTest.PixelMapFormatConvert_032: end";
}
} // namespace Media
} // namespace OHOS