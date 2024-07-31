/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_yuv_convert_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fstream>
#include <vector>

#include <filesystem>
#include <iostream>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_format_convert_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"

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
constexpr int32_t SLEEP_TIME = 100;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

static const std::string IMAGE_INPUT_JPG_PATH1 = "/data/local/tmp/800-500.jpg";
static const std::string IMAGE_INPUT_JPG_PATH2 = "/data/local/tmp/951-595.jpg";
static const std::string IMAGE_INPUT_YUV_PATH3 = "/data/local/tmp/P010.yuv";

void RgbConvertToYuv(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuv: CreateImageSource fail");
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuv: CreatePixelMap fail");
        return;
    }

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    srcPixelMap->FreePixelMap();
    if (ret != SUCCESS) {
        IMAGE_LOGE("RgbConvertToYuv: ConvertImageFormat fail");
        return;
    }
    IMAGE_LOGI("RgbConvertToYuv: ConvertImageFormat succ");
}

void YuvConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    IMAGE_LOGI("YuvConvertToRgb: start");
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("YuvConvertToRgb: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("YuvConvertToRgb: CreatePixelMap fail");
        return;
    }
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    srcPixelMap->FreePixelMap();
    if (ret != SUCCESS) {
        IMAGE_LOGE("YuvConvertToRgb: ConvertImageFormat fail");
        return;
    }
    IMAGE_LOGI("YuvConvertToRgb: succ");
}

bool ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum)
{
    FILE* const fileOrg = fopen(path.c_str(), "rb");
    if (fileOrg == nullptr) {
        return false;
    }
    if (srcNum == 0) {
        size_t bytesOrg = fread(chOrg, sizeof(uint8_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            return false;
        }
    } else {
        size_t bytesOrg = fread(chOrg, sizeof(uint16_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            return false;
        }
    }
    return true;
}

void YuvP010ConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize,
    uint32_t destBuffersize)
{
    IMAGE_LOGI("YuvP010ConvertToRgb: start");
    ImageSize imageSize;
    imageSize.width = srcSize.width;
    imageSize.height = srcSize.height;
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / NUM_2) * ((imageSize.height + 1) / NUM_2);
    const size_t totalSize = (ySize + NUM_2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    if (!result) {
        delete[] chOrg;
        return;
    }
    const uint32_t dataLength = totalSize * NUM_2;
    uint32_t *data = (uint32_t *)chOrg;
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = srcFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    if (pixelMap.get() == nullptr) {
        delete[] chOrg;
        return;
    }
    delete[] chOrg;
    std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelMap);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    if (ret != SUCCESS || srcPixelMap->GetPixelFormat() != destFormat) {
        srcPixelMap->FreePixelMap();
        IMAGE_LOGE("YuvP010ConvertToRgb: CreatePixelMap fail");
        return;
    }
    srcPixelMap->FreePixelMap();
    IMAGE_LOGI("YuvP010ConvertToRgb: succ");
}

void RGB565ToNV12FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("RGB565ToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGB565ToNV12FuzzTest001: end");
}

void RGB565ToNV12FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("RGB565ToNV12FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGB565ToNV12FuzzTest002: end");
}

void RGB565ToNV21FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("RGB565ToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGB565ToNV21FuzzTest001: end");
}

void RGB565ToNV21FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("RGB565ToNV21FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGB565ToNV21FuzzTest002: end");
}

void BGRAToNV21FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("BGRAToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("BGRAToNV21FuzzTest001: end");
}

void BGRAToNV21FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("BGRAToNV21FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("BGRAToNV21FuzzTest002: end");
}

void BGRAToNV12FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("BGRAToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("BGRAToNV12FuzzTest001: end");
}

void BGRAToNV12FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("BGRAToNV12FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuv(srcFormat, destFormat, srcSize);
    IMAGE_LOGI("BGRAToNV12FuzzTest002: end");
}

void RgbToYuvFuzzTest001()
{
    IMAGE_LOGI("RgbToYuvFuzzTest001: start");
    RGB565ToNV12FuzzTest001();
    RGB565ToNV12FuzzTest002();
    RGB565ToNV21FuzzTest001();
    RGB565ToNV21FuzzTest002();
    BGRAToNV21FuzzTest001();
    BGRAToNV21FuzzTest002();
    BGRAToNV12FuzzTest001();
    BGRAToNV12FuzzTest002();
    IMAGE_LOGI("RgbToYuvFuzzTest001: end");
}

void NV21ToRGBFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGBFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBFuzzTest001: end");
}

void NV21ToRGBFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGBFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBFuzzTest002: end");
}

void NV21ToRGBAFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGBAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBAFuzzTest001: end");
}

void NV21ToRGBAFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGBAFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBAFuzzTest002: end");
}

void NV21ToBGRAFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToBGRAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToBGRAFuzzTest001: end");
}

void NV21ToBGRAFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToBGRAFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToBGRAFuzzTest002: end");
}

void NV21ToRGB565FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGB565FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGB565FuzzTest001: end");
}

void NV21ToRGB565FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToRGB565FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGB565FuzzTest002: end");
}

void NV21ToNV12FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV12FuzzTest001: end");
}

void NV21ToNV12FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToNV12FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV12FuzzTest002: end");
}

void NV12ToNV21FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToNV21FuzzTest001: end");
}

void NV12ToNV21FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToNV21FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToNV21FuzzTest002: end");
}

void NV12ToRGB565FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGB565FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGB565FuzzTest001: end");
}

void NV12ToRGB565FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGB565FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB565;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGB565FuzzTest002: end");
}

void NV12ToRGBAFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGBAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBAFuzzTest001: end");
}

void NV12ToRGBAFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGBAFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBAFuzzTest002: end");
}

void NV12ToBGRAFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToBGRAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToBGRAFuzzTest001: end");
}

void NV12ToBGRAFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToBGRAFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_BGRA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToBGRAFuzzTest002: end");
}

void NV12ToRGBFuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGBFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBFuzzTest001: end");
}

void NV12ToRGBFuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToRGBFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * BYTES_PER_PIXEL_RGB;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBFuzzTest002: end");
}

void NV21ToNV12P010FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV12P010FuzzTest001: end");
}

void NV21ToNV12P010FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToNV12P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV12P010FuzzTest002: end");
}

void NV21ToNV12P010FuzzTest003()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV21ToNV12P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV12P010FuzzTest003: end");
}

void NV12ToNV12P010FuzzTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES)  * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToNV12P010FuzzTest001: end");
}

void NV12ToNV12P010FuzzTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    IMAGE_LOGI("NV12ToNV12P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToNV12P010FuzzTest002: end");
}

void YuvToRgbFuzzTest001()
{
    IMAGE_LOGI("YuvToRgbFuzzTest001: start");
    NV21ToRGBFuzzTest001();
    NV21ToRGBFuzzTest002();
    NV21ToRGBAFuzzTest001();
    NV21ToRGBAFuzzTest002();
    NV21ToBGRAFuzzTest001();
    NV21ToBGRAFuzzTest002();
    NV21ToRGB565FuzzTest001();
    NV21ToRGB565FuzzTest002();
    NV21ToNV12FuzzTest001();
    NV21ToNV12FuzzTest002();
    NV12ToNV21FuzzTest001();
    NV12ToNV21FuzzTest002();
    NV12ToRGB565FuzzTest001();
    NV12ToRGB565FuzzTest002();
    NV12ToRGBAFuzzTest001();
    NV12ToRGBAFuzzTest002();
    NV12ToBGRAFuzzTest001();
    NV12ToBGRAFuzzTest002();
    NV12ToRGBFuzzTest001();
    NV12ToRGBFuzzTest002();
    NV21ToNV12P010FuzzTest001();
    NV21ToNV12P010FuzzTest002();
    NV21ToNV12P010FuzzTest003();
    NV12ToNV12P010FuzzTest001();
    NV12ToNV12P010FuzzTest002();
    IMAGE_LOGI("YuvToRgbFuzzTest001: end");
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::RgbToYuvFuzzTest001();
    OHOS::Media::YuvToRgbFuzzTest001();
    return 0;
}