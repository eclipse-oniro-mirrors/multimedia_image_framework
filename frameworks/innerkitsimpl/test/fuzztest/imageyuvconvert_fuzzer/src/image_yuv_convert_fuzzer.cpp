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

#define private public
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

#include "pixel_map.h"

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

/*
 * test pixelmap IPC interface
 */
bool g_pixelMapIpcTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test parcel pixelmap
    Parcel parcel;
    pixelMap->SetMemoryName("MarshallingPixelMap");
    if (!pixelMap->Marshalling(parcel)) {
        IMAGE_LOGI("g_pixelMapIpcTest Marshalling failed id: %{public}d, isUnmap: %{public}d",
            pixelMap->GetUniqueId(), pixelMap->IsUnMap());
        return false;
    }
    Media::PixelMap* unmarshallingPixelMap = Media::PixelMap::Unmarshalling(parcel);
    if (!unmarshallingPixelMap) {
        return false;
    }
    unmarshallingPixelMap->SetMemoryName("unmarshallingPixelMap");
    IMAGE_LOGI("g_pixelMapIpcTest unmarshallingPixelMap failed id: %{public}d, isUnmap: %{public}d",
        unmarshallingPixelMap->GetUniqueId(), unmarshallingPixelMap->IsUnMap());
    unmarshallingPixelMap->FreePixelMap();
    delete unmarshallingPixelMap;
    unmarshallingPixelMap = nullptr;
    return true;
}

std::unique_ptr<Media::PixelMap> GetYuvPixelMap(PixelFormat &srcFormat, Size &srcSize)
{
    IMAGE_LOGI("GetYuvPixelMap: start");
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::unique_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("GetYuvPixelMap: CreateImageSource fail");
        return nullptr;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::unique_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("GetYuvPixelMap: CreatePixelMap fail");
        return nullptr;
    }
    return srcPixelMap;
}

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

void RgbConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010: CreatePixelMap fail");
        return;
    }

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    srcPixelMap->FreePixelMap();
    if (ret != SUCCESS) {
        IMAGE_LOGE("RgbConvertToYuvP010: ConvertImageFormat fail");
        return;
    }
    IMAGE_LOGI("RgbConvertToYuvP010: ConvertImageFormat succ");
}

void RgbConvertToYuvP010ByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
    PixelFormat &destFormat, Size &srcSize)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    auto rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010ByPixelMap: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = tempFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = nullptr;
    srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010ByPixelMap: CreatePixelMap fail");
        return;
    }

    uint32_t tmpRet = ImageFormatConvert::ConvertImageFormat(srcPixelMap, srcFormat);
    if (tmpRet != SUCCESS) {
        IMAGE_LOGE("RgbConvertToYuvP010ByPixelMap: ConvertImageFormat srcFormat fail");
        srcPixelMap->FreePixelMap();
        return;
    }

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    srcPixelMap->FreePixelMap();
    if (ret != SUCCESS) {
        IMAGE_LOGE("RgbConvertToYuvP010ByPixelMap: ConvertImageFormat destFormat fail");
        return;
    }
    IMAGE_LOGI("RgbConvertToYuvP010ByPixelMap: ConvertImageFormat succ");
}

void PixelMapFormatConvert(PixelFormat &srcFormat, PixelFormat &destFormat,
    Size &srcSize, uint32_t destBuffersize)
{
    uint32_t errorCode = 0;
    SourceOptions srcopts;
    srcopts.formatHint = "image/jpeg";
    std::string jpgPath = srcSize.width % EVEN_ODD_DIVISOR == 0 ? IMAGE_INPUT_JPG_PATH1 : IMAGE_INPUT_JPG_PATH2;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, srcopts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    decodeOpts.desiredSize.width = srcSize.width;
    decodeOpts.desiredSize.height = srcSize.height;
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: CreatePixelMap fail");
        return;
    }

    uint32_t *data = (uint32_t *)srcPixelMap->GetPixels();
    const uint32_t dataLength = srcPixelMap->GetByteCount();
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = destFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = srcSize.width;
    opts.size.height = srcSize.height;

    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    if (pixelMap.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: PixelMap::Create fail");
        return;
    }
    IMAGE_LOGI("PixelMapFormatConvert: ConvertImageFormat succ");
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

std::unique_ptr<Media::PixelMap> GetYuvP010PixelMap(PixelFormat &srcFormat, Size &srcSize)
{
    IMAGE_LOGI("GetYuvP010PixelMap: start");
    ImageSize imageSize;
    imageSize.width = srcSize.width;
    imageSize.height = srcSize.height;
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / NUM_2) * ((imageSize.height + 1) / NUM_2);
    const size_t totalSize = (ySize + NUM_2 * uvSize);
    uint16_t* const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_INPUT_YUV_PATH3, totalSize, 1);
    if (!result) {
        IMAGE_LOGE("GetYuvPixelMap: ReadFile fail");
        delete[] chOrg;
        return nullptr;
    }
    const uint32_t dataLength = totalSize * NUM_2;
    uint32_t *data = reinterpret_cast<uint32_t*>(chOrg);
    InitializationOptions opts;
    opts.srcPixelFormat = srcFormat;
    opts.pixelFormat = srcFormat;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    if (pixelMap.get() == nullptr) {
        delete[] chOrg;
        IMAGE_LOGE("GetYuvPixelMap: Create fail");
        return nullptr;
    }
    delete[] chOrg;
    return pixelMap;
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
    uint32_t *data = reinterpret_cast<uint32_t *>(chOrg);
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

void NV21PixelMapIPCTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    PixelFormat srcFormat = PixelFormat::NV21;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvPixelMap);
}

void NV21PixelMapIPCTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    PixelFormat srcFormat = PixelFormat::NV21;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvPixelMap);
}

void NV12PixelMapIPCTest001()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    PixelFormat srcFormat = PixelFormat::NV12;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvPixelMap);
}

void NV12PixelMapIPCTest002()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    PixelFormat srcFormat = PixelFormat::NV12;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvPixelMap);
}

void NV12P010PixelMapIPCTest001()
{
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvP010PixelMap = GetYuvP010PixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvP010PixelMap);
}

void NV21P010PixelMapIPCTest001()
{
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    std::unique_ptr<Media::PixelMap> yuvP010PixelMap = GetYuvP010PixelMap(srcFormat, srcSize);
    g_pixelMapIpcTest(yuvP010PixelMap);
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

void NV21ToRGBAF16FuzzTest001()
{
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest001: end");
}

void NV21ToRGBAF16FuzzTest002()
{
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest002: end");
}

void NV12ToRGBAF16FuzzTest001()
{
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = TREE_ORIGINAL_WIDTH * TREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest001: end");
}

void NV12ToRGBAF16FuzzTest002()
{
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = ODDTREE_ORIGINAL_WIDTH * ODDTREE_ORIGINAL_HEIGHT * sizeof(uint64_t);
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest002: end");
}

void NV21P010ToNV12FuzzTest003()
{
    IMAGE_LOGI("NV21P010ToNV12FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToNV12FuzzTest003: end");
}

void NV21ToNV21P010FuzzTest003()
{
    IMAGE_LOGI("NV21ToNV21P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToNV21P010FuzzTest003: end");
}

void NV12ToNV21P010FuzzTest003()
{
    IMAGE_LOGI("NV12ToNV21P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToNV21P010FuzzTest003: end");
}

void NV12ToRGBA1010102FuzzTest001()
{
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest001: end");
}

void NV21ToRGBA1010102FuzzTest001()
{
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest001: end");
}

void NV12ToRGBA1010102FuzzTest003()
{
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest003: end");
}

void NV21ToRGBA1010102FuzzTest003()
{
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest003: end");
}

void NV12P010ToNV12FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToNV12FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV12;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToNV12FuzzTest003: end");
}

void NV12P010ToNV21FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToNV21FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToNV21FuzzTest003: end");
}

void NV12P010ToNV21P010FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToNV21P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToNV21P010FuzzTest003: end");
}

void NV12P010ToRGB565FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToRGB565FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToRGB565FuzzTest003: end");
}

void NV12P010ToRGBAFuzzTest003()
{
    IMAGE_LOGI("NV12P010ToRGBAFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToRGBAFuzzTest003: end");
}

void NV12P010ToBGRAFuzzTest003()
{
    IMAGE_LOGI("NV12P010ToBGRAFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToBGRAFuzzTest003: end");
}

void NV12P010ToRGBFuzzTest003()
{
    IMAGE_LOGI("NV12P010ToRGBFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToRGBFuzzTest003: end");
}

void NV12P010ToRGBAF16FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToRGBAF16FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToRGBAF16FuzzTest003: end");
}

void NV21P010ToNV21FuzzTest003()
{
    IMAGE_LOGI("NV21P010ToNV21FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::NV21;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToNV21FuzzTest003: end");
}

void NV12P010ToNV12P010FuzzTest003()
{
    IMAGE_LOGI("NV12P010ToNV12P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToNV12P010FuzzTest003: end");
}

void NV21P010ToRGB565FuzzTest003()
{
    IMAGE_LOGI("NV21P010ToRGB565FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_565;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB565;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToRGB565FuzzTest003: end");
}

void NV21P010ToRGBAFuzzTest003()
{
    IMAGE_LOGI("NV21P010ToRGBAFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToRGBAFuzzTest003: end");
}

void NV21P010ToBGRAFuzzTest003()
{
    IMAGE_LOGI("NV21P010ToBGRAFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_BGRA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToBGRAFuzzTest003: end");
}

void NV21P010ToRGBFuzzTest003()
{
    IMAGE_LOGI("NV21P010ToRGBFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGB_888;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGB;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToRGBFuzzTest003: end");
}

void NV21P010ToRGBAF16FuzzTest003()
{
    IMAGE_LOGI("NV21P010ToRGBAF16FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * sizeof(uint64_t);
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToRGBAF16FuzzTest003: end");
}

void NV12P010ToRGBA1010102FuzzTest004()
{
    IMAGE_LOGI("NV12P010ToRGBA_1010102FuzzTest004: start");
    PixelFormat srcFormat = PixelFormat::YCBCR_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV12P010ToRGBA_1010102FuzzTest004: end");
}

void NV21P010ToRGBA1010102FuzzTest004()
{
    IMAGE_LOGI("NV21P010ToRGBA_1010102FuzzTest004: start");
    PixelFormat srcFormat = PixelFormat::YCRCB_P010;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    Size srcSize = { P010_ORIGINAL_WIDTH, P010_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = srcSize.width * srcSize.height * BYTES_PER_PIXEL_RGBA;
    YuvP010ConvertToRgb(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("NV21P010ToRGBA_1010102FuzzTest004: end");
}

void RGBAToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBAToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAToNV12P010FuzzTest001: end");
}

void RGBAToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBAToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAToNV12P010FuzzTest002: end");
}

void RGBAToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBAToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAToNV21P010FuzzTest001: end");
}

void RGBAToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBAToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAToNV21P010FuzzTest002: end");
}

void RGBToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBToNV12P010FuzzTest001: end");
}

void RGBToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBToNV12P010FuzzTest002: end");
}

void RGBToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBToNV21P010FuzzTest001: end");
}

void RGBToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBToNV21P010FuzzTest002: end");
}

void RGBAF16ToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest001: end");
}

void RGBAF16ToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest002: end");
}

void RGBAF16ToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest001: end");
}

void RGBAF16ToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat, srcSize);
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest002: end");
}

void PixelMapFormatFuzzTest001()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("PixelMapFormatFuzzTest001: end");
}

void PixelMapFormatFuzzTest002()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("PixelMapFormatFuzzTest002: end");
}

void PixelMapFormatFuzzTest003()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    Size srcSize = { ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("PixelMapFormatFuzzTest003: end");
}

void PixelMapFormatFuzzTest004()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest004: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    Size srcSize = { TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT };
    uint32_t destBuffersize = (srcSize.width * srcSize.height + ((srcSize.width + 1) / EVEN_ODD_DIVISOR) *
        ((srcSize.height + 1) / EVEN_ODD_DIVISOR) * TWO_SLICES) * TWO_SLICES;
    PixelMapFormatConvert(srcFormat, destFormat, srcSize, destBuffersize);
    IMAGE_LOGI("PixelMapFormatFuzzTest004: end");
}

void GetBufferSizeByFormatFuzzTest001()
{
    IMAGE_LOGI("GetBufferSizeByFormatFuzzTest001: start");
    Size size = {1, 1};
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGB_565, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGB_888, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::ARGB_8888, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGBA_8888, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::BGRA_8888, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::RGBA_F16, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::NV21, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::NV12, size);
    ImageFormatConvert::GetBufferSizeByFormat(PixelFormat::UNKNOWN, size);
    IMAGE_LOGI("GetBufferSizeByFormatFuzzTest001: end");
}

void YUVGetConvertFuncByFormatFuzzTest001()
{
    IMAGE_LOGI("YUVGetConvertFuncByFormatFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::UNKNOWN;
    PixelFormat destFormat = PixelFormat::ARGB_8888;
    ImageFormatConvert::YUVGetConvertFuncByFormat(srcFormat, destFormat);
    IMAGE_LOGI("YUVGetConvertFuncByFormatFuzzTest001: end");
}

void IsSupportFuzzTest001()
{
    IMAGE_LOGI("IsSupportFuzzTest001: start");
    ImageFormatConvert::IsSupport(PixelFormat::ARGB_8888);
    ImageFormatConvert::IsSupport(PixelFormat::RGB_565);
    ImageFormatConvert::IsSupport(PixelFormat::RGBA_8888);
    ImageFormatConvert::IsSupport(PixelFormat::BGRA_8888);
    ImageFormatConvert::IsSupport(PixelFormat::RGB_888);
    ImageFormatConvert::IsSupport(PixelFormat::RGBA_F16);
    ImageFormatConvert::IsSupport(PixelFormat::RGBA_1010102);
    ImageFormatConvert::IsSupport(PixelFormat::YCBCR_P010);
    ImageFormatConvert::IsSupport(PixelFormat::YCRCB_P010);
    ImageFormatConvert::IsSupport(PixelFormat::NV21);
    ImageFormatConvert::IsSupport(PixelFormat::NV12);
    ImageFormatConvert::IsSupport(PixelFormat::UNKNOWN);
    IMAGE_LOGI("IsSupportFuzzTest001: end");
}

void IsValidSizeFuzzTest001()
{
    IMAGE_LOGI("IsValidSizeFuzzTest001: start");
    const Size size1 = {1, 1};
    const Size size2 = {0, 0};
    ImageFormatConvert::IsValidSize(size1);
    ImageFormatConvert::IsValidSize(size2);
    IMAGE_LOGI("IsValidSizeFuzzTest001: end");
}

void ImageFuzzTest001()
{
    IMAGE_LOGI("ImageFuzzTest001: start");
    GetBufferSizeByFormatFuzzTest001();
    YUVGetConvertFuncByFormatFuzzTest001();
    IsSupportFuzzTest001();
    IsValidSizeFuzzTest001();
    IMAGE_LOGI("ImageFuzzTest001: end");
}

void PixelMapFormattotalFuzzTest001()
{
    IMAGE_LOGI("PixelMapFormatTest001: start");
    PixelMapFormatFuzzTest001();
    PixelMapFormatFuzzTest002();
    PixelMapFormatFuzzTest003();
    PixelMapFormatFuzzTest004();
    IMAGE_LOGI("PixelMapFormatTest001: end");
}

void YuvPixelMapIPCFuzzTest001()
{
    NV21PixelMapIPCTest001();
    NV21PixelMapIPCTest002();
    NV12PixelMapIPCTest001();
    NV12PixelMapIPCTest002();
}

void YuvP010PixelMapIPCFuzzTest001()
{
    NV12P010PixelMapIPCTest001();
    NV21P010PixelMapIPCTest001();
}

void RgbToYuvP010ByPixelMapFuzzTest001()
{
    IMAGE_LOGI("RgbToYuvP010ByPixelMapTest001: start");
    RGBAToNV12P010FuzzTest001();
    RGBAToNV12P010FuzzTest002();
    RGBAToNV21P010FuzzTest001();
    RGBAToNV21P010FuzzTest002();
    RGBToNV12P010FuzzTest001();
    RGBToNV12P010FuzzTest002();
    RGBToNV21P010FuzzTest001();
    RGBToNV21P010FuzzTest002();
    RGBAF16ToNV12P010FuzzTest001();
    RGBAF16ToNV12P010FuzzTest002();
    RGBAF16ToNV21P010FuzzTest001();
    RGBAF16ToNV21P010FuzzTest002();
    IMAGE_LOGI("RgbToYuvP010ByPixelMapTest001: end");
}

void YuvP010ToRgbFuzzTest001()
{
    IMAGE_LOGI("YuvP010ToRgbTest001: start");
    NV12P010ToNV12FuzzTest003();
    NV12P010ToNV21FuzzTest003();
    NV12P010ToNV21P010FuzzTest003();
    NV12P010ToRGB565FuzzTest003();
    NV12P010ToRGBAFuzzTest003();
    NV12P010ToBGRAFuzzTest003();
    NV12P010ToRGBFuzzTest003();
    NV12P010ToRGBAF16FuzzTest003();
    NV21P010ToNV12FuzzTest003();
    NV21P010ToNV21FuzzTest003();
    NV12P010ToNV12P010FuzzTest003();
    NV21P010ToRGB565FuzzTest003();
    NV21P010ToRGBAFuzzTest003();
    NV21P010ToBGRAFuzzTest003();
    NV21P010ToRGBFuzzTest003();
    NV21P010ToRGBAF16FuzzTest003();
    NV12P010ToRGBA1010102FuzzTest004();
    NV21P010ToRGBA1010102FuzzTest004();
    IMAGE_LOGI("YuvP010ToRgbTest001: end");
}

void YuvToRgbFuzzTest002()
{
    IMAGE_LOGI("YuvToRgbFuzzTest002: start");
    NV21ToNV21P010FuzzTest003();
    NV12ToNV21P010FuzzTest003();
    NV12ToRGBA1010102FuzzTest003();
    NV21ToRGBA1010102FuzzTest003();
    IMAGE_LOGI("YuvToRgbFuzzTest002: end");
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
    NV21ToRGBAF16FuzzTest001();
    NV21ToRGBAF16FuzzTest002();
    NV12ToRGBAF16FuzzTest001();
    NV12ToRGBAF16FuzzTest002();
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
    OHOS::Media::YuvToRgbFuzzTest002();
    OHOS::Media::YuvP010ToRgbFuzzTest001();
    OHOS::Media::RgbToYuvP010ByPixelMapFuzzTest001();
    OHOS::Media::YuvPixelMapIPCFuzzTest001();
    OHOS::Media::YuvP010PixelMapIPCFuzzTest001();
    OHOS::Media::PixelMapFormattotalFuzzTest001();
    OHOS::Media::ImageFuzzTest001();
    return 0;
}