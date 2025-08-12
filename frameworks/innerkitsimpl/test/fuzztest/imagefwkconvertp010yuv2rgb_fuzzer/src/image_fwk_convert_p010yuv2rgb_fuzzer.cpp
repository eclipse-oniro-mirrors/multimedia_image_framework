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
#include "image_fwk_convert_p010yuv2rgb_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#include <fcntl.h>

#include <filesystem>
#include <iostream>
#include <unistd.h>

#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_format_convert_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "message_parcel.h"

namespace OHOS {
namespace Media {

constexpr int32_t P010_ORIGINAL_WIDTH = 1920;
constexpr int32_t P010_ORIGINAL_HEIGHT = 1080;
constexpr uint32_t BYTES_PER_PIXEL_RGB565 = 2;
constexpr uint32_t BYTES_PER_PIXEL_RGB = 3;
constexpr uint32_t BYTES_PER_PIXEL_RGBA = 4;
constexpr uint32_t BYTES_PER_PIXEL_BGRA = 4;
constexpr uint32_t EVEN_ODD_DIVISOR = 2;
constexpr uint32_t TWO_SLICES = 2;
constexpr int32_t NUM_2 = 2;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

static const std::string IMAGE_INPUT_YUV_PATH3 = "/data/local/tmp/P010.yuv";

bool ReadFile(void *chOrg, std::string path, int32_t totalsize, int32_t srcNum)
{
    FILE* const fileOrg = fopen(path.c_str(), "rb");
    if (fileOrg == nullptr) {
        return false;
    }
    if (srcNum == 0) {
        size_t bytesOrg = fread(chOrg, sizeof(uint8_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            fclose(fileOrg);
            return false;
        }
    } else {
        size_t bytesOrg = fread(chOrg, sizeof(uint16_t), static_cast<size_t>(totalsize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalsize)) {
            fclose(fileOrg);
            return false;
        }
    }
    fclose(fileOrg);
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
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    int fd = open(OHOS::Media::IMAGE_INPUT_YUV_PATH3.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        IMAGE_LOGE("Fuzzer copy data fail");
        return 0;
    }
    close(fd);
    OHOS::Media::YuvP010ToRgbFuzzTest001();
    return 0;
}