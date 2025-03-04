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

#include "image_fwk_convert_astc2rgb_fuzzer.h"

#include <fstream>
#include <securec.h>
#include "image_format_convert.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "media_errors.h"
#include "pixel_convert.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {
constexpr uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
constexpr uint32_t ASTC_HEAD_LEN = 16;
constexpr uint32_t UNPACK_SHIFT_1 = 8;
constexpr uint32_t UNPACK_SHIFT_2 = 16;
constexpr uint32_t UNPACK_SHIFT_3 = 24;
constexpr uint8_t MASKBITS_FOR_8BIT = 0xFF;
constexpr uint8_t BYTE_POS_7 = 7;
constexpr uint8_t BYTE_POS_8 = 8;
constexpr uint8_t BYTE_POS_9 = 9;
constexpr uint8_t BYTE_POS_10 = 10;
constexpr uint8_t BYTE_POS_11 = 11;
constexpr uint8_t BYTE_POS_12 = 12;
constexpr uint32_t ASTC_MAX_WIDTH = 8499;
constexpr uint32_t MAX_MALLOC_SIZE = (10 * 1024 * 1024); // 10M

void GenAstcHeader(uint8_t *data, size_t size)
{
    if (size >= ASTC_HEAD_LEN) {
        uint8_t *astcBuf = data;
        *astcBuf++ = ASTC_MAGIC_ID & MASKBITS_FOR_8BIT;
        *astcBuf++ = (ASTC_MAGIC_ID >> UNPACK_SHIFT_1) & MASKBITS_FOR_8BIT;
        *astcBuf++ = (ASTC_MAGIC_ID >> UNPACK_SHIFT_2) & MASKBITS_FOR_8BIT;
        *astcBuf++ = (ASTC_MAGIC_ID >> UNPACK_SHIFT_3) & MASKBITS_FOR_8BIT;
    }
    return;
}

bool DumpSingleInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        IMAGE_LOGE("invalid input!");
        return false;
    }
    const std::string inFilePath = "/data/local/tmp/fuzzAstcDec.astc";
    std::ofstream dumpInFile;
    dumpInFile.open(inFilePath, std::ios_base::binary | std::ios_base::trunc);
    if (!dumpInFile.is_open()) {
        IMAGE_LOGE("fail to open %{public}s", inFilePath.c_str());
        return false;
    }
    dumpInFile.write(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), size);
    dumpInFile.close();
    return true;
}

unsigned int UnpackBytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return static_cast<unsigned int>(a) +
        (static_cast<unsigned int>(b) << UNPACK_SHIFT_1) +
        (static_cast<unsigned int>(c) << UNPACK_SHIFT_2) +
        (static_cast<unsigned int>(d) << UNPACK_SHIFT_3);
}

std::unique_ptr<Media::PixelMap> GetPixelMap(const uint8_t *data, size_t size, PixelFormat srcformat)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (errorCode != SUCCESS || imageSource == nullptr) {
        IMAGE_LOGE("AstcCOnvertToRgb: CreateImageSource fail");
        return nullptr;
    }
    DecodeOptions decodeOpts;
    unsigned int dimX = UnpackBytes(data[BYTE_POS_7], data[BYTE_POS_8], data[BYTE_POS_9], 0);
    unsigned int dimY = UnpackBytes(data[BYTE_POS_10], data[BYTE_POS_11], data[BYTE_POS_12], 0);
    decodeOpts.desiredSize.width = static_cast<int>(dimX % ASTC_MAX_WIDTH);
    decodeOpts.desiredSize.height = static_cast<int>(dimY % ASTC_MAX_WIDTH);
    decodeOpts.desiredPixelFormat = srcformat;
    std::unique_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || pixelMap == nullptr) {
        IMAGE_LOGE("AstcCOnvertToRgb: CreatePixelMap fail");
        return nullptr;
    }
    return pixelMap;
}

void AstcToRgbFuzzTest(const uint8_t *data, size_t size)
{
    if (size <= 0 || size > MAX_MALLOC_SIZE) {
        return;
    }
    uint8_t *dataIn = static_cast<uint8_t *>(malloc(size));
    if (dataIn == nullptr || size < ASTC_HEAD_LEN) {
        return;
    }
    if (memcpy_s(dataIn, size, data, size) != 0) {
        free(dataIn);
        return;
    }
    GenAstcHeader(dataIn, size);
    uint32_t errorCode = 0;
    // right format
    std::unique_ptr<Media::PixelMap> input = GetPixelMap(dataIn, size, PixelFormat::ASTC_4x4);
    if (input == nullptr) {
        free(dataIn);
        return;
    }
    std::unique_ptr<Media::PixelMap> resultPixelMap = PixelMap::ConvertFromAstc(std::move(input).get(), errorCode,
        PixelFormat::RGBA_8888);
    if (errorCode != SUCCESS) {
        free(dataIn);
        return;
    }
    // err format
    input = GetPixelMap(dataIn, size, PixelFormat::ASTC_6x6);
    if (input == nullptr) {
        free(dataIn);
        return;
    }
    resultPixelMap = PixelMap::ConvertFromAstc(std::move(input).get(), errorCode,
        PixelFormat::ARGB_8888);
    if (errorCode != SUCCESS) {
        free(dataIn);
        return;
    }
    free(dataIn);
    return;
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::DumpSingleInput(data, size);
    OHOS::Media::AstcToRgbFuzzTest(data, size);
    return 0;
}