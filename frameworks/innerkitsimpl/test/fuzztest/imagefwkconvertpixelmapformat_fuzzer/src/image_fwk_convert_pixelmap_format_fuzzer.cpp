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
#include "image_fwk_convert_pixelmap_format_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
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

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;
static constexpr uint32_t OPT_SIZE = 80;
static const std::string IMAGE_INPUT_JPG_PATH1 = "/data/local/tmp/test.jpg";

void PixelMapFormatConvert(PixelFormat &srcFormat, PixelFormat &destFormat)
{
    uint32_t errorCode = 0;
    SourceOptions srcopts;
    srcopts.formatHint = "image/jpeg";
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, srcopts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
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

    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    if (pixelMap.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: PixelMap::Create fail");
        return;
    }
    IMAGE_LOGI("PixelMapFormatConvert: ConvertImageFormat succ");
}

void PixelMapFormatFuzzTest001()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    PixelMapFormatConvert(srcFormat, destFormat);
    IMAGE_LOGI("PixelMapFormatFuzzTest001: end");
}

void PixelMapFormatFuzzTest002()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    PixelMapFormatConvert(srcFormat, destFormat);
    IMAGE_LOGI("PixelMapFormatFuzzTest002: end");
}

void PixelMapFormatFuzzTest003()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    PixelMapFormatConvert(srcFormat, destFormat);
    IMAGE_LOGI("PixelMapFormatFuzzTest003: end");
}

void PixelMapFormatFuzzTest004()
{
    IMAGE_LOGI("PixelMapFormatFuzzTest004: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    PixelMapFormatConvert(srcFormat, destFormat);
    IMAGE_LOGI("PixelMapFormatFuzzTest004: end");
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

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (size < OHOS::Media::OPT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return 0;
    }
    if (write data, size - OHOS::Media::OPT_SIZE) != static_cast<ssize_t>(size - OHOS::Media::OPT_SIZE)) {
        close(fd);
        return 0;
    }
    close(fd);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (action) {
        case 0:
            OHOS::Media::PixelMapFormatFuzzTest001();
            break;
        case 1:
            OHOS::Media::PixelMapFormatFuzzTest002();
            break;
        case 2:
            OHOS::Media::PixelMapFormatFuzzTest003();
            break;
        case 3:
            OHOS::Media::PixelMapFormatFuzzTest004();
            break;
        default:
            break;
    }
    return 0;
}