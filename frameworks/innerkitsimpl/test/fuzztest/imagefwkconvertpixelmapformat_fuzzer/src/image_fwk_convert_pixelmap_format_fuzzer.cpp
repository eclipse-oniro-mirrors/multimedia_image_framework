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

    static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        IMAGE_LOGE("Fuzzer copy data fail");
        return 0;
    }
    close(fd);
    OHOS::Media::PixelMapFormattotalFuzzTest001();
    return 0;
}