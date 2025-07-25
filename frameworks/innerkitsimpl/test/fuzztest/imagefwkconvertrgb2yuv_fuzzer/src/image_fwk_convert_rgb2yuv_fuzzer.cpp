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
#include "image_fwk_convert_rgb2yuv_fuzzer.h"

#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <string>
#include <fstream>
#include <vector>

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

void RgbConvertToYuv(PixelFormat &srcFormat, PixelFormat &destFormat)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuv: CreateImageSource fail");
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
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

void RGB565ToNV12FuzzTest001()
{
    IMAGE_LOGI("RGB565ToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV12FuzzTest001: end");
}

void RGB565ToNV12FuzzTest002()
{
    IMAGE_LOGI("RGB565ToNV12FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV12;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV12FuzzTest002: end");
}

void RGB565ToNV21FuzzTest001()
{
    IMAGE_LOGI("RGB565ToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV21FuzzTest001: end");
}

void RGB565ToNV21FuzzTest002()
{
    IMAGE_LOGI("RGB565ToNV21FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV21FuzzTest002: end");
}

void BGRAToNV21FuzzTest001()
{
    IMAGE_LOGI("BGRAToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV21FuzzTest001: end");
}

void BGRAToNV21FuzzTest002()
{
    IMAGE_LOGI("BGRAToNV21FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV21FuzzTest002: end");
}

void BGRAToNV12FuzzTest001()
{
    IMAGE_LOGI("BGRAToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV12FuzzTest001: end");
}

void BGRAToNV12FuzzTest002()
{
    IMAGE_LOGI("BGRAToNV12FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV12;
    RgbConvertToYuv(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV12FuzzTest002: end");
}
} // namespace Media
} // namespace OHOS

/*Fuzzer entry point*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*Run your code on data*/
    IMAGE_LOGI("RgbToYuvFuzzTest001: start");
    static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        IMAGE_LOGE("Fuzzer copy data fail");
        return 0;
    }
    close(fd);
    OHOS::Media::RGB565ToNV12FuzzTest001();
    OHOS::Media::RGB565ToNV12FuzzTest002();
    OHOS::Media::RGB565ToNV21FuzzTest001();
    OHOS::Media::RGB565ToNV21FuzzTest002();
    OHOS::Media::BGRAToNV21FuzzTest001();
    OHOS::Media::BGRAToNV21FuzzTest002();
    OHOS::Media::BGRAToNV12FuzzTest001();
    OHOS::Media::BGRAToNV12FuzzTest002();
    IMAGE_LOGI("RgbToYuvFuzzTest001: end");
    return 0;
}