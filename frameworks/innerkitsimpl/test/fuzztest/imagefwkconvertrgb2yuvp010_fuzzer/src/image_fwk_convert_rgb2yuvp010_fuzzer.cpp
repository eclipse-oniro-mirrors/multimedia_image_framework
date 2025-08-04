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
#include "image_fwk_convert_rgb2yuvp010_fuzzer.h"

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

void RgbConvertToYuvP010(PixelFormat &srcFormat, PixelFormat &destFormat)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
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

void RGB565ToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGB565ToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV12P010FuzzTest001: end");
}

void RGB565ToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGB565ToNV12P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV12P010FuzzTest002: end");
}

void RGB565ToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGB565ToNV21P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV21P010FuzzTest001: end");
}

void RGB565ToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGB565ToNV21P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("RGB565ToNV21P010FuzzTest002: end");
}

void BGRAToNV12P010FuzzTest001()
{
    IMAGE_LOGI("BGRAToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV12P010FuzzTest001: end");
}

void BGRAToNV12P010FuzzTest002()
{
    IMAGE_LOGI("BGRAToNV12P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV12P010FuzzTest002: end");
}

void BGRAToNV21P010FuzzTest001()
{
    IMAGE_LOGI("BGRAToNV21P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV21P010FuzzTest001: end");
}

void BGRAToNV21P010FuzzTest002()
{
    IMAGE_LOGI("BGRAToNV21P010FuzzTest002: start");
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010(srcFormat, destFormat);
    IMAGE_LOGI("BGRAToNV21P010FuzzTest002: end");
}

void RgbConvertToYuvP010ByPixelMap(PixelFormat &tempFormat, PixelFormat &srcFormat,
    PixelFormat &destFormat)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    auto rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("RgbConvertToYuvP010ByPixelMap: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = tempFormat;
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

void RGBAToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBAToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAToNV12P010FuzzTest001: end");
}

void RGBAToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBAToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAToNV12P010FuzzTest002: end");
}

void RGBAToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBAToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAToNV21P010FuzzTest001: end");
}

void RGBAToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBAToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_8888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAToNV21P010FuzzTest002: end");
}

void RGBToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBToNV12P010FuzzTest001: end");
}

void RGBToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBToNV12P010FuzzTest002: end");
}

void RGBToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBToNV21P010FuzzTest001: end");
}

void RGBToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGB_888;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBToNV21P010FuzzTest002: end");
}

void RGBAF16ToNV12P010FuzzTest001()
{
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest001: end");
}

void RGBAF16ToNV12P010FuzzTest002()
{
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV12;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAF16ToNV12P010FuzzTest002: end");
}

void RGBAF16ToNV21P010FuzzTest001()
{
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest001: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest001: end");
}

void RGBAF16ToNV21P010FuzzTest002()
{
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest002: start");
    PixelFormat tempFormat = PixelFormat::NV21;
    PixelFormat srcFormat = PixelFormat::RGBA_F16;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    RgbConvertToYuvP010ByPixelMap(tempFormat, srcFormat, destFormat);
    IMAGE_LOGI("RGBAF16ToNV21P010FuzzTest002: end");
}


void RgbToYuvP010FuzzTest001()
{
    IMAGE_LOGI("YuvP010ToRgbTest001: start");
    RGB565ToNV12P010FuzzTest001();
    RGB565ToNV12P010FuzzTest002();
    RGB565ToNV21P010FuzzTest001();
    RGB565ToNV21P010FuzzTest002();
    BGRAToNV12P010FuzzTest001();
    BGRAToNV12P010FuzzTest002();
    BGRAToNV21P010FuzzTest001();
    BGRAToNV21P010FuzzTest002();
    IMAGE_LOGI("YuvP010ToRgbTest001: end");
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
    OHOS::Media::RgbToYuvP010FuzzTest001();
    OHOS::Media::RgbToYuvP010ByPixelMapFuzzTest001();
    return 0;
}