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
#include "image_fwk_convert_yuv2rgb_fuzzer.h"

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

static const std::string IMAGE_INPUT_JPG_PATH1 = "/data/local/tmp/test.jpg";

void YuvConvertToRgb(PixelFormat &srcFormat, PixelFormat &destFormat)
{
    IMAGE_LOGI("YuvConvertToRgb: start");
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("YuvConvertToRgb: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
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

void NV21ToRGBFuzzTest001()
{
    IMAGE_LOGI("NV21ToRGBFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToRGBFuzzTest001: end");
}

void NV21ToRGBAFuzzTest001()
{
    IMAGE_LOGI("NV21ToRGBAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToRGBAFuzzTest001: end");
}

void NV21ToBGRAFuzzTest001()
{
    IMAGE_LOGI("NV21ToBGRAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToBGRAFuzzTest001: end");
}

void NV21ToRGB565FuzzTest001()
{
    IMAGE_LOGI("NV21ToRGB565FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_565;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToRGB565FuzzTest001: end");
}

void NV21ToNV12FuzzTest001()
{
    IMAGE_LOGI("NV21ToNV12FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::NV12;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToNV12FuzzTest001: end");
}

void NV12ToNV21FuzzTest001()
{
    IMAGE_LOGI("NV12ToNV21FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::NV21;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToNV21FuzzTest001: end");
}

void NV12ToRGB565FuzzTest001()
{
    IMAGE_LOGI("NV12ToRGB565FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_565;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToRGB565FuzzTest001: end");
}

void NV12ToRGBAFuzzTest001()
{
    IMAGE_LOGI("NV12ToRGBAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToRGBAFuzzTest001: end");
}

void NV12ToBGRAFuzzTest001()
{
    IMAGE_LOGI("NV12ToBGRAFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::BGRA_8888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToBGRAFuzzTest001: end");
}

void NV12ToRGBFuzzTest001()
{
    IMAGE_LOGI("NV12ToRGBFuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGB_888;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToRGBFuzzTest001: end");
}

void NV21ToNV12P010FuzzTest001()
{
    IMAGE_LOGI("NV21ToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToNV12P010FuzzTest001: end");
}

void NV12ToNV12P010FuzzTest001()
{
    IMAGE_LOGI("NV12ToNV12P010FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCBCR_P010;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToNV12P010FuzzTest001: end");
}

void NV21ToRGBAF16FuzzTest001()
{
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToRGBAF16FuzzTest001: end");
}

void NV12ToRGBAF16FuzzTest001()
{
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest001: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_F16;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToRGBAF16FuzzTest001: end");
}

void NV21ToNV21P010FuzzTest003()
{
    IMAGE_LOGI("NV21ToNV21P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToNV21P010FuzzTest003: end");
}

void NV12ToNV21P010FuzzTest003()
{
    IMAGE_LOGI("NV12ToNV21P010FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::YCRCB_P010;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToNV21P010FuzzTest003: end");
}

void NV12ToRGBA1010102FuzzTest003()
{
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV12;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV12ToRGBA1010102FuzzTest003: end");
}

void NV21ToRGBA1010102FuzzTest003()
{
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest003: start");
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_1010102;
    YuvConvertToRgb(srcFormat, destFormat);
    IMAGE_LOGI("NV21ToRGBA1010102FuzzTest003: end");
}

void YuvToRgbFuzzTest001()
{
    IMAGE_LOGI("YuvToRgbFuzzTest001: start");
    NV21ToRGBFuzzTest001();
    NV21ToRGBAFuzzTest001();
    NV21ToBGRAFuzzTest001();
    NV21ToRGB565FuzzTest001();
    NV21ToNV12FuzzTest001();
    NV12ToNV21FuzzTest001();
    NV12ToRGB565FuzzTest001();
    NV12ToRGBAFuzzTest001();
    NV12ToBGRAFuzzTest001();
    NV12ToRGBFuzzTest001();
    NV21ToNV12P010FuzzTest001();
    NV12ToNV12P010FuzzTest001();
    NV21ToRGBAF16FuzzTest001();
    NV12ToRGBAF16FuzzTest001();
    NV21ToNV21P010FuzzTest003();
    NV12ToNV21P010FuzzTest003();
    NV12ToRGBA1010102FuzzTest003();
    NV21ToRGBA1010102FuzzTest003();
    IMAGE_LOGI("YuvToRgbFuzzTest001: end");
}

/*
 * test pixelmap IPC interface
 */
bool g_pixelMapIpcTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (!pixelMap) {
        return false;
    }
    // test parcel pixelmap
    MessageParcel parcel;
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

std::unique_ptr<Media::PixelMap> GetYuvPixelMap(PixelFormat &srcFormat)
{
    IMAGE_LOGI("GetYuvPixelMap: start");
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::unique_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, opts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("GetYuvPixelMap: CreateImageSource fail");
        return nullptr;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = srcFormat;
    std::unique_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("GetYuvPixelMap: CreatePixelMap fail");
        return nullptr;
    }
    return srcPixelMap;
}

void NV21PixelMapIPCTest001()
{
    PixelFormat srcFormat = PixelFormat::NV21;
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat);
    g_pixelMapIpcTest(yuvPixelMap);
}

void NV12PixelMapIPCTest001()
{
    PixelFormat srcFormat = PixelFormat::NV12;
    std::unique_ptr<Media::PixelMap> yuvPixelMap = GetYuvPixelMap(srcFormat);
    g_pixelMapIpcTest(yuvPixelMap);
}

void YuvPixelMapIPCFuzzTest001()
{
    NV21PixelMapIPCTest001();
    NV12PixelMapIPCTest001();
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
    OHOS::Media::YuvToRgbFuzzTest001();
    OHOS::Media::YuvPixelMapIPCFuzzTest001();
    return 0;
}