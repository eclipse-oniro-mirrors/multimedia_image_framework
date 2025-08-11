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

#include "image_fwk_decode_jpeg_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "svg_decoder.h"
#include "bmp_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_JPEG_FUZZ"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
constexpr uint32_t OPT_SIZE = 40;
constexpr uint32_t PIXELFORMAT_MODULO = 3;

using namespace OHOS::ImagePlugin;
void JpegTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    std::vector<PixelFormat> formats = {PixelFormat::NV21, PixelFormat::NV12, PixelFormat::RGBA_8888};
    uint8_t index = FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO;
    decodeOpts.desiredPixelFormat = formats[index];
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    PixelMapTest001(pixelMap.get());
    PixelMapTest002(pixelMap.get());
    PixelYuvTest001(pixelMap.get());
    PixelYuvTest002(pixelMap.get());
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (size < OHOS::Media::OPT_SIZE) {
        return -1;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string pathName = "/data/local/tmp/test_decode_jpg.jpg";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, pathName);
    OHOS::Media::JpegTest001(pathName);
    return 0;
}