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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_fwk_decode_gif_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

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
#define LOG_TAG "IMAGE_FWK_DECODE_GIF_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

constexpr uint32_t OPT_SIZE = 40;
constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;

void GifTest001(const std::string& pathName)
{
    Media::SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr.", __func__);
        return;
    }

    for (uint32_t index = 0; index < imageSource->GetFrameCount(errorCode); ++index) {
        DecodeOptions decodeOpts;
        SetFdpDecodeOptions(FDP, decodeOpts);
        auto pixelMap = imageSource->CreatePixelMapEx(index, decodeOpts, errorCode);
        IMAGE_LOGI("%{public}s gif decode SUCCESS", __func__);
    }
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
    static const std::string pathName = "/data/local/tmp/test_decode_gif.gif";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, pathName);
    OHOS::Media::GifTest001(pathName);
    return 0;
}