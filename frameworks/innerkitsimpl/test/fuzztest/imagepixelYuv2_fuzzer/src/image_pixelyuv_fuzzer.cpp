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

#include "image_pixelyuv_fuzzer.h"
#include "common_fuzztest_function.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "pixel_map.h"

#include "image_log.h"
#include "image_source.h"

namespace OHOS {
namespace Media {

FuzzedDataProvider* FDP;

void PixelMapYuvFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }

    float degrees = FDP->ConsumeFloatingPoint<float>();
    pixelMap->rotate(degrees);

    float dstWidth = FDP->ConsumeFloatingPoint<float>();
    float dstHeight = FDP->ConsumeFloatingPoint<float>();
    AntiAliasingOption option = static_cast<AntiAliasingOption>(FDP->ConsumeIntegral<uint8_t>() % 11);
    pixelMap->scale(dstWidth, dstHeight, option);
}

}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    OHOS::Media::PixelMapYuvFuzzTest(data, size);
    return 0;
}
