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

#include "image_fwk_region_decode_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_REGION_DECODE_FUZZ"

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;
using namespace OHOS::ImagePlugin;
void RegionDecodeTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    decodeOpts.cropAndScaleStrategy = static_cast<CropAndScaleStrategy>(FDP->ConsumeIntegral<uint8_t>() % 3);
    imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    const std::string pathName = "/data/local/tmp/test_region_decode_jpg.jpg";
    WriteDataToFile(data, size, pathName);
    OHOS::Media::RegionDecodeTest001(pathName);
    return 0;
}