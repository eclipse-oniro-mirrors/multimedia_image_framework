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
#include "image_fuzzer.h"
#include "native_image.h"

namespace OHOS {
namespace Media {

static constexpr uint32_t OPT_SIZE = 80;
FuzzedDataProvider* FDP;

/*
 * test image get functions
 */
void ImageGetFunctionsFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    std::unique_ptr<OHOS::Media::NativeImage> image = std::make_unique<OHOS::Media::NativeImage>(buffer, releaser);
    int32_t colorSpace = FDP->ConsumeIntegral<int32_t>();
    image->GetColorSpace(colorSpace);
    image->GetBufferData();
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <  OHOS::Media::OPT_SIZE) {
        return -1;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::ImageGetFunctionsFuzzTest();
    return 0;
}