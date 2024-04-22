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

#include "image_create_image_source_by_data_fuzz.h"

#include <cstdint>
#include <string>

#include "securec.h"
#include "image_source.h"
namespace OHOS {
void CreateImageSourceByDataFuzz(const uint8_t* data, size_t size)
{
    uint8_t dest[size + 1];
    int ret = memcpy_s(dest, sizeof(dest), data, size);
    if (ret != 0) {
        return;
    }
    dest[sizeof(dest) - 1] = '\0';
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imagesource = Media::ImageSource::CreateImageSource(dest, sizeof(dest), opts, errorCode);
    Media::DecodeOptions dopts;
    imagesource->CreatePixelMap(dopts, errorCode);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateImageSourceByDataFuzz(data, size);
    return 0;
}