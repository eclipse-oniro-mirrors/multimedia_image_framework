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

#include "image_heifs_metadata_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "common_fuzztest_function.h"
#include "kv_metadata.h"
#include "heifs_metadata.h"
#include "media_errors.h"
#include "image_type.h"
#include "securec.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

void SetBlobFuzzTest001(const uint8_t *data, size_t size)
{
    HeifsMetadata metadata;
    metadata.SetBlob(data, size);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(size);
    if (dst) {
        metadata.GetBlob(size, dst.get());
        metadata.GetBlobPtr();
        metadata.GetBlobSize();
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::SetBlobFuzzTest001(data, size);
    return 0;
}