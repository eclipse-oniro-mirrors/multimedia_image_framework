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

#include "imageframework_fuzzer.h"

#include <cstdint>
#include <string>

#include "image_source.h"
#include "pixel_map.h"
namespace OHOS {
void BatchInsertFuzzer(const uint8_t* data, size_t size)
{
    uint32_t errCode = 0;
    Media::SourceOptions opts;
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(data, size, opts, errCode);
    const int32_t offset = 0;
    Media::InitializationOptions iopts;
    Media::PixelMap::Create((uint32_t*)data, size, iopts);
    Media::PixelMap::Create((uint32_t*)data, size, offset, 0, iopts);
    Media::PixelMap::Create((uint32_t*)data, size, offset, 0, iopts, true);
    Media::BUILD_PARAM bp;
    bp.offset_ = 0;
    bp.stride_ = 0;
    bp.flag_ = true;
    int err = 0;
    Media::PixelMap::Create((uint32_t*)data, size, bp, iopts, err);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::BatchInsertFuzzer(data, size);
    return 0;
}