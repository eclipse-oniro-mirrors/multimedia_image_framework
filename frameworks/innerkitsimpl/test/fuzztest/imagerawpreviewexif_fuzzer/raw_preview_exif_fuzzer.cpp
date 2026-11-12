/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <string>

#include "image_source.h"
#include "media_errors.h"
#include "metadata_accessor_factory.h"

namespace {
constexpr size_t MAX_INPUT_SIZE = 300 * 1024 * 1024;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0 || size > MAX_INPUT_SIZE) {
        return 0;
    }
    OHOS::Media::SourceOptions options;
    uint32_t error = OHOS::Media::SUCCESS;
    auto source = OHOS::Media::ImageSource::CreateImageSource(data, static_cast<uint32_t>(size), options, error);
    if (source != nullptr) {
        std::string orientation;
        (void)source->GetRawPreviewOrientation(orientation);
    }
    OHOS::Media::DataInfo dataInfo { const_cast<uint8_t *>(data), static_cast<uint32_t>(size) };
    std::string orientation;
    (void)OHOS::Media::MetadataAccessorFactory::GetRawPreviewOrientation(dataInfo, orientation);
    return 0;
}
