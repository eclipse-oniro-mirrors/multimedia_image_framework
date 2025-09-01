/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "metadata.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "Metadata"

namespace OHOS {
namespace Media {

uint32_t ImageMetadata::GetBlob(uint32_t bufferSize, uint8_t *dst)
{
    (void)dst;
    (void)bufferSize;
    return ERR_MEDIA_INVALID_OPERATION;
}

uint32_t ImageMetadata::SetBlob(const uint8_t *source, const uint32_t bufferSize)
{
    (void)source;
    (void)bufferSize;
    return ERR_MEDIA_INVALID_OPERATION;
}

uint32_t ImageMetadata::GetBlobSize()
{
    return 0;
};

uint8_t* ImageMetadata::GetBlobPtr()
{
    return nullptr;
}
} // namespace Media
} // namespace OHOS