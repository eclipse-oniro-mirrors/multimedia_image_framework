/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "buffer_packer_stream.h"

#include "image_log.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "BufferPackerStream"

namespace OHOS {
namespace Media {

BufferPackerStream::BufferPackerStream(uint8_t *outputData, uint32_t maxSize)
    : outputData_(outputData), maxSize_(maxSize)
{}

bool BufferPackerStream::Write(const uint8_t *buffer, uint32_t size)
{
    if ((buffer == nullptr) || (size == 0)) {
        IMAGE_LOGE("input parameter invalid.");
        return false;
    }
    if (outputData_ == nullptr) {
        IMAGE_LOGE("output stream is null.");
        return false;
    }
    uint32_t leftSize = maxSize_ - offset_;
    if (size > leftSize) {
        IMAGE_LOGE("write data:[%{public}lld] out of max size:[%{public}u].",
            static_cast<long long>(size + offset_), maxSize_);
        return false;
    }
    if (memcpy_s(outputData_ + offset_, leftSize, buffer, size) != EOK) {
        IMAGE_LOGE("memory copy failed.");
        return false;
    }
    offset_ += size;
    return true;
}

int64_t BufferPackerStream::BytesWritten()
{
    return offset_;
}

bool BufferPackerStream::GetCapicity(size_t &size)
{
    size = maxSize_;
    return true;
}
} // namespace Media
} // namespace OHOS
