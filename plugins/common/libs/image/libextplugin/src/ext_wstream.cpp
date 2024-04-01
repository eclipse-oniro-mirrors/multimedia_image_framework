/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ext_wstream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtWStream"

namespace {
    constexpr static size_t SIZE_ZERO = 0;
}
namespace OHOS {
namespace ImagePlugin {

ExtWStream::ExtWStream(OutputDataStream *stream) : stream_(stream)
{
}

bool ExtWStream::write(const void* buffer, size_t size) __attribute__((no_sanitize("cfi")))
{
    if (stream_ == nullptr) {
        IMAGE_LOGE("ExtWStream::write stream is nullptr");
        return false;
    }
    return stream_->Write(static_cast<const uint8_t*>(buffer), size);
}

void ExtWStream::flush()
{
    if (stream_ == nullptr) {
        IMAGE_LOGE("ExtWStream::flush stream is nullptr");
        return;
    }
    stream_->Flush();
}

size_t ExtWStream::bytesWritten() const
{
    if (stream_ == nullptr) {
        IMAGE_LOGE("ExtWStream::bytesWritten stream is nullptr");
        return SIZE_ZERO;
    }
    size_t written = SIZE_ZERO;
    stream_->GetCurrentSize(written);
    return written;
}

bool MetadataWStream::write(const void *buffer, size_t size)
{
    OHOS::Media::byte* bytePtr = reinterpret_cast<OHOS::Media::byte*>(const_cast<void*>(buffer));
    if (stream_->Write(bytePtr, size) !=0) {
        return true;
    }
    return false;
}

size_t MetadataWStream::bytesWritten() const
{
    return stream_->GetSize();
}

uint8_t* MetadataWStream::GetAddr()
{
    return stream_->GetAddr();
}

} // namespace ImagePlugin
} // namespace OHOS
