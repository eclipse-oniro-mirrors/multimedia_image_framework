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

#include "ext_stream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtStream"

namespace {
    constexpr static size_t SIZE_ZERO = 0;
}
namespace OHOS {
namespace ImagePlugin {
struct InputStream {
    uint8_t* buf;
    uint32_t size;
    uint32_t resSize;
};

ExtStream::ExtStream(InputDataStream *stream) : stream_(stream)
{
}

static void InputStreamInit(InputStream &buf, uint8_t *input, size_t size)
{
    buf.buf = input;
    buf.size = static_cast<uint32_t>(size);
    buf.resSize = static_cast<uint32_t>(size);
}

static size_t Skip(InputDataStream *stream, size_t size)
{
    if (stream == nullptr) {
        return SIZE_ZERO;
    }
    uint32_t cur = stream->Tell();
    uint32_t seek = cur + static_cast<uint32_t>(size);
    if (!stream->Seek(seek)) {
        IMAGE_LOGE("skip failed, curpositon, skip size.");
        return SIZE_ZERO;
    }
    return size;
}

size_t ExtStream::read(void *buffer, size_t size)
{
    if (stream_ == nullptr) {
        return SIZE_ZERO;
    }
    if (buffer == nullptr) {
        return Skip(stream_, size);
    }
    InputStream buf;
    InputStreamInit(buf, static_cast<uint8_t *>(buffer), size);
    
    uint32_t desiredSize = buf.size;
    if (stream_->GetStreamSize() != SIZE_ZERO && stream_->GetStreamSize() < desiredSize) {
        desiredSize = stream_->GetStreamSize();
    }
    if (!stream_->Read(desiredSize, buf.buf, buf.size, buf.resSize)) {
        IMAGE_LOGE("read failed, desire read size=%{public}u", buf.resSize);
        return 0;
    }
    return static_cast<size_t>(buf.resSize);
}

size_t ExtStream::peek(void *buffer, size_t size) const
{
    if (stream_ == nullptr) {
        return SIZE_ZERO;
    }
    if (buffer == nullptr) {
        IMAGE_LOGE("peek failed, output buffer is null");
        return SIZE_ZERO;
    }
    InputStream buf;
    InputStreamInit(buf, static_cast<uint8_t *>(buffer), size);
    if (!stream_->Peek(buf.size, buf.buf, buf.size, buf.resSize)) {
        IMAGE_LOGE("peek failed, desire read size=%{public}u", buf.resSize);
        return 0;
    }
    return static_cast<size_t>(buf.resSize);
}

bool ExtStream::isAtEnd() const
{
    if (stream_ == nullptr) {
        return true;
    }
    size_t size = stream_->GetStreamSize();
    return (stream_->Tell() == size);
}

size_t ExtStream::getLength() const
{
    return stream_ == nullptr ? 0 : stream_->GetStreamSize();
}
} // namespace ImagePlugin
} // namespace OHOS
