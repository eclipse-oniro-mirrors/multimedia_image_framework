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
#include "raw_stream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "RawStream"

namespace OHOS {
namespace ImagePlugin {

RawStream::RawStream(InputDataStream &sourceStream)
{
    IMAGE_LOGD("create IN");

    inputStream_ = &sourceStream;

    IMAGE_LOGD("create OUT");
}

RawStream::~RawStream()
{
    IMAGE_LOGD("release IN");

    inputStream_ = nullptr;

    IMAGE_LOGD("release OUT");
}

// api for piex::StreamInterface
piex::Error RawStream::GetData(const size_t offset, const size_t length, uint8_t* data)
{
    if (inputStream_ == nullptr) {
        IMAGE_LOGE("GetData, InputStream is null");
        return piex::kUnsupported;
    }

    uint32_t u32Offset = static_cast<uint32_t>(offset);
    uint32_t u32Length = static_cast<uint32_t>(length);

    if (inputStream_->Tell() != u32Offset) {
        if (!inputStream_->Seek(u32Offset)) {
            IMAGE_LOGE("GetData, seek fail");
            return piex::kFail;
        }

        if (inputStream_->Tell() != u32Offset) {
            IMAGE_LOGE("GetData, seeked fail");
            return piex::kFail;
        }
    }

    uint32_t readSize = 0;
    if (!inputStream_->Read(u32Length, data, u32Length, readSize)) {
        IMAGE_LOGE("GetData, read fail");
        return piex::kFail;
    }

    if (readSize != u32Length) {
        IMAGE_LOGE("GetData, read want:%{public}u, real:%{public}u", u32Length, readSize);
        return piex::kFail;
    }

    return piex::kOk;
}
} // namespace ImagePlugin
} // namespace OHOS
