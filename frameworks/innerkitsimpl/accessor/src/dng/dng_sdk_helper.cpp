/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "dng/dng_sdk_helper.h"

#include <limits>

#include "dng/dng_exif_metadata.h"
#include "dng/dng_sdk_info.h"
#include "image_log.h"
#include "media_errors.h"

#include "dng_area_task.h"
#include "dng_errors.h"
#include "dng_host.h"
#include "dng_stream.h"

namespace OHOS {
namespace Media {

class DngSdkInputDataStream : public dng_stream {
public:
    explicit DngSdkInputDataStream(ImagePlugin::InputDataStream* stream)
        : dng_stream((dng_abort_sniffer*) nullptr, dng_stream::kDefaultBufferSize, 0), stream_(stream) {}

    ~DngSdkInputDataStream()
    {
        stream_ = nullptr;
    }

protected:
    uint64_t DoGetLength() override
    {
        return stream_ ? stream_->GetStreamSize() : 0;
    }

    void DoRead(void* data, uint32_t count, uint64_t offset) override
    {
        if (!data) {
            ThrowReadFile();
            return;
        }
        if (offset > std::numeric_limits<uint32_t>::max()) {
            ThrowReadFile();
            return;
        }
        if (!stream_ || !stream_->Seek(static_cast<uint32_t>(offset))) {
            ThrowReadFile();
            return;
        }
        uint32_t readSize = 0;
        if (!stream_->Read(count, static_cast<uint8_t*>(data), count, readSize) || readSize != count) {
            ThrowReadFile();
            return;
        }
    }

private:
    ImagePlugin::InputDataStream* stream_;
};

class DngSdkMetadataStream : public dng_stream {
public:
    explicit DngSdkMetadataStream(std::shared_ptr<MetadataStream>& stream)
        : dng_stream((dng_abort_sniffer*) nullptr, dng_stream::kDefaultBufferSize, 0), stream_(stream) {}

    ~DngSdkMetadataStream() {}

protected:
    uint64_t DoGetLength() override
    {
        return stream_ ? stream_->GetSize() : 0;
    }

    void DoRead(void* data, uint32_t count, uint64_t offset) override
    {
        if (!data) {
            ThrowReadFile();
            return;
        }
        if (offset > std::numeric_limits<long>::max()) {
            ThrowReadFile();
            return;
        }
        if (!stream_ || stream_->Seek(static_cast<long>(offset), SeekPos::BEGIN) < 0) {
            ThrowReadFile();
            return;
        }
        ssize_t readSize = stream_->Read(static_cast<uint8_t*>(data), count);
        if (readSize < 0 || static_cast<uint32_t>(readSize) != count) {
            ThrowReadFile();
            return;
        }
    }

private:
    std::shared_ptr<MetadataStream> stream_;
};

class DngSdkHost : public dng_host {
public:
    explicit DngSdkHost() : dng_host() {}

    ~DngSdkHost() {}

    void PerformAreaTask(dng_area_task& task, const dng_rect& area) override
    {
        task.Start(1, area.Size(), &Allocator(), Sniffer());
        task.ProcessOnThread(0, area, area.Size(), this->Sniffer());
        task.Finish(1);
    }

    uint32 PerformAreaTaskThreads() override
    {
        return 1;
    }
};

static bool ReadDngInfo(dng_stream& stream, dng_host& host, dng_info* info)
{
    if (stream.Length() == 0 || info == nullptr) {
        return false;
    }

    host.ValidateSizes();
    info->Parse(host, stream);
    info->PostParse(host);
    if (!info->IsValidDNG()) {
        return false;
    }
    return true;
}

std::unique_ptr<DngSdkInfo> DngSdkHelper::ParseInfoFromStream(std::shared_ptr<MetadataStream>& stream)
{
    try {
        DngSdkMetadataStream dngStream(stream);
        DngSdkHost dngHost;
        std::unique_ptr<DngSdkInfo> dngInfo = std::make_unique<DngSdkInfo>();
        if (!ReadDngInfo(dngStream, dngHost, dngInfo.get())) {
            return nullptr;
        }
        return dngInfo;
    } catch (...) {
        IMAGE_LOGE("DNG SDK exception caught in ParseInfoFromStream");
        return nullptr;
    }
}

static uint32_t GetPropertyByOptions(const std::unique_ptr<DngSdkInfo>& info, MetadataValue& value,
    const std::vector<DngPropertyOption>& options)
{
    CHECK_ERROR_RETURN_RET_LOG(info == nullptr, ERR_IMAGE_GET_DATA_ABNORMAL,
        "[%{public}s] DngSdkInfo is nullptr", __func__);
    for (auto const& option : options) {
        if (info->GetProperty(value, option) == SUCCESS) {
            return SUCCESS;
        }
    }
    return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
}

static uint32_t SetPropertyByOptions(const std::unique_ptr<DngSdkInfo>& info, const MetadataValue& value,
    const std::vector<DngPropertyOption>& options)
{
    CHECK_ERROR_RETURN_RET(info == nullptr, ERR_IMAGE_GET_DATA_ABNORMAL);
    for (auto const& option : options) {
        if (info->SetProperty(value, option) == SUCCESS) {
            return SUCCESS;
        }
    }
    return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
}

static std::vector<DngPropertyOption> GetExifPropertyOptions(uint32_t mainIndex)
{
    return {
        {DngMetaSourceType::SUB_PREVIEW_IFD, mainIndex},
        {DngMetaSourceType::SUB_PREVIEW_IFD, 0},
        {DngMetaSourceType::EXIF, 0},
        {DngMetaSourceType::SHARED, 0},
        {DngMetaSourceType::CHAINED_IFD, 0},
    };
}

uint32_t DngSdkHelper::GetExifProperty(const std::unique_ptr<DngSdkInfo>& info, MetadataValue& value)
{
    try {
        CHECK_ERROR_RETURN_RET(info == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
        return GetPropertyByOptions(info, value, GetExifPropertyOptions(info->fMainIndex));
    } catch (...) {
        IMAGE_LOGE("Failed to get value %{public}s", value.key.c_str());
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
}

uint32_t DngSdkHelper::SetExifProperty(const std::unique_ptr<DngSdkInfo>& info, const MetadataValue& value)
{
    CHECK_ERROR_RETURN_RET(info == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    return SetPropertyByOptions(info, value, GetExifPropertyOptions(info->fMainIndex));
}
} // namespace Media
} // namespace OHOS