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
#include "include/core/SkImage.h"
#include "media_errors.h"

#include "dng_area_task.h"
#include "dng_errors.h"
#include "dng_host.h"
#include "dng_pixel_buffer.h"
#include "dng_read_image.h"
#include "dng_stream.h"
#include "dng_tag_types.h"

namespace OHOS {
namespace Media {

constexpr uint32_t BYTES_SIZE = 8;
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

class DngSdkNegative : public dng_negative {
public:
    explicit DngSdkNegative(dng_host& host) : dng_negative(host) {}

    virtual ~DngSdkNegative() {}
};

class DngSdkHost : public dng_host {
public:
    explicit DngSdkHost() : dng_host() {}

    ~DngSdkHost() {}

    dng_negative* Make_dng_negative () override
    {
        auto dngNegative = new DngSdkNegative(*this);
        return dngNegative;
    }
};

static bool ReadDngInfo(dng_stream& stream, dng_host& host, dng_info* info) __attribute__((no_sanitize("cfi")))
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

static std::unique_ptr<dng_negative> SyncDngNegative(dng_stream& stream, dng_host& host, dng_info& info)
    __attribute__((no_sanitize("cfi")))
{
    CHECK_ERROR_RETURN_RET(stream.Length() == 0, nullptr);
    std::unique_ptr<dng_negative> negative;
    negative.reset(host.Make_dng_negative());
    CHECK_ERROR_RETURN_RET(negative == nullptr, nullptr);
    host.ValidateSizes();
    negative->Parse(host, stream, info);
    negative->PostParse(host, stream, info);
    negative->SynchronizeMetadata();
    return negative;
}

static const dng_image* ReadRawStage1(dng_stream& stream, dng_host& host, dng_info& info,
    std::unique_ptr<dng_negative>& negative) __attribute__((no_sanitize("cfi")))
{
    try {
        negative = SyncDngNegative(stream, host, info);
        CHECK_ERROR_RETURN_RET_LOG(negative == nullptr, nullptr, "SyncDngNegative failed");
        negative->ReadStage1Image(host, stream, info);
        negative->ValidateRawImageDigest(host);
        CHECK_ERROR_RETURN_RET_LOG(negative->IsDamaged(), nullptr, "Dng negative is damaged");
        const dng_image* stage1Image = negative->Stage1Image();
        return stage1Image;
    }
    catch (...) {
        IMAGE_LOGE("DNG SDK exception caught in ReadRawStage1");
        return nullptr;
    }
}

uint32_t DngSdkHelper::GetImageRawData(ImagePlugin::InputDataStream* stream, std::vector<uint8_t>& data,
    uint32_t& bitsPerSample)
{
    try {
        DngSdkInputDataStream dngStream(stream);
        DngSdkHost dngHost;
        dng_info dngInfo;
        if (!ReadDngInfo(dngStream, dngHost, &dngInfo)) {
            return ERR_IMAGE_GET_DATA_ABNORMAL;
        }
        std::unique_ptr<dng_negative> negative = nullptr;
        const dng_image* image = ReadRawStage1(dngStream, dngHost, dngInfo, negative);
        CHECK_ERROR_RETURN_RET(image == nullptr, ERR_IMAGE_GET_DATA_ABNORMAL);
        uint32_t width = image->Width();
        uint32_t height = image->Height();
        uint32_t planes = image->Planes();
        uint32_t pixelType = image->PixelType();
        uint32_t bytesPerSample = TagTypeSize(pixelType);
        CHECK_ERROR_RETURN_RET(ImageUtils::CheckMulOverflow(width, height, bytesPerSample), ERR_IMAGE_DATA_UNSUPPORT);
        auto tmpSize = width * height * bytesPerSample;
        CHECK_ERROR_RETURN_RET(ImageUtils::CheckMulOverflow(tmpSize, planes), ERR_IMAGE_DATA_UNSUPPORT);
        auto totalBytes = tmpSize * planes;
        CHECK_ERROR_RETURN_RET(SkImageInfo::ByteSizeOverflowed(totalBytes), ERR_IMAGE_DATA_UNSUPPORT);
        IMAGE_LOGD("Dng image info: width=%{public}u, height=%{public}u, planes=%{public}u, "
            "pixelType=%{public}u, bytesPerSample=%{public}u, totalBytes=%{public}zu",
            width, height, planes, pixelType, bytesPerSample, totalBytes);
        CHECK_ERROR_RETURN_RET(bytesPerSample == 0 || planes != 1, ERR_IMAGE_DATA_UNSUPPORT);
        data.clear();
        data.resize(totalBytes);
        bitsPerSample = bytesPerSample * BYTES_SIZE;
        dng_pixel_buffer buffer;
        buffer.fPlane = 0;
        buffer.fPlanes = 1;
        buffer.fColStep = 1;
        buffer.fPlaneStep = 1;
        buffer.fPixelType = pixelType;
        buffer.fPixelSize = bytesPerSample;
        if (width <= static_cast<uint32_t>(std::numeric_limits<int>::max())) {
            buffer.fRowStep = static_cast<int>(width);
        } else {
            return ERR_IMAGE_GET_DATA_ABNORMAL;
        }
        buffer.fData = data.data();
        buffer.fArea = image->Bounds();
        image->Get(buffer, dng_image::edge_zero);
        IMAGE_LOGD("DNG image raw data extracted successfully");
        return SUCCESS;
    } catch (...) {
        IMAGE_LOGE("DNG SDK exception caught in GetImageRawData - ReadDngInfo");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
}
} // namespace Media
} // namespace OHOS