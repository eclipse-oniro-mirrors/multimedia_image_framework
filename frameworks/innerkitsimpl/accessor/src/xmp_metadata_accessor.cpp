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

#include "buffer_metadata_stream.h"
#include "image_log.h"
#include "media_errors.h"
#include "xmp_buffer_IO.h"
#include "xmp_metadata_accessor.h"
#include "xmp_metadata_impl.h"

namespace OHOS {
namespace Media {
static constexpr XMP_OptionBits ConvertAccessModeToXMPOptions(XMPAccessMode mode)
{
    switch (mode) {
        case XMPAccessMode::READ_ONLY_XMP:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP;
        case XMPAccessMode::READ_FULL_METADATA:
            return kXMPFiles_OpenForRead;
        case XMPAccessMode::READ_WRITE_XMP:
            return kXMPFiles_OpenForUpdate | kXMPFiles_OpenOnlyXMP;
        case XMPAccessMode::READ_WRITE_XMP_OPTIMIZED:
            return kXMPFiles_OpenForUpdate | kXMPFiles_OptimizeFileLayout;
        default:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP;
    }
}

XMPMetadataAccessor::XMPMetadataAccessor(std::shared_ptr<MetadataStream> &stream, XMPAccessMode mode)
    : imageStream_(stream), accessMode_(mode)
{
    CHECK_ERROR_RETURN_LOG(!XMPMetadata::Initialize(), "%{public}s failed to init XMPMetadataAccessor", __func__);
    CHECK_ERROR_RETURN_LOG(imageStream_ == nullptr, "%{public}s imageStream is nullptr", __func__);
    InitializeFromStream();
}

uint32_t XMPMetadataAccessor::Read()
{
    uint32_t status = CheckXMPFiles();
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, status, "%{public}s failed to check XMPFiles", __func__);

    auto impl = std::make_unique<XMPMetadataImpl>();
    CHECK_ERROR_RETURN_RET_LOG(!impl || !impl->IsValid(), ERR_MEDIA_MALLOC_FAILED,
        "%{public}s XMPMetadataImpl is invalid", __func__);
    if (!xmpFiles_->GetXMP(impl->GetRawPtr())) {
        IMAGE_LOGE("%{public}s GetXMP failed", __func__);
        return ERR_XMP_DECODE_FAILED;
    }

    xmpMetadata_ = std::make_shared<XMPMetadata>(std::move(impl));
    IMAGE_LOGD("%{public}s successfully read XMPMetadata", __func__);
    return SUCCESS;
}

uint32_t XMPMetadataAccessor::Write()
{
    uint32_t status = CheckXMPFiles();
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, status, "%{public}s failed to check XMPFiles", __func__);
    CHECK_ERROR_RETURN_RET_LOG(xmpMetadata_ == nullptr, ERR_MEDIA_NULL_POINTER,
        "%{public}s xmpMetadata is nullptr", __func__);

    std::unique_ptr<XMPMetadataImpl> &impl = xmpMetadata_->GetImpl();
    CHECK_ERROR_RETURN_RET_LOG(!impl || !impl->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s XMPMetadataImpl is invalid", __func__);

    SXMPMeta &meta = impl->GetMeta();
    CHECK_ERROR_RETURN_RET_LOG(!xmpFiles_->CanPutXMP(meta), ERR_MEDIA_INVALID_OPERATION,
        "%{public}s CanPutXMP failed", __func__);

    xmpFiles_->PutXMP(meta);
    xmpFiles_->CloseFile();  // This updates the XMPBuffer_IO's internal buffer

    // Write back to file
    CHECK_ERROR_RETURN_RET_LOG(bufferIO_ == nullptr, ERR_MEDIA_NULL_POINTER,
        "%{public}s bufferIO is nullptr", __func__);
    return UpdateData(static_cast<const uint8_t*>(bufferIO_->GetDataPtr()), bufferIO_->GetDataSize());
}

std::shared_ptr<XMPMetadata> XMPMetadataAccessor::Get()
{
    return xmpMetadata_;
}

void XMPMetadataAccessor::Set(std::shared_ptr<XMPMetadata> &xmpMetadata)
{
    xmpMetadata_ = xmpMetadata;
}

uint32_t XMPMetadataAccessor::CheckXMPFiles()
{
    CHECK_ERROR_RETURN_RET_LOG(!XMPMetadata::Initialize(), ERR_XMP_INIT_FAILED,
        "%{public}s failed to init XMPMetadataAccessor", __func__);

    if (xmpFiles_ == nullptr) {
        IMAGE_LOGE("%{public}s xmpFiles is nullptr", __func__);
        return ERR_XMP_INVALID_FILE;
    }

    if (!xmpFiles_->GetFileInfo()) {
        IMAGE_LOGE("%{public}s xmpFiles is not open", __func__);
        return ERR_XMP_INVALID_FILE;
    }
    return SUCCESS;
}

void XMPMetadataAccessor::InitializeFromStream()
{
    CHECK_ERROR_RETURN_LOG(imageStream_ == nullptr || !imageStream_->IsOpen(),
        "%{public}s failed, image stream is invalid", __func__);

    imageStream_->Seek(0, SeekPos::BEGIN);
    ssize_t streamSize = imageStream_->GetSize();
    CHECK_ERROR_RETURN_LOG(streamSize <= 0, "%{public}s failed, stream size is invalid", __func__);

    // Read data from stream
    std::vector<uint8_t> buffer(streamSize);
    ssize_t readSize = imageStream_->Read(buffer.data(), streamSize);
    CHECK_ERROR_RETURN_LOG(readSize != streamSize, "%{public}s failed to read from stream", __func__);

    // Determine if writable based on access mode
    bool isWritable = (accessMode_ == XMPAccessMode::READ_WRITE_XMP || 
                      accessMode_ == XMPAccessMode::READ_WRITE_XMP_OPTIMIZED);

    // Create XMPBuffer_IO and open with XMP SDK
    bufferIO_ = std::make_shared<XMPBuffer_IO>(buffer.data(), static_cast<XMP_Uns32>(streamSize), isWritable);
    xmpFiles_.reset(new SXMPFiles());

    XMP_OptionBits openFlags = ConvertAccessModeToXMPOptions(accessMode_);
    if (!xmpFiles_->OpenFile(bufferIO_.get(), kXMP_UnknownFile, openFlags)) {
        IMAGE_LOGE("%{public}s failed to open file with XMPBuffer_IO", __func__);
        xmpFiles_ = nullptr;
        bufferIO_ = nullptr;
    }
}

uint32_t XMPMetadataAccessor::UpdateData(const uint8_t *dataBlob, uint32_t size)
{
    CHECK_ERROR_RETURN_RET_LOG(imageStream_ == nullptr || !imageStream_->IsOpen(), ERR_IMAGE_SOURCE_DATA,
        "%{public}s imageStream is invalid", __func__);

    // Create temporary buffer stream with modified data
    BufferMetadataStream tmpBufStream(const_cast<uint8_t*>(dataBlob), size, BufferMetadataStream::MemoryMode::Fix);
    CHECK_ERROR_RETURN_RET_LOG(!tmpBufStream.Open(OpenMode::ReadWrite), ERR_IMAGE_SOURCE_DATA,
        "%{public}s BufferMetadataStream::Open failed", __func__);

    // Write back to original stream
    imageStream_->Seek(0, SeekPos::BEGIN);
    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->CopyFrom(tmpBufStream), ERR_MEDIA_INVALID_OPERATION,
        "%{public}s Copy from temp stream failed", __func__);

    IMAGE_LOGD("%{public}s successfully updated XMP data, size: %{public}u", __func__, size);
    return SUCCESS;
}
} // namespace OHOS
} // namespace Media
