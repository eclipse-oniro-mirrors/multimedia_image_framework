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

#include "image_log.h"
#include "media_errors.h"
#include "XMPBuffer_IO.hpp"
#include "XMPFd_IO.hpp"
#include "xmp_metadata_accessor.h"
#include "xmp_metadata_impl.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadataAccessor"

namespace {
    constexpr int32_t INVALID_FILE_DESCRIPTOR = -1;
}

namespace OHOS {
namespace Media {
std::atomic<int32_t> XMPMetadataAccessor::refCount_{0};
std::mutex XMPMetadataAccessor::initMutex_;

XMPMetadataAccessor::XMPMetadataAccessor()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    if (refCount_.load() == 0) {
        XMP_TRY();
        bool initOk = SXMPFiles::Initialize(kXMPFiles_IgnoreLocalText);
        CHECK_ERROR_RETURN_LOG(!initOk, "%{public}s failed to initialize XMPFiles", __func__);
        XMP_CATCH_NO_RETURN();
    }

    ++refCount_;
    isRefCounted_ = true;
}

XMPMetadataAccessor::~XMPMetadataAccessor()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    CHECK_ERROR_RETURN_LOG(!isRefCounted_, "%{public}s not ref counted! Maybe initialization failed.", __func__);

    if (--refCount_ == 0) {
        XMP_TRY();
        SXMPFiles::Terminate();
        XMP_CATCH_NO_RETURN();
    }
}

static constexpr XMP_OptionBits ConvertAccessModeToXMPOptions(XMPAccessMode mode)
{
    switch (mode) {
        case XMPAccessMode::READ_ONLY_XMP:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP | kXMPFiles_DisableLegacyImport;
        case XMPAccessMode::READ_WRITE_XMP:
            return kXMPFiles_OpenForUpdate | kXMPFiles_OpenOnlyXMP | kXMPFiles_DisableLegacyImport;
        default:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP | kXMPFiles_DisableLegacyImport;
    }
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessor::Create(const uint8_t *data, uint32_t size,
    XMPAccessMode mode)
{
    std::unique_ptr<XMPMetadataAccessor> accessor = std::make_unique<XMPMetadataAccessor>();
    uint32_t status = accessor->InitializeFromBuffer(data, size, mode);
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, nullptr, "%{public}s failed to initialize from buffer", __func__);
    return accessor;
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessor::Create(const std::string &filePath, XMPAccessMode mode)
{
    std::unique_ptr<XMPMetadataAccessor> accessor = std::make_unique<XMPMetadataAccessor>();
    uint32_t status = accessor->InitializeFromPath(filePath, mode);
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, nullptr, "%{public}s failed to initialize from path", __func__);
    return accessor;
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessor::Create(int32_t fileDescriptor, XMPAccessMode mode)
{
    std::unique_ptr<XMPMetadataAccessor> accessor = std::make_unique<XMPMetadataAccessor>();
    uint32_t status = accessor->InitializeFromFd(fileDescriptor, mode);
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, nullptr, "%{public}s failed to initialize from fd", __func__);
    return accessor;
}

uint32_t XMPMetadataAccessor::Read()
{
    XMP_TRY();
    uint32_t status = CheckXMPFiles();
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, status, "%{public}s failed to check XMPFiles", __func__);

    auto impl = std::make_unique<XMPMetadataImpl>();
    CHECK_ERROR_RETURN_RET_LOG(!impl || !impl->IsValid(), ERR_MEDIA_MALLOC_FAILED,
        "%{public}s XMPMetadataImpl is invalid", __func__);
    if (!xmpFiles_->GetXMP(impl->GetRawPtr())) {
        IMAGE_LOGE("%{public}s GetXMP failed, ioType=%{public}hhu, maybe no XMP data in file",
            __func__, static_cast<uint8_t>(ioType_));
        return ERR_XMP_DECODE_FAILED;
    }

    xmpMetadata_ = std::make_shared<XMPMetadata>(std::move(impl));
    IMAGE_LOGD("%{public}s successfully read XMPMetadata", __func__);
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadataAccessor::Write()
{
    XMP_TRY();
    uint32_t status = CheckXMPFiles();
    CHECK_ERROR_RETURN_RET_LOG(status != SUCCESS, status, "%{public}s failed to check XMPFiles", __func__);
    CHECK_ERROR_RETURN_RET_LOG(xmpMetadata_ == nullptr, ERR_MEDIA_NULL_POINTER,
        "%{public}s xmpMetadata is nullptr", __func__);

    if (ioType_ == IOType::UNKNOWN || ioType_ == IOType::XMP_BUFFER_IO) {
        IMAGE_LOGE("%{public}s IOType: %{public}hhu is not supported for write operation", __func__, ioType_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    std::unique_ptr<XMPMetadataImpl> &impl = xmpMetadata_->GetImpl();
    CHECK_ERROR_RETURN_RET_LOG(!impl || !impl->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s XMPMetadataImpl is invalid", __func__);

    SXMPMeta &meta = impl->GetMeta();
    CHECK_ERROR_RETURN_RET_LOG(!xmpFiles_->CanPutXMP(meta), ERR_MEDIA_INVALID_OPERATION,
        "%{public}s CanPutXMP failed", __func__);

    xmpFiles_->PutXMP(meta);
    xmpFiles_->CloseFile();
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
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
    XMP_TRY();
    if (xmpFiles_ == nullptr) {
        IMAGE_LOGE("%{public}s xmpFiles is nullptr", __func__);
        return ERR_XMP_INVALID_FILE;
    }

    if (!xmpFiles_->GetFileInfo()) {
        IMAGE_LOGE("%{public}s xmpFiles is not open", __func__);
        return ERR_XMP_INVALID_FILE;
    }
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadataAccessor::InitializeFromBuffer(const uint8_t *data, uint32_t size, XMPAccessMode mode)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(data == nullptr || size == 0, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s data is nullptr or size is 0", __func__);
    xmpFiles_.reset(new SXMPFiles());
    CHECK_ERROR_RETURN_RET_LOG(xmpFiles_ == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "%{public}s failed to create XMPFiles", __func__);

    // Determine if read only based on access mode
    bool readOnly = (mode == XMPAccessMode::READ_ONLY_XMP);
    bufferIO_ = std::make_shared<XMPBuffer_IO>(data, static_cast<XMP_Uns32>(size), readOnly);
    CHECK_ERROR_RETURN_RET_LOG(bufferIO_ == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "%{public}s failed to create XMPBuffer_IO", __func__);

    XMP_OptionBits openFlags = ConvertAccessModeToXMPOptions(mode);
    if (!xmpFiles_->OpenFile(bufferIO_.get(), kXMP_UnknownFile, openFlags)) {
        IMAGE_LOGE("%{public}s failed to open file with XMPBuffer_IO", __func__);
        return ERR_XMP_INVALID_FILE;
    }

    ioType_ = IOType::XMP_BUFFER_IO;
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadataAccessor::InitializeFromPath(const std::string &filePath, XMPAccessMode mode)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(filePath.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s filePath is empty", __func__);
    xmpFiles_.reset(new SXMPFiles());
    CHECK_ERROR_RETURN_RET_LOG(xmpFiles_ == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "%{public}s failed to create XMPFiles", __func__);

    XMP_OptionBits openFlags = ConvertAccessModeToXMPOptions(mode);
    if (!xmpFiles_->OpenFile(filePath.c_str(), kXMP_UnknownFile, openFlags)) {
        IMAGE_LOGE("%{public}s failed to open file with XMPFiles_IO: %{public}s", __func__, filePath.c_str());
        return ERR_XMP_INVALID_FILE;
    }

    ioType_ = IOType::XMP_FILE_PATH;
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadataAccessor::InitializeFromFd(int32_t fileDescriptor, XMPAccessMode mode)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(fileDescriptor == INVALID_FILE_DESCRIPTOR, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s fileDescriptor is invalid", __func__);
    xmpFiles_.reset(new SXMPFiles());
    CHECK_ERROR_RETURN_RET_LOG(xmpFiles_ == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "%{public}s failed to create XMPFiles", __func__);

    // Determine if read only based on access mode
    bool readOnly = (mode == XMPAccessMode::READ_ONLY_XMP);
    fdIO_ = std::make_shared<XMPFd_IO>(fileDescriptor, readOnly, false);
    CHECK_ERROR_RETURN_RET_LOG(fdIO_ == nullptr || !fdIO_->IsValid(), ERR_MEDIA_MALLOC_FAILED,
        "%{public}s failed to create XMPFd_IO", __func__);

    XMP_OptionBits openFlags = ConvertAccessModeToXMPOptions(mode);
    if (!xmpFiles_->OpenFile(fdIO_.get(), kXMP_UnknownFile, openFlags)) {
        IMAGE_LOGE("%{public}s failed to open file with XMPFd_IO", __func__);
        return ERR_XMP_INVALID_FILE;
    }

    ioType_ = IOType::XMP_FD_IO;
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}
} // namespace OHOS
} // namespace Media
