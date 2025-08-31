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

#include "blob_metadata.h"

#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include "ashmem.h"
#include "buffer_handle_parcel.h"
#include "image_log.h"
#include "image_utils.h"
#include "ipc_file_descriptor.h"
#include "media_errors.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "BlobMetadata"

namespace OHOS {
namespace Media {
const static uint64_t MAX_BLOB_METADATA_LENGTH = 20 * 1024 * 1024;
const static uint32_t MAX_MARSHAL_BLOB_DATA_SIZE = 32 * 1024;
std::atomic<uint32_t> BlobMetadata::currentId = 0;

BlobMetadata::BlobMetadata()
{
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
};

BlobMetadata::BlobMetadata(MetadataType type)
{
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    type_ = type;
};

BlobMetadata::BlobMetadata(const BlobMetadata& blobMetadata)
{
    if (blobMetadata.data_ == nullptr || blobMetadata.dataSize_ <= 0) {
        return;
    }
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    data_ = new uint8_t[blobMetadata.dataSize_];
    if (memcpy_s(data_, blobMetadata.dataSize_, blobMetadata.data_, blobMetadata.dataSize_) != EOK) {
        delete[] data_;
        data_ = nullptr;
        type_ = MetadataType::UNKNOWN;
        dataSize_ = 0;
    } else {
        type_ = blobMetadata.type_;
        dataSize_ = blobMetadata.dataSize_;
    }
}

BlobMetadata& BlobMetadata::operator=(const BlobMetadata &blobMetadata)
{
    if (this == &blobMetadata) {
        return *this;
    }
    if (data_ != nullptr) {
        delete[] data_;
        data_ = nullptr;
    }
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    if (blobMetadata.data_ == nullptr || blobMetadata.dataSize_ <= 0) {
        dataSize_ = 0;
        return *this;
    }
    data_ = new uint8_t[blobMetadata.dataSize_];
    if (memcpy_s(data_, blobMetadata.dataSize_, blobMetadata.data_, blobMetadata.dataSize_) != EOK) {
        delete[] data_;
        data_ = nullptr;
        type_ = MetadataType::UNKNOWN;
        dataSize_ = 0;
        return *this;
    }
    type_ = blobMetadata.type_;
    dataSize_ = blobMetadata.dataSize_;
    return *this;
}

BlobMetadata::~BlobMetadata()
{
    if (data_ != nullptr) {
        delete[] data_;
        data_ = nullptr;
    }
}

int BlobMetadata::GetValue(const std::string &key, std::string &value) const
{
    IMAGE_LOGE("Unsupported operation");
    return ERR_MEDIA_INVALID_OPERATION;
}

bool BlobMetadata::SetValue(const std::string &key, const std::string &value)
{
    IMAGE_LOGE("Unsupported operation");
    return false;
}

bool BlobMetadata::RemoveEntry(const std::string &key)
{
    IMAGE_LOGE("Unsupported operation");
    return false;
}

const ImageMetadata::PropertyMapPtr BlobMetadata::GetAllProperties()
{
    IMAGE_LOGE("Unsupported operation");
    return nullptr;
}

MetadataType BlobMetadata::GetType() const
{
    return type_;
}

bool BlobMetadata::RemoveExifThumbnail()
{
    IMAGE_LOGE("Unsupported operation");
    return false;
}

uint32_t BlobMetadata::GetUniqueId() const
{
    return uniqueId_;
}

std::shared_ptr<ImageMetadata> BlobMetadata::CloneMetadata()
{
    if (dataSize_ > MAX_BLOB_METADATA_LENGTH) {
        IMAGE_LOGE("Failed to clone, the size of metadata exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_BLOB_METADATA_LENGTH));
        return nullptr;
    }
    return std::make_shared<BlobMetadata>(*this);
}

void BlobMetadata::ReleaseMemory(void *addr, void *context, uint32_t size)
{
    if (context != nullptr) {
        int *fd = static_cast<int *>(context);
        if (addr != nullptr) {
            ::munmap(addr, size);
        }
        if (fd != nullptr) {
            ::close(*fd);
        }
        context = nullptr;
        addr = nullptr;
    }
}

bool BlobMetadata::WriteDataToParcel(Parcel &parcel, size_t size) const
{
    if (data_ == nullptr) {
        IMAGE_LOGE("WriteDataToParcel data_ is nullptr");
        return false;
    }
    const uint8_t *data = data_;
    uint32_t id = GetUniqueId();
    std::string name = "Parcel Blob, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), size);
    IMAGE_LOGI("Blob AshmemCreate:[%{public}d].", fd);
    if (fd < 0) {
        return false;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    IMAGE_LOGD("Blob AshmemSetProt:[%{public}d].", result);
    if (result < 0) {
        ::close(fd);
        return false;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        IMAGE_LOGE("WriteDataToParcel map failed, errno:%{public}d", errno);
        return false;
    }
    IMAGE_LOGD("mmap success");
    if (memcpy_s(ptr, size, data, size) != EOK) {
        ::munmap(ptr, size);
        ::close(fd);
        IMAGE_LOGE("WriteDataToParcel memcpy_s error");
        return false;
    }
    if (!WriteFileDescriptor(parcel, fd)) {
        ::munmap(ptr, size);
        ::close(fd);
        IMAGE_LOGE("WriteDataToParcel WriteFileDescriptor error");
        return false;
    }
    IMAGE_LOGD("WriteDataToParcel WriteFileDescriptor success");
    ::munmap(ptr, size);
    ::close(fd);
    return true;
}

bool BlobMetadata::ReadDataFromAshmem(Parcel &parcel, std::unique_ptr<BlobMetadata> &blobMetadataPtr,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    if (blobMetadataPtr == nullptr || blobMetadataPtr->data_ == nullptr ||
        blobMetadataPtr->dataSize_ <= 0 || blobMetadataPtr->dataSize_ > MAX_BLOB_METADATA_LENGTH) {
        IMAGE_LOGE("Invalid BlobMetadataPtr or data buffer.");
        return false;
    }
    auto readFdDefaultFunc = [](Parcel &parcel) -> int { return ReadFileDescriptor(parcel); };
    int fd = ((readSafeFdFunc != nullptr) ? readSafeFdFunc(parcel, readFdDefaultFunc) : readFdDefaultFunc(parcel));
    if (fd < 0) {
        IMAGE_LOGE("Failed to read file descriptor from parcel.");
        return false;
    }
    int32_t ashmemSize = AshmemGetSize(fd);
    if (blobMetadataPtr->dataSize_ != static_cast<uint32_t>(ashmemSize)) {
        ::close(fd);
        IMAGE_LOGE("ReadBlobDataFromParcel check ashmem size failed, fd:[%{public}d].", fd);
        return false;
    }
    void *ptr = ::mmap(nullptr, blobMetadataPtr->dataSize_, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        IMAGE_LOGE("ReadBlobData map failed, errno:%{public}d", errno);
        return false;
    }
    if (memcpy_s(blobMetadataPtr->data_, blobMetadataPtr->dataSize_, ptr, blobMetadataPtr->dataSize_) != EOK) {
        ::munmap(ptr, blobMetadataPtr->dataSize_);
        ::close(fd);
        IMAGE_LOGE("memcpy Blob data size:[%{public}d] error.", blobMetadataPtr->dataSize_);
        return false;
    }
    ReleaseMemory(ptr, &fd, blobMetadataPtr->dataSize_);
    return true;
}

bool BlobMetadata::ReadDataFromParcel(Parcel &parcel, std::unique_ptr<BlobMetadata> &blobMetadataPtr)
{
    const uint8_t *ptr = parcel.ReadUnpadBuffer(static_cast<size_t>(blobMetadataPtr->dataSize_));
    if (ptr == nullptr) {
        IMAGE_LOGE("Failed to read data from parcel.");
        return false;
    }
    if (memcpy_s(blobMetadataPtr->data_, blobMetadataPtr->dataSize_,
        ptr, blobMetadataPtr->dataSize_) != EOK) {
        IMAGE_LOGE("memcpy_s failed to copy data.");
        return false;
    }
    return true;
}

int BlobMetadata::ReadFileDescriptor(Parcel &parcel)
{
    sptr<IPCFileDescriptor> descriptor = parcel.ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        IMAGE_LOGE("ReadFileDescriptor get descriptor failed");
        return -1;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        IMAGE_LOGE("ReadFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return -1;
    }
    return dup(fd);
}

bool BlobMetadata::WriteFileDescriptor(Parcel &parcel, int fd)
{
    if (fd < 0) {
        IMAGE_LOGE("WriteFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        IMAGE_LOGE("WriteFileDescriptor dup fd failed, dupFd:[%{public}d].", dupFd);
        return false;
    }
    sptr<IPCFileDescriptor> descriptor = new IPCFileDescriptor(dupFd);
    return parcel.WriteObject<IPCFileDescriptor>(descriptor);
}

bool BlobMetadata::Marshalling(Parcel &parcel) const
{
    if (data_ == nullptr) {
        IMAGE_LOGE("%{public}s Blob data is nullptr.", __func__);
        return false;
    }
    if (dataSize_ > MAX_BLOB_METADATA_LENGTH) {
        IMAGE_LOGE("The length of Blob metadata exceeds the maximum limit.");
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(type_))) {
        IMAGE_LOGE("Failed to write Blob data type.");
        return false;
    }
    if (!parcel.WriteUint32(dataSize_)) {
        IMAGE_LOGE("Failed to write Blob data size.");
        return false;
    }
    if (dataSize_ < MAX_MARSHAL_BLOB_DATA_SIZE) {
        if (!parcel.WriteUnpadBuffer(data_, dataSize_)) {
            IMAGE_LOGE("Failed to write Blob data buffer.");
            return false;
        }
    } else if (!WriteDataToParcel(parcel, dataSize_)) {
        IMAGE_LOGE("Failed to write Blob data By Ashmem.");
        return false;
    }
    return true;
}

BlobMetadata *BlobMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    BlobMetadata *dstBlobMetadata = Unmarshalling(parcel, error);
    if (dstBlobMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstBlobMetadata;
}

BlobMetadata *BlobMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    uint32_t type;
    if (!parcel.ReadUint32(type)) {
        IMAGE_LOGE("Failed to read data type.");
        return nullptr;
    }
    std::unique_ptr<BlobMetadata> blobMetadataPtr = std::make_unique<BlobMetadata>(static_cast<MetadataType>(type));
    uint32_t dataSize;
    if (!parcel.ReadUint32(dataSize)) {
        IMAGE_LOGE("Failed to read data size.");
        return nullptr;
    }
    if (dataSize <= 0 || dataSize > MAX_BLOB_METADATA_LENGTH) {
        IMAGE_LOGE("The size of Blob metadata exceeds the maximum limit.");
        return nullptr;
    }
    blobMetadataPtr->dataSize_ = dataSize;
    blobMetadataPtr->data_ = new uint8_t[dataSize];

    if (blobMetadataPtr->data_ == nullptr) {
        IMAGE_LOGE("Failed to allocate memory for Blob data buffer.");
        return nullptr;
    }
    const uint8_t *ptr = nullptr;
    bool ret = false;
    if (dataSize < MAX_MARSHAL_BLOB_DATA_SIZE) {
        ret = ReadDataFromParcel(parcel, blobMetadataPtr);
    } else {
        ret = ReadDataFromAshmem(parcel, blobMetadataPtr);
    }
    if (!ret) {
        delete[] blobMetadataPtr->data_;
        blobMetadataPtr->data_ = nullptr;
        blobMetadataPtr->type_ = MetadataType::UNKNOWN;
        blobMetadataPtr->dataSize_ = 0;
        IMAGE_LOGE("Failed to read data from parcel.");
    }
    return blobMetadataPtr.release();
}

uint32_t BlobMetadata::GetBlob(uint32_t bufferSize, uint8_t *dst)
{
    if (data_ == nullptr) {
        IMAGE_LOGE("Get Blob by buffer current Blob data is null");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (bufferSize < dataSize_ || dst == nullptr) {
        IMAGE_LOGE("Get Blob Input bufferSize or ptr Incorrect %{public}u", bufferSize);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    if (memcpy_s(dst, bufferSize, data_, dataSize_) != EOK) {
        IMAGE_LOGE("get Blob Metadata blob to dst fail");
        return ERR_MEDIA_MALLOC_FAILED;
    }
    return SUCCESS;
}

uint8_t *BlobMetadata::GetBlobPtr()
{
    return data_;
}

uint32_t BlobMetadata::SetBlob(const uint8_t *source, const uint32_t bufferSize)
{
    if (source == nullptr || bufferSize == 0 || bufferSize > MAX_BLOB_METADATA_LENGTH) {
        IMAGE_LOGE("Set Blob by buffer source is nullptr or size(%{public}llu) incorrect.",
            static_cast<unsigned long long>(bufferSize));
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    IMAGE_LOGI("setblob datasize_ %{public}u , bufferSize %{public}u", dataSize_, bufferSize);
    uint8_t *resData = new uint8_t[bufferSize];
    if (resData == nullptr) {
        IMAGE_LOGE("Failed to allocate memory for Blob Metadata Blob");
        return ERR_MEDIA_MALLOC_FAILED;
    }
    if (memcpy_s(resData, bufferSize, source, bufferSize) != EOK) {
        delete[] resData;
        resData = nullptr;
        IMAGE_LOGE("Set blob data to Blob data_ fail.");
        return ERR_MEDIA_MALLOC_FAILED;
    }
    if (data_ != nullptr) {
        delete[] data_;
        data_ = nullptr;
    }
    data_ = resData;
    dataSize_ = bufferSize;
    return SUCCESS;
}

uint32_t BlobMetadata::GetBlobSize()
{
    return dataSize_;
}
} // namespace Media
} // namespace OHOS