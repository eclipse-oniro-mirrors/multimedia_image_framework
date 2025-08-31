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

#ifndef INTERFACES_INNERKITS_INCLUDE_BLOB_METADATA_H
#define INTERFACES_INNERKITS_INCLUDE_BLOB_METADATA_H

#include <atomic>
#include "image_type.h"
#include "metadata.h"

namespace OHOS {
namespace Media {
class BlobMetadata : public ImageMetadata {
public:
    static std::atomic<uint32_t> currentId;
    BlobMetadata();
    BlobMetadata(MetadataType type);
    BlobMetadata(const BlobMetadata &blobMetadata);
    BlobMetadata& operator=(const BlobMetadata &blobMetadata);
    ~BlobMetadata();
    int GetValue(const std::string &key, std::string &value) const override;
    bool SetValue(const std::string &key, const std::string &value) override;
    bool RemoveEntry(const std::string &key) override;
    const ImageMetadata::PropertyMapPtr GetAllProperties() override;
    MetadataType GetType() const override;
    bool RemoveExifThumbnail() override;
    std::shared_ptr<ImageMetadata> CloneMetadata() override;

    NATIVEEXPORT uint32_t GetBlob(uint32_t bufferSize, uint8_t *dst) override;
    NATIVEEXPORT uint32_t SetBlob(const uint8_t *source, const uint32_t bufferSize) override;
    NATIVEEXPORT uint32_t GetBlobSize() override;
    NATIVEEXPORT uint8_t* GetBlobPtr() override;

    uint32_t GetUniqueId() const;
    bool Marshalling(Parcel &parcel) const override;
    static BlobMetadata *Unmarshalling(Parcel &parcel);
    static BlobMetadata *Unmarshalling(Parcel &parcel, PICTURE_ERR &error);
    static bool WriteFileDescriptor(Parcel &parcel, int fd);
    static void ReleaseMemory(void *addr, void *context, uint32_t size);
    static int ReadFileDescriptor(Parcel &parcel);
    bool WriteDataToParcel(Parcel &parcel, size_t size) const;
    static bool ReadDataFromAshmem(Parcel &parcel, std::unique_ptr<BlobMetadata> &blobMetadataPtr,
        std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc = nullptr);
    static bool ReadDataFromParcel(Parcel &parcel, std::unique_ptr<BlobMetadata> &blobMetadataPtr);
protected:
    uint8_t *data_ = nullptr;
    uint32_t dataSize_ = 0;
    uint32_t uniqueId_ = 0;
    MetadataType type_ = MetadataType::UNKNOWN;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_INCLUDE_BLOB_METADATA_H