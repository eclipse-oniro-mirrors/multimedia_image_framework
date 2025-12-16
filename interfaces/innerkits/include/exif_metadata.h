/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_EXIF_METADATA_H
#define INTERFACES_INNERKITS_INCLUDE_EXIF_METADATA_H

#include <libexif/exif-entry.h>
#include <libexif/exif-tag.h>
#include <libexif/huawei/exif-mnote-data-huawei.h>
#include <unordered_map>

#include "image_type.h"
#include "metadata.h"
#include "parcel.h"

namespace OHOS {
namespace Media {

struct EntryBasicInfo {
    ExifFormat format;
    unsigned long components;
    unsigned char *data;
    ExifByteOrder byteOrder;
};
class ExifMetadata : public ImageMetadata {
public:
    ExifMetadata();
    ExifMetadata(ExifData *exifData);
    virtual ~ExifMetadata();
    virtual int GetValue(const std::string &key, std::string &value) const override;
    int GetValueByType(const std::string &key, MetadataValue &result) const;
    int HandleHwMnoteByType(const std::string &key, MetadataValue &result) const;
    bool SetBlobValue(const MetadataValue &properties);
    virtual bool SetValue(const std::string &key, const std::string &value) override;
    virtual bool RemoveEntry(const std::string &key) override;
    virtual const ImageMetadata::PropertyMapPtr GetAllProperties() override;
    virtual std::shared_ptr<ImageMetadata> CloneMetadata() override;
    ExifData* GetExifData();
    bool CreateExifdata();
    NATIVEEXPORT std::shared_ptr<ExifMetadata> Clone();
    bool Marshalling(Parcel &parcel) const override;
    static ExifMetadata *Unmarshalling(Parcel &parcel);
    static ExifMetadata *Unmarshalling(Parcel &parcel, PICTURE_ERR &error);
    void GetFilterArea(const std::vector<std::string> &exifKeys, std::vector<std::pair<uint32_t, uint32_t>> &ranges);
    MetadataType GetType() const override
    {
        return MetadataType::EXIF;
    }
    bool RemoveExifThumbnail() override;
    bool ExtractXmageCoordinates(XmageCoordinateMetadata &coordMetadata) const;
    uint32_t GetBlobSize() override;
    uint32_t GetBlob(uint32_t bufferSize, uint8_t *dst) override;
    uint32_t SetBlob(const uint8_t *source, const uint32_t bufferSize) override;
    static PropertyValueType GetPropertyValueType(const std::string& key);
    static std::shared_ptr<ExifMetadata> InitExifMetadata();
    static const std::map<std::string, PropertyValueType>& GetExifMetadataMap();
    static const std::map<std::string, PropertyValueType>& GetHwMetadataMap();
    static const std::map<NapiMetadataType, std::map<std::string, PropertyValueType>>& GetPropertyTypeMapping();
    static const std::unordered_map<std::string, std::string>& GetPropertyKeyMap();

private:
    bool ParseExifCoordinate(const std::string& fieldName, uint32_t& outputValue) const;
    ExifEntry* CreateEntry(const std::string &key, const ExifTag &tag, const size_t len);
    MnoteHuaweiEntry* CreateHwEntry(const std::string &key);
    ExifEntry* GetEntry(const std::string &key, const size_t len);
    ExifEntry* GetEntry(const std::string &key) const;
    ExifMnoteData* GetHwMnoteData(bool &isNewMaker);
    int HandleMakerNote(std::string &value) const;
    int HandleHwMnote(const std::string &key, std::string &value) const;
    void ReallocEntry(ExifEntry *ptrEntry, const size_t len);
    bool SetShort(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetSShort(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetLong(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetSLong(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetRational(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetSRational(ExifEntry *ptrEntry, const ExifByteOrder &o, const std::string &value);
    bool SetByte(ExifEntry *ptrEntry, const std::string &value);
    bool SetMem(ExifEntry *ptrEntry, const std::string &value, const size_t len);
    bool SetHwMoteValue(const std::string &key, const std::string &value);
    bool SetMakerNoteValue(const std::string &value);
    bool RemoveHwEntry(const std::string &key);
    bool SetCommonValue(const std::string &key, const std::string &value);
    bool IsSpecialHwKey(const std::string &key) const;
    void FindRationalRanges(ExifContent *content,
        std::vector<std::pair<uint32_t, uint32_t>> &ranges, int index);
    void FindRanges(const ExifTag &tag, std::vector<std::pair<uint32_t, uint32_t>> &ranges);
    int GetUserMakerNote(std::string& value) const;
    ExifData *exifData_;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_EXIF_METADATA_H
