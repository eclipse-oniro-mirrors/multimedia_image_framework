/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <iostream>
#include <map>
#include <ostream>
#include <set>
#include <sstream>
#include <vector>
#include <string_view>

#include "exif_metadata.h"
#include "exif_metadata_formatter.h"
#include "image_log.h"
#include "libexif/exif-format.h"
#include "libexif/exif-tag.h"
#include "libexif/huawei/exif-mnote-data-huawei.h"
#include "libexif/huawei/mnote-huawei-entry.h"
#include "libexif/huawei/mnote-huawei-tag.h"
#include "libexif/huawei/mnote-huawei-data-type.h"
#include "media_errors.h"
#include "securec.h"
#include "string_ex.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ExifMetadata"

namespace OHOS {
namespace Media {
const auto KEY_SIZE = 2;
const auto TAG_VALUE_SIZE = 1024;
const static std::string DEFAULT_EXIF_VALUE = "default_exif_value";
const std::set<std::string_view> HW_SPECIAL_KEYS = {
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS"
};

template <typename T> std::istream &OutputRational(std::istream &is, T &r)
{
    int32_t nominator = 0;
    int32_t denominator = 0;
    char c('\0');
    is >> nominator >> c >> denominator;
    if (c != '/') {
        is.setstate(std::ios::failbit);
    }
    if (is) {
        r = { nominator, denominator };
    }
    return is;
}

std::istream &operator >> (std::istream &is, ExifRational &r)
{
    return OutputRational(is, r);
}

std::istream &operator >> (std::istream &is, ExifSRational &r)
{
    return OutputRational(is, r);
}

std::set<ExifTag> UndefinedByte = { EXIF_TAG_SCENE_TYPE, EXIF_TAG_COMPONENTS_CONFIGURATION, EXIF_TAG_FILE_SOURCE };

ExifMetadata::ExifMetadata() : exifData_(nullptr) {}

ExifMetadata::ExifMetadata(ExifData *exifData) : exifData_(exifData) {}

ExifMetadata::~ExifMetadata()
{
    if (exifData_ != nullptr) {
        exif_data_unref(exifData_);
        exifData_ = nullptr;
    }
}

int ExifMetadata::GetValue(const std::string &key, std::string &value) const
{
    IMAGE_LOGD("Retrieving value for key: %{public}s", key.c_str());
    if (exifData_ == nullptr) {
        IMAGE_LOGE("Exif data is null for key: %{public}s", key.c_str());
        value = "";
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (key == "MakerNote") {
        return HandleMakerNote(value);
    }
    char tagValueChar[TAG_VALUE_SIZE];
    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") || IsSpecialHwKey(key)) {
        value = DEFAULT_EXIF_VALUE;
        ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
        if (md == nullptr) {
            IMAGE_LOGD("Exif data mnote data md is nullptr");
            return SUCCESS;
        }
        if (!is_huawei_md(md)) {
            IMAGE_LOGE("Exif data returned null for key: %{public}s", key.c_str());
            return SUCCESS;
        }
        MnoteHuaweiEntryCount *ec = nullptr;
        mnote_huawei_get_entry_count((ExifMnoteDataHuawei *)md, &ec);
        if (ec == nullptr) {
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
        for (unsigned int i = 0; i < ec->size; i++) {
            MnoteHuaweiEntry *entry = ec->entries[i];
            if (key == mnote_huawei_tag_get_name(entry->tag)) {
                mnote_huawei_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
                value = tagValueChar;
            }
        }
        mnote_huawei_free_entry_count(ec);
    } else {
        auto tag = exif_tag_from_name(key.c_str());
        ExifEntry *entry = GetEntry(key);
        if (entry == nullptr) {
            IMAGE_LOGD("Exif data entry returned null for key: %{public}s, tag: %{public}d", key.c_str(), tag);
            value = "";
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
        IMAGE_LOGD("Using exif_entry_get_value for key: %{public}s, tag: %{public}d", key.c_str(), entry->tag);
        exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
        value = tagValueChar;
    }
    IMAGE_LOGD("Retrieved value for key: %{public}s is: %{public}s", key.c_str(), value.c_str());
    return SUCCESS;
}

int ExifMetadata::HandleMakerNote(std::string &value) const
{
    value.clear();
    std::vector<char> tagValueChar(TAG_VALUE_SIZE, 0);
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    if (md == nullptr) {
        IMAGE_LOGD("Exif data mnote data md is a nullptr.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (!is_huawei_md(md)) {
        IMAGE_LOGD("Exif data mnote data md is not ours md.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    MnoteHuaweiEntryCount *ec = nullptr;
    mnote_huawei_get_entry_count((ExifMnoteDataHuawei *)md, &ec);
    if (ec == nullptr) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        const char *mnoteKey = mnote_huawei_tag_get_name(entry->tag);
        if (std::strcmp(mnoteKey, "HwUnknow") == 0) {
            continue;
        }
        mnote_huawei_entry_get_value(entry, tagValueChar.data(), tagValueChar.size());
        value += std::string(mnoteKey) + ":" + tagValueChar.data() + ",";
    }

    // Check if the last character of value is a comma and remove it
    if (value.length() > 1 && value[value.length() - 1] == ',') {
        value = value.substr(0, value.length() - 1);
    }

    return SUCCESS;
}

ExifData *ExifMetadata::GetExifData()
{
    return exifData_;
}

bool ExifMetadata::CreateExifdata()
{
    if (exifData_ != nullptr) {
        exif_data_unref(exifData_);
        exifData_ = nullptr;
        exifData_ = exif_data_new();
        if (exifData_ == nullptr) {
            IMAGE_LOGE("Failed to recreate exif data after unref.");
            return false;
        }

        // Set the image options
        exif_data_set_option(exifData_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
        exif_data_set_data_type(exifData_, EXIF_DATA_TYPE_COMPRESSED);
        exif_data_set_byte_order(exifData_, EXIF_BYTE_ORDER_INTEL);

        // Create the mandatory EXIF fields with default data
        exif_data_fix(exifData_);
        return true;
    }
    exifData_ = exif_data_new();
    if (exifData_ == nullptr) {
        IMAGE_LOGE("Failed to create new exif data.");
        return false;
    }

    // Set the image options
    exif_data_set_option(exifData_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
    exif_data_set_data_type(exifData_, EXIF_DATA_TYPE_COMPRESSED);
    exif_data_set_byte_order(exifData_, EXIF_BYTE_ORDER_INTEL);

    // Create the mandatory EXIF fields with default data
    exif_data_fix(exifData_);
    IMAGE_LOGD("New exif data created.");
    return true;
}

std::shared_ptr<ExifMetadata> ExifMetadata::Clone()
{
    ExifData *exifData = this->GetExifData();

    unsigned char *dataBlob = nullptr;
    uint32_t size = 0;
    TiffParser::Encode(&dataBlob, size, exifData);
    if (dataBlob == nullptr) {
        return nullptr;
    }

    ExifData *newExifData = nullptr;
    TiffParser::Decode(dataBlob, size, &newExifData);
    if (newExifData == nullptr) {
        return nullptr;
    }
    std::shared_ptr<ExifMetadata> exifDataPtr = std::make_shared<ExifMetadata>(newExifData);
    return exifDataPtr;
}

ExifEntry *ExifMetadata::CreateEntry(const std::string &key, const ExifTag &tag, const size_t valueLen)
{
    ExifEntry *entry = exif_entry_new();
    if (entry == nullptr) {
        IMAGE_LOGE("Failed to create new ExifEntry.");
        return nullptr;
    }
    entry->tag = tag; // tag must be set before calling exif_content_add_entry
    auto ifdindex = exif_ifd_from_name(key.c_str());
    exif_content_add_entry(exifData_->ifd[ifdindex], entry);
    exif_entry_initialize(entry, tag);

    if (entry->format == EXIF_FORMAT_UNDEFINED && entry->size != valueLen) {
        exif_content_remove_entry(exifData_->ifd[ifdindex], entry);

        // Create a memory allocator to manage this ExifEntry
        ExifMem *exifMem = exif_mem_new_default();
        if (exifMem == nullptr) {
            IMAGE_LOGE("Failed to create memory allocator for ExifEntry.");
            return nullptr;
        }

        // Create a new ExifEntry using our allocator
        entry = exif_entry_new_mem(exifMem);
        if (entry == nullptr) {
            IMAGE_LOGE("Failed to create new ExifEntry using memory allocator.");
            exif_mem_unref(exifMem);
            return nullptr;
        }

        // Allocate memory to use for holding the tag data
        void *buffer = exif_mem_alloc(exifMem, valueLen);
        if (buffer == nullptr) {
            IMAGE_LOGE("Failed to allocate memory for tag data.");
            exif_entry_unref(entry);
            exif_mem_unref(exifMem);
            return nullptr;
        }

        // Fill in the entry
        entry->data = static_cast<unsigned char *>(buffer);
        entry->size = valueLen;
        entry->tag = tag;
        entry->components = valueLen;
        entry->format = EXIF_FORMAT_UNDEFINED;

        // Attach the ExifEntry to an IFD
        exif_content_add_entry(exifData_->ifd[ifdindex], entry);

        // The ExifMem and ExifEntry are now owned elsewhere
        exif_mem_unref(exifMem);
        exif_entry_unref(entry);
    }
    return entry;
}

MnoteHuaweiEntry *ExifMetadata::CreateHwEntry(const std::string &key)
{
    ExifMnoteData *md = exif_data_get_mnote_data (exifData_);
    if (!is_huawei_md(md)) {
        IMAGE_LOGE("Failed to create MnoteHuaweiEntry is not Huawei MakeNote.");
        return nullptr;
    }

    ExifByteOrder order = exif_mnote_data_huawei_get_byte_order(md);
    MnoteHuaweiEntry* entry = mnote_huawei_entry_new(md);
    if (!entry) {
        IMAGE_LOGE("Failed to create MnoteHuaweiEntry.");
        return nullptr;
    }

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    mnote_huawei_entry_initialize(entry, tag, order);
    return entry;
}

void ExifMetadata::ReallocEntry(ExifEntry *ptrEntry, const size_t valueLen)
{
    // Create a memory allocator to manage this ExifEntry
    ExifMem *exifMem = exif_mem_new_default();
    if (exifMem == nullptr) {
        IMAGE_LOGE("Failed to create memory allocator for ExifEntry. Value length: %{public}zu", valueLen);
        return;
    }
    auto buf = exif_mem_realloc(exifMem, ptrEntry->data, valueLen);
    if (buf != nullptr) {
        ptrEntry->data = static_cast<unsigned char *>(buf);
        ptrEntry->size = exif_format_get_size(ptrEntry->format) * valueLen;
        ptrEntry->components = exif_format_get_size(ptrEntry->format) * valueLen;
    } else {
        IMAGE_LOGE("Failed to reallocate memory for ExifEntry. Requested size: %{public}zu", valueLen);
    }
    exif_mem_unref(exifMem);
}

ExifEntry *ExifMetadata::GetEntry(const std::string &key, const size_t valueLen)
{
    IMAGE_LOGD("GetEntry key is %{public}s.", key.c_str());
    ExifTag tag = exif_tag_from_name(key.c_str());
    ExifEntry *entry;
    if (tag == 0x0001 || tag == 0x0002) {
        ExifIfd ifd = exif_ifd_from_name(key.c_str());
        entry = exif_content_get_entry(exifData_->ifd[ifd], tag);
    } else {
        entry = exif_data_get_entry(exifData_, tag);
    }

    if (entry == nullptr) {
        IMAGE_LOGD("GetEntry entry is nullptr and try to create entry.");
        entry = CreateEntry(key, tag, valueLen);
    }

    if (entry == nullptr) {
        IMAGE_LOGE("GetEntry entry is nullptr fail.");
        return nullptr;
    }

    if ((entry->format == EXIF_FORMAT_UNDEFINED || entry->format == EXIF_FORMAT_ASCII) &&
        (entry->size != static_cast<unsigned int>(valueLen))) {
        ReallocEntry(entry, valueLen);
    }
    return entry;
}

ExifEntry *ExifMetadata::GetEntry(const std::string &key) const
{
    IMAGE_LOGD("GetEntry by key is %{public}s.", key.c_str());
    ExifTag tag = exif_tag_from_name(key.c_str());
    ExifEntry *entry = nullptr;
    if (tag == 0x0001 || tag == 0x0002) {
        ExifIfd ifd = exif_ifd_from_name(key.c_str());
        entry = exif_content_get_entry(exifData_->ifd[ifd], tag);
    } else {
        entry = exif_data_get_entry(exifData_, tag);
    }
    return entry;
}

bool ExifMetadata::SetShort(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifShort tmp;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifShort from string. Current count: %{public}lu", icount);
            return false;
        }
        exif_set_short(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetLong(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifLong tmp;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifLong from string. Current count: %{public}lu", icount);
            return false;
        }
        exif_set_long(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSShort(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSShort tmp;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifSShort from string. Current count: %{public}lu", icount);
            return false;
        }
        exif_set_sshort(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSLong(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSLong tmp;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifSLong from string. Current count: %{public}lu", icount);
            return false;
        }
        exif_set_slong(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetRational(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifRational rat;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifRational from string. Current count: %{public}lu", icount);
            return false;
        }
        int offset = static_cast<int>(icount * exif_format_get_size(ptrEntry->format));
        exif_set_rational(ptrEntry->data + offset, order, rat);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSRational(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSRational rat;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        if (is.fail()) {
            IMAGE_LOGE("Failed to read ExifSRational from string. Current count: %{public}lu", icount);
            return false;
        }
        int offset = static_cast<int>(icount * exif_format_get_size(ptrEntry->format));
        exif_set_srational(ptrEntry->data + offset, order, rat);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetByte(ExifEntry *ptrEntry, const std::string &value)
{
    std::string result;
    for (char c : value) {
        if (c != ' ') {
            result += c;
        }
    }
    const char *p = result.c_str();
    int valueLen = static_cast<int>(result.length());
    for (int i = 0; i < valueLen && i < static_cast<int>(ptrEntry->size); i++) {
        *(ptrEntry->data + i) = p[i] - '0';
    }
    return true;
}

bool ExifMetadata::SetMem(ExifEntry *ptrEntry, const std::string &value, const size_t valueLen)
{
    if (UndefinedByte.find(ptrEntry->tag) != UndefinedByte.end()) {
        return SetByte(ptrEntry, value);
    }
    IMAGE_LOGD("memcpy_s value string %{public}s", value.c_str());
    if (memcpy_s((ptrEntry)->data, valueLen, value.c_str(), valueLen) != 0) {
        IMAGE_LOGE("Failed to copy memory for ExifEntry. Requested size: %{public}zu", valueLen);
        return false;
    }
    return true;
}

bool ExifMetadata::SetValue(const std::string &key, const std::string &value)
{
    if (exifData_ == nullptr) {
        IMAGE_LOGE("Exif data is null. Cannot set value for key: %{public}s", key.c_str());
        return false;
    }
    auto result = ExifMetadatFormatter::Format(key, value);
    if (result.first) {
        IMAGE_LOGE("Failed to validate and convert value for key: %{public}s", key.c_str());
        return false;
    }

    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") ||
        IsSpecialHwKey(key)) {
        IMAGE_LOGD("Set HwMoteValue %{public}s", value.c_str());
        return SetHwMoteValue(key, result.second);
    }

    return SetCommonValue(key, result.second);
}

bool ExifMetadata::SetHwMoteValue(const std::string &key, const std::string &value)
{
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    if (!is_huawei_md(md)) {
        IMAGE_LOGD("Makernote is not huawei makernote.");
        return false;
    }

    MnoteHuaweiTag hwTag = mnote_huawei_tag_from_name(key.c_str());
    if (hwTag == MNOTE_HUAWEI_INFO) {
        IMAGE_LOGD("The key: %{public}s is unknow hwTag", key.c_str());
        return false;
    }

    auto *entry = exif_mnote_data_huawei_get_entry_by_tag((ExifMnoteDataHuawei*) md, hwTag);
    if (!entry) {
        entry = CreateHwEntry(key);
        if (!entry) {
            return false;
        }
        auto ret = exif_mnote_data_add_entry(md, entry);
        if (ret) {
            mnote_huawei_entry_free(entry);
            IMAGE_LOGE("Add new hw entry failed.");
            return false;
        }

        mnote_huawei_entry_free_contour(entry);
        entry = exif_mnote_data_huawei_get_entry_by_tag((ExifMnoteDataHuawei*) md, hwTag);
    }

    const char *data = value.c_str();
    int dataLen = value.length();
    int ret = mnote_huawei_entry_set_value(entry, data, dataLen);
    return ret == 0 ? true : false;
}

bool ExifMetadata::SetCommonValue(const std::string &key, const std::string &value)
{
    size_t valueLen = value.length();
    ExifEntry *ptrEntry = GetEntry(key, valueLen);
    if (ptrEntry == nullptr) {
        return false;
    }
    ExifByteOrder order = exif_data_get_byte_order(ptrEntry->parent->parent);
    bool isSetSuccess = false;
    switch (ptrEntry->format) {
        case EXIF_FORMAT_SHORT:
            isSetSuccess = SetShort(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_LONG:
            isSetSuccess = SetLong(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SSHORT:
            isSetSuccess = SetSShort(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SLONG:
            isSetSuccess = SetSLong(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_RATIONAL:
            isSetSuccess = SetRational(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SRATIONAL:
            isSetSuccess = SetSRational(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_BYTE:
            isSetSuccess = SetByte(ptrEntry, value);
            break;
        case EXIF_FORMAT_UNDEFINED:
        case EXIF_FORMAT_ASCII:
            isSetSuccess = SetMem(ptrEntry, value, valueLen);
            break;
        default:
            IMAGE_LOGE("Unsupported Exif format for key: %{public}s", key.c_str());
            break;
    }
    return isSetSuccess;
}

bool ExifMetadata::RemoveEntry(const std::string &key)
{
    bool isSuccess = false;
    if (!(exifData_ && ExifMetadatFormatter::IsModifyAllowed(key))) {
        IMAGE_LOGD("RemoveEntry failed, can not remove entry for key: %{public}s", key.c_str());
        return isSuccess;
    }

    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") ||
        IsSpecialHwKey(key)) {
        return RemoveHwEntry(key);
    }

    ExifEntry *entry = GetEntry(key);
    if (!entry) {
        IMAGE_LOGD("RemoveEntry failed, can not find entry for key: %{public}s", key.c_str());
        return isSuccess;
    }

    IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
    exif_content_remove_entry(entry->parent, entry);
    isSuccess = true;
    return isSuccess;
}

bool ExifMetadata::RemoveHwEntry(const std::string &key)
{
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);

    if (!is_huawei_md(md)) {
        IMAGE_LOGD("Exif makernote is not huawei makernote");
        return false;
    }

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    auto *entry = exif_mnote_data_huawei_get_entry_by_tag((ExifMnoteDataHuawei*) md, tag);
    if (!entry) {
        IMAGE_LOGE("Get entry by tag failed, there is no entry for key: %{public}s", key.c_str());
        return false;
    }

    exif_mnote_data_remove_entry(md, entry);
    return true;
}

bool ExifMetadata::IsSpecialHwKey(const std::string &key) const
{
    auto iter = HW_SPECIAL_KEYS.find(key);
    return (iter != HW_SPECIAL_KEYS.end());
}

} // namespace Media
} // namespace OHOS
