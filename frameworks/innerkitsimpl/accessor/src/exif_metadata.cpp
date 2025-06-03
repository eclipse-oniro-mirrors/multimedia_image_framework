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
#include <numeric>
#include <ostream>
#include <set>
#include <sstream>
#include <vector>
#include <string_view>

#include "exif_metadata.h"
#include "exif_metadata_formatter.h"
#include "image_log.h"
#include "libexif/exif-format.h"
#include "libexif/exif-mem.h"
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
const auto MAX_TAG_VALUE_SIZE_FOR_STR = 64 * 1024;
const auto TERMINATOR_SIZE = 1;
const auto EXIF_HEAD_SIZE = 6;
const int NUMERATOR_SIZE = 4; // 4 bytes for numeratior
const static std::string DEFAULT_EXIF_VALUE = "default_exif_value";
const static std::string HW_CAPTURE_MODE = "HwMnoteCaptureMode";
const static std::string HW_FOCUS_MODE_EXIF = "HwMnoteFocusModeExif";
const static std::string MAKER_NOTE_TAG = "MakerNote";
const static uint64_t MAX_EXIFMETADATA_MAX_SIZE = 1024 * 1024;
const std::set<std::string_view> HW_SPECIAL_KEYS = {
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS",
    "HwUnknow",
};
const unsigned char INIT_HW_DATA[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x55, 0x41, 0x57, 0x45, 0x49, 0x00,
    0x00, 0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x02, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
};

static const int GET_SUPPORT_MAKERNOTE_COUNT = 1;
static const int INIT_HW_DATA_HEAD_LENGTH = 8;
template <typename T, typename U> std::istream &OutputRational(std::istream &is, T &r)
{
    U nominator = 0;
    U denominator = 0;
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
    return OutputRational<ExifRational, uint32_t>(is, r);
}

std::istream &operator >> (std::istream &is, ExifSRational &r)
{
    return OutputRational<ExifSRational, int32_t>(is, r);
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
    value.clear();
    IMAGE_LOGD("Retrieving value for key: %{public}s", key.c_str());
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
                               "Exif data is null for key: %{public}s", key.c_str());
    if (!ExifMetadatFormatter::IsKeySupported(key)) {
        IMAGE_LOGD("Key is not supported.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (key == MAKER_NOTE_TAG) {
        return HandleMakerNote(value);
    }
    
    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") || IsSpecialHwKey(key)) {
        return HandleHwMnote(key, value);
    } else {
        auto tag = exif_tag_from_name(key.c_str());
        ExifEntry *entry = GetEntry(key);
        if (entry == nullptr) {
            IMAGE_LOGD("Exif data entry returned null for key: %{public}s, tag: %{public}d", key.c_str(), tag);
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
        IMAGE_LOGD("Using exif_entry_get_value for key: %{public}s, tag: %{public}d", key.c_str(), entry->tag);
        
        unsigned int tagValueSizeTmp = 0;
        if (entry->size >= TAG_VALUE_SIZE && (entry->format == EXIF_FORMAT_ASCII ||
            entry->format == EXIF_FORMAT_UNDEFINED)) {
            tagValueSizeTmp = entry->size + TERMINATOR_SIZE > MAX_TAG_VALUE_SIZE_FOR_STR ?
                MAX_TAG_VALUE_SIZE_FOR_STR : entry->size + TERMINATOR_SIZE;
        } else {
            tagValueSizeTmp = TAG_VALUE_SIZE;
        }
        char tagValueChar[tagValueSizeTmp];

        exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
        value = tagValueChar;
    }
    if (ExifMetadatFormatter::IsSensitiveInfo(key)) {
        IMAGE_LOGD("Retrieved value for key: %{public}s success", key.c_str());
    } else {
        IMAGE_LOGD("Retrieved value for key: %{public}s is: %{public}s", key.c_str(), value.c_str());
    }
    return SUCCESS;
}

const ImageMetadata::PropertyMapPtr ExifMetadata::GetAllProperties()
{
    ImageMetadata::PropertyMapPtr result = std::make_shared<ImageMetadata::PropertyMap>();
    std::string value;
    auto rwKeys = ExifMetadatFormatter::GetRWKeys();
    for (const auto& key : rwKeys) {
        if (GetValue(key, value) == SUCCESS) {
            result->insert(std::make_pair(key, value));
        }
    }
    auto roKeys = ExifMetadatFormatter::GetROKeys();
    for (const auto& key : roKeys) {
        if (GetValue(key, value) == SUCCESS) {
            result->insert(std::make_pair(key, value));
        }
    }
    IMAGE_LOGD("Get record arguments success.");
    return result;
}

std::shared_ptr<ImageMetadata> ExifMetadata::CloneMetadata()
{
    return Clone();
}

int ExifMetadata::HandleMakerNote(std::string &value) const
{
    value.clear();
    std::vector<char> tagValueChar(TAG_VALUE_SIZE, 0);
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    bool cond = false;
    if (md == nullptr) {
        IMAGE_LOGD("Exif data mnote data md is a nullptr.");
    }
    if (!is_huawei_md(md)) {
        return GetUserMakerNote(value);
    }
    MnoteHuaweiEntryCount *ec = nullptr;
    mnote_huawei_get_entry_count(reinterpret_cast<ExifMnoteDataHuawei *>(md), &ec);
    cond = ec == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        const char *mnoteKey = mnote_huawei_tag_get_name(entry->tag);
        if (HW_SPECIAL_KEYS.find(mnoteKey) != HW_SPECIAL_KEYS.end()) {
            continue;
        }
        mnote_huawei_entry_get_value(entry, tagValueChar.data(), tagValueChar.size());
        value += std::string(mnoteKey) + ":" + tagValueChar.data() + ",";
    }

    // Check if the last character of value is a comma and remove it
    if (value.length() > 1 && value[value.length() - 1] == ',') {
        value = value.substr(0, value.length() - 1);
    }
    mnote_huawei_free_entry_count(ec);

    return SUCCESS;
}

int ExifMetadata::HandleHwMnote(const std::string &key, std::string &value) const
{
    value = DEFAULT_EXIF_VALUE;
    char tagValueChar[TAG_VALUE_SIZE];
    if (key == HW_FOCUS_MODE_EXIF) {
        auto entry = exif_data_get_entry_ext(exifData_, EXIF_TAG_MAKER_NOTE);
        exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
        value = tagValueChar;
        bool cond = value.empty();
        CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
        return SUCCESS;
    }
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    bool cond = false;
    cond = md == nullptr;
    CHECK_DEBUG_RETURN_RET_LOG(cond, SUCCESS, "Exif data mnote data md is nullptr");
    cond = !is_huawei_md(md);
    CHECK_ERROR_RETURN_RET_LOG(cond, SUCCESS, "Exif data returned null for key: %{public}s", key.c_str());
    MnoteHuaweiEntryCount *ec = nullptr;
    mnote_huawei_get_entry_count(reinterpret_cast<ExifMnoteDataHuawei *>(md), &ec);
    cond = ec == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        if (entry == nullptr) {
            continue;
        }
        if (key == mnote_huawei_tag_get_name(entry->tag)) {
            mnote_huawei_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
            value = tagValueChar;
            break;
        }
    }
    mnote_huawei_free_entry_count(ec);
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
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to create new exif data.");

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

    if (size > MAX_EXIFMETADATA_MAX_SIZE) {
        IMAGE_LOGE("Failed to clone, the size of exif metadata exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_EXIFMETADATA_MAX_SIZE));
        return nullptr;
    }
    ExifData *newExifData = nullptr;
    TiffParser::Decode(dataBlob, size, &newExifData);
    bool cond = newExifData == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    std::shared_ptr<ExifMetadata> exifDataPtr = std::make_shared<ExifMetadata>(newExifData);
    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }
    return exifDataPtr;
}

ExifEntry *ExifMetadata::CreateEntry(const std::string &key, const ExifTag &tag, const size_t valueLen)
{
    ExifEntry *entry = exif_entry_new();
    bool cond = false;
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create new ExifEntry.");
    entry->tag = tag; // tag must be set before calling exif_content_add_entry
    auto ifdindex = exif_ifd_from_name(key.c_str());
    exif_content_add_entry(exifData_->ifd[ifdindex], entry);
    exif_entry_initialize(entry, tag);

    if (entry->format == EXIF_FORMAT_UNDEFINED && entry->size != valueLen) {
        exif_content_remove_entry(exifData_->ifd[ifdindex], entry);

        // Create a memory allocator to manage this ExifEntry
        ExifMem *exifMem = exif_mem_new_default();
        cond = exifMem == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create memory allocator for ExifEntry.");

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
    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create MnoteHuaweiEntry is not Huawei MakeNote.");

    ExifByteOrder order = exif_mnote_data_huawei_get_byte_order(md);
    MnoteHuaweiEntry* entry = mnote_huawei_entry_new(md);
    cond = !entry;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create MnoteHuaweiEntry.");

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    mnote_huawei_entry_initialize(entry, tag, order);
    return entry;
}

void ExifMetadata::ReallocEntry(ExifEntry *ptrEntry, const size_t valueLen)
{
    // Create a memory allocator to manage this ExifEntry
    ExifMem *exifMem = exif_mem_new_default();
    bool cond = exifMem == nullptr;
    CHECK_ERROR_RETURN_LOG(cond, "Failed to create memory allocator for ExifEntry. Value length: %{public}zu",
                           valueLen);
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

    bool cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetEntry entry is nullptr fail.");

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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifShort from string. Current count: %{public}lu", icount);
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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifLong from string. Current count: %{public}lu", icount);
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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSShort from string. Current count: %{public}lu", icount);
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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSLong from string. Current count: %{public}lu", icount);
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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifRational from string. Current count: %{public}lu", icount);
        unsigned long offset = icount * exif_format_get_size(ptrEntry->format);
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
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSRational from string. Current count: %{public}lu", icount);
        unsigned long offset = icount * exif_format_get_size(ptrEntry->format);
        exif_set_srational(ptrEntry->data + offset, order, rat);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetByte(ExifEntry *ptrEntry, const std::string &value)
{
    std::string result = std::accumulate(value.begin(), value.end(), std::string(), [](std::string res, char a) {
        if (a != ' ') {
            return res += a;
        }
        return res;
    });
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
    if (memcpy_s((ptrEntry)->data, valueLen, value.c_str(), valueLen) != 0) {
        IMAGE_LOGE("Failed to copy memory for ExifEntry. Requested size: %{public}zu", valueLen);
        return false;
    }
    return true;
}

bool ExifMetadata::SetValue(const std::string &key, const std::string &value)
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Exif data is null. Cannot set value for key: %{public}s", key.c_str());
    if (value.empty()) {
        IMAGE_LOGE("Set empty value.");
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
    if (key == MAKER_NOTE_TAG) {
        IMAGE_LOGD("Set MakerNote %{public}s", value.c_str());
        return SetMakerNoteValue(value);
    }

    return SetCommonValue(key, result.second);
}

bool ExifMetadata::SetMakerNoteValue(const std::string &value)
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "exifData_ is nullptr");
    cond = value.length() >= MAX_TAG_VALUE_SIZE_FOR_STR;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "value length is too long. length: %{public}zu", value.length());
    //clear all makernote data.
    ExifEntry *entry = nullptr;
    do {
        entry = exif_data_get_entry(exifData_, EXIF_TAG_MAKER_NOTE);
        if (entry != nullptr) {
            exif_content_remove_entry(entry->parent, entry);
        }
    } while (entry != nullptr);

    auto md = exif_data_get_mnote_data(exifData_);
    if (md != nullptr) {
        exif_mnote_data_unref(md);
        exif_data_set_priv_md(exifData_, nullptr);
    }

    size_t valueLen = value.length();
    entry = CreateEntry(MAKER_NOTE_TAG, EXIF_TAG_MAKER_NOTE, valueLen);
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Create entry is nullptr");
    if (memcpy_s(entry->data, entry->size, value.c_str(), valueLen) != 0) {
        IMAGE_LOGE("Failed to copy memory for ExifEntry. Requested size: %{public}zu", valueLen);
        return false;
    }

    bool isHwHead = entry->size > INIT_HW_DATA_HEAD_LENGTH &&
                        memcmp(entry->data, INIT_HW_DATA + EXIF_HEAD_SIZE, INIT_HW_DATA_HEAD_LENGTH) == 0;
    if (isHwHead) {
        uint32_t tempSize = EXIF_HEAD_SIZE + entry->size;
        std::vector<unsigned char> tempData(tempSize, 0);
        cond = memcpy_s(tempData.data() + EXIF_HEAD_SIZE, tempSize - EXIF_HEAD_SIZE, entry->data, entry->size) != EOK;
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "memcpy is failed");
        auto mem = exif_data_get_priv_mem(exifData_);
        auto hwMd = exif_mnote_data_huawei_new(mem);
        if (hwMd != nullptr) {
            exif_data_set_priv_md(exifData_, hwMd);
            exif_mnote_data_set_offset(hwMd, 0);
            exif_mnote_data_load(hwMd, tempData.data(), tempSize);
            IMAGE_LOGD("value is hw makernote data. load finished! res:%{public}d", is_huawei_md(hwMd));
        }
    }
    return true;
}

bool ExifMetadata::SetHwMoteValue(const std::string &key, const std::string &value)
{
    bool isNewMaker = false;
    if (key == HW_FOCUS_MODE_EXIF) {
        auto entry = exif_data_get_entry_ext(exifData_, EXIF_TAG_MAKER_NOTE);
        if (entry == nullptr) {
            entry = CreateEntry(key, EXIF_TAG_MAKER_NOTE, value.size() + 1);
        }
        if (entry != nullptr) {
            if ((entry->format == EXIF_FORMAT_UNDEFINED || entry->format == EXIF_FORMAT_ASCII) &&
            (entry->size != static_cast<unsigned int>(value.size() + 1))) {
                ReallocEntry(entry, value.size() + 1);
            }
            SetMem(entry, value, value.size() + 1);
        }
    }
    ExifMnoteData *md = GetHwMnoteData(isNewMaker);
    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "Makernote is not huawei makernote.");

    MnoteHuaweiTag hwTag = mnote_huawei_tag_from_name(key.c_str());
    cond = hwTag == MNOTE_HUAWEI_INFO;
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "The key: %{public}s is unknow hwTag", key.c_str());

    auto *entry = exif_mnote_data_huawei_get_entry_by_tag(reinterpret_cast<ExifMnoteDataHuawei *>(md), hwTag);
    if (!entry) {
        entry = CreateHwEntry(key);
        cond = !entry;
        CHECK_ERROR_RETURN_RET(cond, false);
        auto ret = exif_mnote_data_add_entry(md, entry);
        if (ret) {
            mnote_huawei_entry_free(entry);
            IMAGE_LOGE("Add new hw entry failed.");
            return false;
        }

        mnote_huawei_entry_free_contour(entry);
        entry = exif_mnote_data_huawei_get_entry_by_tag(reinterpret_cast<ExifMnoteDataHuawei *>(md), hwTag);
    }

    const char *data = value.c_str();
    int dataLen = value.length();
    int ret = mnote_huawei_entry_set_value(entry, data, dataLen);
    if (ret == 0 && isNewMaker && hwTag != MNOTE_HUAWEI_CAPTURE_MODE) {
        IMAGE_LOGD("Remve default initialized hw entry.");
        RemoveEntry(HW_CAPTURE_MODE);
    }
    return ret == 0 ? true : false;
}

ExifMnoteData* ExifMetadata::GetHwMnoteData(bool &isNewMaker)
{
    bool cond = false;
    cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    if (md != nullptr) {
        return md;
    }
    IMAGE_LOGD("Makenote not exist & ready to init makernote with hw entry.");
    ExifMem *mem = exif_data_get_priv_mem(exifData_);
    cond = mem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData exif data with no ExifMem.");
    md = exif_mnote_data_huawei_new(mem);
    cond = md == nullptr || md->methods.load == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData new mnote hw data failed.");
    exif_data_set_priv_md(exifData_, (ExifMnoteData *)md);
    unsigned long hwsize = sizeof(INIT_HW_DATA) / sizeof(INIT_HW_DATA[0]);
    md->methods.load(md, INIT_HW_DATA, hwsize);
    auto makernote = CreateEntry(MAKER_NOTE_TAG, EXIF_TAG_MAKER_NOTE, hwsize);
    cond = makernote == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData create maker note failed.");
    cond = memcpy_s(makernote->data, hwsize - EXIF_HEAD_SIZE, INIT_HW_DATA + EXIF_HEAD_SIZE,
                    hwsize - EXIF_HEAD_SIZE) != 0;
    CHECK_ERROR_PRINT_LOG(cond, "Failed to copy memory for ExifEntry. Requested size: %{public}lu", hwsize);
    isNewMaker = true;
    return md;
}

bool ExifMetadata::SetCommonValue(const std::string &key, const std::string &value)
{
    size_t valueLen = value.length();
    ExifEntry *ptrEntry = GetEntry(key, valueLen);
    bool cond = ptrEntry == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
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
    bool cond = false;
    cond = !(exifData_ && ExifMetadatFormatter::IsModifyAllowed(key));
    CHECK_DEBUG_RETURN_RET_LOG(cond, isSuccess,
                               "RemoveEntry failed, can not remove entry for key: %{public}s", key.c_str());

    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") ||
        IsSpecialHwKey(key)) {
        return RemoveHwEntry(key);
    }

    ExifEntry *entry = GetEntry(key);
    cond = !entry;
    CHECK_DEBUG_RETURN_RET_LOG(cond, isSuccess,
                               "RemoveEntry failed, can not find entry for key: %{public}s", key.c_str());

    IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
    exif_content_remove_entry(entry->parent, entry);
    isSuccess = true;
    return isSuccess;
}

bool ExifMetadata::RemoveHwEntry(const std::string &key)
{
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);

    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "Exif makernote is not huawei makernote");

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    auto *entry = exif_mnote_data_huawei_get_entry_by_tag((ExifMnoteDataHuawei*) md, tag);
    cond = !entry;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
                               "Get entry by tag failed, there is no entry for key: %{public}s", key.c_str());

    exif_mnote_data_remove_entry(md, entry);
    return true;
}

bool ExifMetadata::IsSpecialHwKey(const std::string &key) const
{
    auto iter = HW_SPECIAL_KEYS.find(key);
    return (iter != HW_SPECIAL_KEYS.end());
}

void ExifMetadata::GetFilterArea(const std::vector<std::string> &exifKeys,
                                 std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    if (exifData_ == nullptr) {
        IMAGE_LOGD("Exif data is null");
        return ;
    }
    auto size = exifKeys.size();
    for (unsigned long keySize = 0; keySize < size; keySize++) {
        ExifTag tag = exif_tag_from_name(exifKeys[keySize].c_str());
        FindRanges(tag, ranges);
    }
}

// If the tag is a rational or srational, we need to store the offset and size of the numerator
void ExifMetadata::FindRationalRanges(ExifContent *content,
    std::vector<std::pair<uint32_t, uint32_t>> &ranges, int index)
{
    for (unsigned long i = 0; i < content->entries[index]->components; i++) {
        std::pair<uint32_t, uint32_t> range =
            std::make_pair(content->entries[index]->offset +
            static_cast<unsigned long>(exif_format_get_size(content->entries[index]->format)) * i, NUMERATOR_SIZE);
        ranges.push_back(range);
    }
    return;
}

void ExifMetadata::FindRanges(const ExifTag &tag, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    bool hasRange = false;

    int ifd = 0;
    while (ifd < EXIF_IFD_COUNT && !hasRange) {
        ExifContent *content = exifData_->ifd[ifd];
        if (!content) {
            IMAGE_LOGD("IFD content is null, ifd: %{public}d.", ifd);
            return ;
        }

        int i = 0;
        while (i < static_cast<int>(content->count) && !hasRange) {
            if (tag == content->entries[i]->tag) {
                (content->entries[i]->format == EXIF_FORMAT_RATIONAL ||
                    content->entries[i]->format == EXIF_FORMAT_SRATIONAL)
                    ? FindRationalRanges(content, ranges, i)
                    : ranges.push_back(std::make_pair(content->entries[i]->offset, content->entries[i]->size));
                hasRange = true;
            }
            ++i;
        }
        ++ifd;
    }
}

bool ExifMetadata::Marshalling(Parcel &parcel) const
{
    if (exifData_ == nullptr) {
        return false;
    }

    unsigned char *data = nullptr;
    unsigned int size = 0;
    exif_data_save_data(exifData_, &data, &size);
    bool cond = false;

    if (!parcel.WriteBool(data != nullptr && size != 0)) {
        IMAGE_LOGE("Failed to write exif data buffer existence value.");
        return false;
    }

    cond = size > MAX_EXIFMETADATA_MAX_SIZE;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "The size of exif metadata exceeds the maximum limit.");

    if (data != nullptr && size != 0) {
        std::unique_ptr<unsigned char[]> exifData(data);
        if (!parcel.WriteUint32(static_cast<uint32_t>(size))) {
            return false;
        }
        cond = !parcel.WriteUnpadBuffer(exifData.get(), size);
        CHECK_ERROR_RETURN_RET(cond, false);
        return true;
    }
    return false;
}

ExifMetadata *ExifMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    ExifMetadata* dstExifMetadata = ExifMetadata::Unmarshalling(parcel, error);
    if (dstExifMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstExifMetadata;
}

ExifMetadata *ExifMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    bool hasExifDataBuffer = parcel.ReadBool();
    bool cond = false;
    if (hasExifDataBuffer) {
        uint32_t size = 0;
        if (!parcel.ReadUint32(size)) {
            return nullptr;
        }

        cond = size > MAX_EXIFMETADATA_MAX_SIZE;
        CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "The size of exif metadata exceeds the maximum limit.");
        
        const uint8_t *data = parcel.ReadUnpadBuffer(static_cast<size_t>(size));
        if (!data) {
            return nullptr;
        }
        ExifData *ptrData = exif_data_new();
        cond = ptrData == nullptr;
        CHECK_ERROR_RETURN_RET(cond, nullptr);
        exif_data_unset_option(ptrData, EXIF_DATA_OPTION_IGNORE_UNKNOWN_TAGS);
        exif_data_load_data(ptrData, static_cast<const unsigned char *>(data), static_cast<unsigned int>(size));
        ExifMetadata *exifMetadata = new(std::nothrow) ExifMetadata(ptrData);
        return exifMetadata;
    }
    return nullptr;
}

bool ExifMetadata::RemoveExifThumbnail()
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    exifData_->remove_thumbnail = 1;
    return true;
}

int ExifMetadata::GetUserMakerNote(std::string& value) const
{
    bool cond{false};
    std::vector<char> userValueChar(MAX_TAG_VALUE_SIZE_FOR_STR, 0);
    int count = exif_data_get_maker_note_entry_count(exifData_);
    cond = count != GET_SUPPORT_MAKERNOTE_COUNT;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ExifEntry *entry = exif_data_get_entry(exifData_, EXIF_TAG_MAKER_NOTE);
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    cond = entry->size >= MAX_TAG_VALUE_SIZE_FOR_STR;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    exif_entry_get_value(entry, userValueChar.data(), userValueChar.size());
    value.assign(userValueChar.data(), entry->size);
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS
