/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "exif_maker_note.h"
#include <memory>
#include "exif_info.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "securec.h"
#include "string_ex.h"
namespace OHOS {
namespace ImagePlugin {
using namespace HiviewDFX;
using namespace Media;
namespace {
constexpr HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ExifMakerNote" };
constexpr unsigned char EXIF_HEADER[] = {'E', 'x', 'i', 'f', '\0', '\0'};
constexpr unsigned char HW_MNOTE_HEADER[] = { 'H', 'U', 'A', 'W', 'E', 'I', '\0', '\0' };
constexpr unsigned char HW_MNOTE_TIFF_II[] = { 'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00 };
constexpr unsigned char HW_MNOTE_TIFF_MM[] = { 'M', 'M', 0x00, 0x2A, 0x00, 0x00, 0x00, 0x80 };
constexpr unsigned char HW_MNOTE_IFD_TAIL[] = { 0x00, 0x00, 0x00, 0x00 };
constexpr unsigned char JPEG_MARKER_SOI = 0xd8;
constexpr unsigned char JPEG_MARKER_APP0 = 0xe0;
constexpr unsigned char JPEG_MARKER_APP1 = 0xe1;
constexpr unsigned char JPEG_MARKER_APP15 = 0xef;
constexpr uint16_t TAG_MOCK = 0xffff;
constexpr uint32_t ENTRY_SIZE = 12;
constexpr uint32_t BUFFER_SIZE = 16;
constexpr uint32_t TEMP_BUFFER_SIZE = 1024;
constexpr uint32_t BACK_TO_EXIF_BEFORE = 6;
constexpr uint32_t JPEG_TAG_SIZE = 2;
constexpr uint32_t JPEG_CHECK_MIN_SIZE = 3;
constexpr uint32_t EXIF_MIN_SIZE = 14;
}

ExifMakerNote::ExifItem::ExifItem()
{
}

ExifMakerNote::ExifItem::ExifItem(const ExifMakerNote::ExifItem& item)
{
    CopyItem(item);
}

ExifMakerNote::ExifItem::~ExifItem()
{
    data.clear();
}

ExifMakerNote::ExifItem& ExifMakerNote::ExifItem::operator=(const ExifMakerNote::ExifItem& item)
{
    CopyItem(item);

    return *this;
}

void ExifMakerNote::ExifItem::CopyItem(const ExifMakerNote::ExifItem& item)
{
    ifd = item.ifd;
    tag = item.tag;
    format = item.format;
    count = item.count;
    data.assign(item.data.begin(), item.data.end());
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, const ExifByteOrder &order,
    bool mock)
{
    return GetValue(value, order, *this, mock);
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, ExifData *exifData, bool mock)
{
    return GetValue(value, exifData, *this, mock);
}

void ExifMakerNote::ExifItem::Dump(const std::string &info, const ExifByteOrder &order)
{
    Dump(info, *this, order);
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, const ExifByteOrder &order,
    ExifMakerNote::ExifItem &item, bool mock)
{
    auto *exifData = exif_data_new();
    if (exifData == nullptr) {
        HiLog::Error(LABEL, "GetValue, data is null.");
        return false;
    }
    exif_data_set_byte_order(exifData, order);

    auto ret = GetValue(value, exifData, item, mock);

    exif_data_unref(exifData);

    return ret;
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, ExifData *exifData,
    ExifMakerNote::ExifItem &item, bool mock)
{
    auto *exifContent = exif_content_new();
    if (exifContent == nullptr) {
        HiLog::Error(LABEL, "GetValue, content is null.");
        return false;
    }

    auto *keepParent = exifContent->parent;

    exifContent->parent = exifData;

    auto ret = GetValue(value, exifContent, item, mock);

    exifContent->parent = keepParent;

    exif_content_unref(exifContent);

    return ret;
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, ExifContent *exifContent,
    ExifMakerNote::ExifItem &item, bool &mock)
{
    auto *exifEntry = exif_entry_new();
    if (exifEntry == nullptr) {
        HiLog::Error(LABEL, "GetValue, item is null.");
        return false;
    }

    auto *keepParent = exifEntry->parent;
    auto keepTag = exifEntry->tag;
    auto keepFormat = exifEntry->format;
    auto keepComponents = exifEntry->components;
    auto *keepData = exifEntry->data;
    auto keepSize = exifEntry->size;

    exifEntry->parent = exifContent;

    auto ret = GetValue(value, exifEntry, item, mock);

    exifEntry->size = keepSize;
    exifEntry->data = keepData;
    exifEntry->components = keepComponents;
    exifEntry->format = keepFormat;
    exifEntry->tag = keepTag;
    exifEntry->parent = keepParent;

    exif_entry_unref(exifEntry);

    return ret;
}

bool ExifMakerNote::ExifItem::GetValue(std::string &value, ExifEntry *exifEntry,
    ExifMakerNote::ExifItem &item, bool &mock)
{
    exifEntry->tag = static_cast<ExifTag>(mock ? TAG_MOCK : item.tag);
    exifEntry->format = static_cast<ExifFormat>(item.format);
    exifEntry->components = item.count;
    exifEntry->data = item.data.data();
    exifEntry->size = item.data.size();

    auto tmpbuf = std::make_unique<char[]>(TEMP_BUFFER_SIZE);
    if (tmpbuf == nullptr) {
        HiLog::Error(LABEL, "GetValue, buffer is null.");
        return false;
    }

    exif_entry_get_value(exifEntry, tmpbuf.get(), TEMP_BUFFER_SIZE);
    value.assign(tmpbuf.get());

    return true;
}

void ExifMakerNote::ExifItem::Dump(const std::string &info, const ExifMakerNote::ExifItem &item,
    const ExifByteOrder &order)
{
    uint32_t dataOrOffset = 0;
    if (!ExifMakerNote::GetUInt32(item.data, order, 0, dataOrOffset)) {
        HiLog::Error(LABEL, "Dump, data");
        return;
    }

    HiLog::Debug(LABEL, "%{public}s, "
        "ifd=0x%{public}x, tag=0x%{public}04x, fmt=%{public}u, cnt=%{public}u, "
        "dataOrOffset=%{public}u(0x%{public}08x), data=[%{public}s]",
        info.c_str(),
        item.ifd, item.tag, item.format, item.count, dataOrOffset, dataOrOffset,
        ExifMakerNote::Dump(item.data).c_str());
}

ExifMakerNote::ExifMakerNote()
{
    hwCaptureMode = EXIFInfo::DEFAULT_EXIF_VALUE;
    hwPhysicalAperture = EXIFInfo::DEFAULT_EXIF_VALUE;
}

ExifMakerNote::~ExifMakerNote()
{
}

uint32_t ExifMakerNote::Parser(ExifData *exif, const unsigned char *data, uint32_t size)
{
    HiLog::Debug(LABEL, "Parser enter");

    bool moreCheck = false;
    uint32_t res = ParserMakerNote(exif, moreCheck);
    if ((res == Media::SUCCESS) || (!moreCheck)) {
        HiLog::Debug(LABEL, "Parser leave");
        return Media::SUCCESS;
    }

    if ((data == nullptr) || (size < sizeof(EXIF_HEADER))) {
        HiLog::Error(LABEL, "Parser leave. check");
        return Media::ERROR;
    }

    const unsigned char *newData = nullptr;
    uint32_t newSize = 0;
    if (!FindExifLocation(data, size, newData, newSize)) {
        HiLog::Error(LABEL, "Parser leave. findExifLocation");
        return Media::ERROR;
    }

    data = newData - BACK_TO_EXIF_BEFORE;
    size = newSize + BACK_TO_EXIF_BEFORE;

    ByteOrderedBuffer boBuffer(data, size);
    boBuffer.GenerateDEArray();

    for (auto &de : boBuffer.directoryEntryArray_) {
        if (de.tag != EXIF_TAG_MAKER_NOTE) {
            continue;
        }

        HiLog::Debug(LABEL, "Parser, find, ifd=%{public}u, tag=0x%{public}04x, fmt=%{public}u, "
            "num=%{public}u, valueOffset=%{public}u, valueLength=%{public}u",
            de.ifd, de.tag, de.format, de.dataCounts, de.valueOffset, de.valueLength);

        if (ParserMakerNote(data + de.valueOffset, de.valueLength) == Media::SUCCESS) {
            HiLog::Debug(LABEL, "Parser leave");
            return Media::SUCCESS;
        }
    }

    HiLog::Debug(LABEL, "Parser leave");
    return Media::ERROR;
}

bool ExifMakerNote::FindExifLocation(const unsigned char *data, uint32_t size,
    const unsigned char *&newData, uint32_t &newSize)
{
    HiLog::Debug(LABEL, "FindExifLocation enter");

    if (size < sizeof(EXIF_HEADER)) {
        HiLog::Error(LABEL, "FindExifLocation, small. size=%{public}u", size);
        return false;
    }

    const unsigned char *d = data;
    if (memcmp(d, EXIF_HEADER, sizeof(EXIF_HEADER)) != 0) {
        if (!FindJpegAPP1(d, size, d, size)) {
            HiLog::Error(LABEL, "FindExifLocation leave, findJpegAPP1.");
            return false;
        }

        d++;
        size--;
        unsigned int len = (d[0] << 8) | d[1];
        HiLog::Debug(LABEL, "FindExifLocation, len=%{public}u", len);

        d += JPEG_TAG_SIZE;
        size -= JPEG_TAG_SIZE;
    }

    if (size < EXIF_MIN_SIZE) {
        HiLog::Error(LABEL, "FindExifLocation, small.");
        return false;
    }

    if (memcmp(d, EXIF_HEADER, sizeof(EXIF_HEADER)) != 0) {
        HiLog::Error(LABEL, "FindExifLocation, no found EXIF header");
        return false;
    }

    HiLog::Debug(LABEL, "FindExifLocation, Found EXIF header");

    newData = d;
    newSize = size;

    HiLog::Debug(LABEL, "FindExifLocation leave");
    return true;
}

bool ExifMakerNote::FindJpegAPP1(const unsigned char *data, uint32_t size,
    const unsigned char *&newData, uint32_t &newSize)
{
    HiLog::Debug(LABEL, "FindJpegAPP1 enter");

    while (size >= JPEG_CHECK_MIN_SIZE) {
        while (size && (data[0] == 0xff)) {
            data++;
            size--;
        }

        if (size && data[0] == JPEG_MARKER_SOI) {
            data++;
            size--;
            continue;
        }

        if (size && data[0] == JPEG_MARKER_APP1) {
            break;
        }

        if (size >= JPEG_CHECK_MIN_SIZE && data[0] >= JPEG_MARKER_APP0 && data[0] <= JPEG_MARKER_APP15) {
            data++;
            size--;
            unsigned int l = (data[0] << 8) | data[1];
            if (l > size) {
                HiLog::Error(LABEL, "FindJpegAPP1, small.");
                return false;
            }
            data += l;
            size -= l;
            continue;
        }

        HiLog::Error(LABEL, "FindJpegAPP1, Unknown.");
        return false;
    }

    if (size < JPEG_CHECK_MIN_SIZE) {
        HiLog::Error(LABEL, "FindJpegAPP1, small2.");
        return false;
    }

    newData = data;
    newSize = size;

    HiLog::Debug(LABEL, "FindJpegAPP1 leave");
    return true;
}

uint32_t ExifMakerNote::ParserMakerNote(ExifData* exif, bool &moreCheck)
{
    HiLog::Debug(LABEL, "ParserMakerNote enter");

    moreCheck = false;

    if (exif == nullptr) {
        HiLog::Fatal(LABEL, "ParserMakerNote, exif is null.");
        return Media::ERROR;
    }

    auto *ee = exif_data_get_entry (exif, EXIF_TAG_MAKER_NOTE);
    auto *md = exif_data_get_mnote_data(exif);
    if ((ee == nullptr) || (md != nullptr)) {
        HiLog::Debug(LABEL, "ParserMakerNote leave");
        return Media::ERROR;
    }

    HiLog::Info(LABEL, "need parser mnote.");

    if (ParserMakerNote(ee->data, ee->size) == Media::SUCCESS) {
        HiLog::Debug(LABEL, "ParserMakerNote leave");
        return Media::SUCCESS;
    }

    moreCheck = true;

    HiLog::Debug(LABEL, "ParserMakerNote leave");
    return Media::ERROR;
}

uint32_t ExifMakerNote::ParserMakerNote(const unsigned char *data, uint32_t size)
{
    HiLog::Debug(LABEL, "ParserMakerNote enter");

    if (!IsHwMakerNote(data, size)) {
        HiLog::Debug(LABEL, "ParserMakerNote leave");
        return Media::ERROR;
    }

    makerNote_.resize(size);
    if (memcpy_s(makerNote_.data(), makerNote_.size(), data, size) != 0) {
        HiLog::Error(LABEL, "memcpy error");
        return Media::ERROR;
    }

    ParserHwMakerNote();

    HiLog::Debug(LABEL, "ParserMakerNote leave");
    return Media::SUCCESS;
}

bool ExifMakerNote::IsParsed() const
{
    return (tiff_offset_ > 0) && (ifd0_offset_ > 0);
}

bool ExifMakerNote::IsHwMakerNote(const unsigned char *data, uint32_t size)
{
    HiLog::Debug(LABEL, "IsHwMakerNote enter");

    tiff_offset_ = 0;
    ifd0_offset_ = 0;

    if (sizeof(HW_MNOTE_TIFF_II) != sizeof(HW_MNOTE_TIFF_MM)) {
        HiLog::Fatal(LABEL, "IsHwMakerNote leave, same");
        return false;
    }
    if (size < (sizeof(HW_MNOTE_HEADER) + sizeof(HW_MNOTE_TIFF_II))) {
        HiLog::Debug(LABEL, "IsHwMakerNote leave, size");
        return false;
    }

    if (memcmp(data, HW_MNOTE_HEADER, sizeof(HW_MNOTE_HEADER)) != 0) {
        HiLog::Debug(LABEL, "IsHwMakerNote leave, hd");
        return false;
    }

    tiff_offset_ = sizeof(HW_MNOTE_HEADER);

    if (memcmp((data + tiff_offset_), HW_MNOTE_TIFF_II, sizeof(HW_MNOTE_TIFF_II)) == 0) {
        order_ = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
        ifd0_offset_ = tiff_offset_ + sizeof(HW_MNOTE_TIFF_II);
        HiLog::Debug(LABEL, "IsHwMakerNote leave, ii, tiff=%{public}u, ifd0=%{public}u", tiff_offset_, ifd0_offset_);
        return true;
    }

    if (memcmp((data+ tiff_offset_), HW_MNOTE_TIFF_MM, sizeof(HW_MNOTE_TIFF_MM)) == 0) {
        order_ = ExifByteOrder::EXIF_BYTE_ORDER_MOTOROLA;
        ifd0_offset_ = tiff_offset_ + sizeof(HW_MNOTE_TIFF_MM);
        HiLog::Debug(LABEL, "IsHwMakerNote leave, mm, tiff=%{public}u, ifd0=%{public}u", tiff_offset_, ifd0_offset_);
        return true;
    }

    HiLog::Error(LABEL, "byte order error");

    HiLog::Debug(LABEL, "IsHwMakerNote leave, order");
    return false;
}

bool ExifMakerNote::ParserHwMakerNote()
{
    HiLog::Debug(LABEL, "ParserHwMakerNote enter");

    bool ret = ParserIFD(ifd0_offset_, HW_MNOTE_IFD_DEFAULT);

    for (auto &entry : items_) {
        entry.Dump("ParserHwMakerNote", order_);

        std::string value;
        auto res = entry.GetValue(value, order_, true);
        if (!res) {
            continue;
        }

        SetValue(entry, value);
    }

    HiLog::Debug(LABEL, "ParserHwMakerNote leave, ret=%{public}u", ret);
    return ret;
}

bool ExifMakerNote::ParserIFD(uint32_t offset, uint32_t ifd, uint32_t deep)
{
    HiLog::Debug(LABEL, "ParserIFD enter, offset=%{public}u, ifd=%{public}u, deep=%{public}u", offset, ifd, deep);

    uint16_t count = 0;
    if (!GetUInt16AndMove(offset, count)) {
        HiLog::Error(LABEL, "ParserIFD leave, count, false");
        return false;
    }
    HiLog::Debug(LABEL, "ParserIFD, count=%{public}u", count);

    for (uint16_t i = 0; i < count; i++) {
        if (ParserItem(offset, ifd, deep)) {
            offset += (sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t));
            continue;
        }

        HiLog::Error(LABEL, "ParserIFD leave, entry, false");
        return false;
    }

    if (memcmp(makerNote_.data() + offset, HW_MNOTE_IFD_TAIL, sizeof(HW_MNOTE_IFD_TAIL)) != 0) {
        HiLog::Error(LABEL, "ParserIFD leave, tail, false");
        return false;
    }

    HiLog::Debug(LABEL, "ParserIFD leave, true");
    return true;
}

bool ExifMakerNote::ParserItem(uint32_t offset, uint32_t ifd, uint32_t deep)
{
    HiLog::Debug(LABEL, "ParserItem enter, offset=%{public}u, deep=%{public}u, data=[%{public}s]",
        offset, deep, ExifMakerNote::Dump(makerNote_, offset, ENTRY_SIZE).c_str());

    uint16_t tag = 0;
    uint16_t format = 0;
    uint32_t components = 0;
    uint32_t dataOrOffset = 0;
    if (!GetUInt16AndMove(offset, tag)) {
        HiLog::Error(LABEL, "ParserItem leave, tag, false");
        return false;
    }
    if (!GetUInt16AndMove(offset, format)) {
        HiLog::Error(LABEL, "ParserItem leave, format, false");
        return false;
    }
    if (!GetUInt32AndMove(offset, components)) {
        HiLog::Error(LABEL, "ParserItem leave, components, false");
        return false;
    }
    if (!GetUInt32(offset, dataOrOffset)) {
        HiLog::Error(LABEL, "ParserItem leave, data, false");
        return false;
    }

    items_.emplace_back(ExifItem());
    ExifItem &back = items_.back();
    back.ifd = ifd;
    back.tag = tag;
    back.format = format;
    back.count = components;
    GetData(offset, sizeof(uint32_t), back.data);
    back.Dump("ParserItem", order_);

    if (deep > 0) {
        HiLog::Debug(LABEL, "ParserItem leave, deep=%{public}u", deep);
        return true;
    }

    if ((back.tag == HW_MNOTE_TAG_SCENE_INFO_OFFSET) || (back.tag ==  HW_MNOTE_TAG_FACE_INFO_OFFSET)) {
        if (!ParserIFD((tiff_offset_ + dataOrOffset), back.tag, (deep + 1))) {
            HiLog::Error(LABEL, "ParserItem leave, ifd, false");
            return false;
        }
    }

    HiLog::Debug(LABEL, "ParserItem leave");
    return true;
}

bool ExifMakerNote::SetValue(const ExifItem &entry, const std::string &value)
{
    if (entry.tag == HW_MNOTE_TAG_CAPTURE_MODE) {
        hwCaptureMode = value;
        return true;
    }

    if (entry.tag == HW_MNOTE_TAG_PHYSICAL_APERTURE) {
        hwPhysicalAperture = value;
        return true;
    }

    return false;
}

bool ExifMakerNote::GetUInt16AndMove(uint32_t &offset, uint16_t &value)
{
    if (GetUInt16(offset, value)) {
        offset += sizeof(uint16_t);
        return true;
    }
    return false;
}

bool ExifMakerNote::GetUInt32AndMove(uint32_t &offset, uint32_t &value)
{
    if (GetUInt32(offset, value)) {
        offset += sizeof(uint32_t);
        return true;
    }
    return false;
}

bool ExifMakerNote::GetDataAndMove(size_t &offset, size_t count, std::vector<unsigned char> &value)
{
    if (GetData(offset, count, value)) {
        offset += count;
        return true;
    }
    return false;
}

bool ExifMakerNote::GetUInt16(uint32_t offset, uint16_t &value)
{
    return ExifMakerNote::GetUInt16(makerNote_, order_, offset, value);
}

bool ExifMakerNote::GetUInt32(uint32_t offset, uint32_t &value)
{
    return ExifMakerNote::GetUInt32(makerNote_, order_, offset, value);
}

bool ExifMakerNote::GetData(size_t offset, size_t count, std::vector<unsigned char> &value)
{
    return ExifMakerNote::GetData(makerNote_, offset, count, value);
}

bool ExifMakerNote::GetUInt16(const std::vector<unsigned char> &buffer, ExifByteOrder order,
    size_t offset, uint16_t &value)
{
    if ((offset + sizeof(uint16_t)) > buffer.size()) {
        HiLog::Error(LABEL, "GetUInt16 check error.");
        return false;
    }
    value = exif_get_short(buffer.data() + offset, order);
    return true;
}

bool ExifMakerNote::GetUInt32(const std::vector<unsigned char> &buffer, ExifByteOrder order,
    size_t offset, uint32_t &value)
{
    if ((offset + sizeof(uint32_t)) > buffer.size()) {
        HiLog::Error(LABEL, "GetUInt32 check error.");
        return false;
    }
    value = exif_get_long(buffer.data() + offset, order);
    return true;
}

bool ExifMakerNote::GetData(const std::vector<unsigned char> &buffer, size_t offset, size_t count,
    std::vector<unsigned char> &value)
{
    if ((offset + count) > buffer.size()) {
        HiLog::Error(LABEL, "GetData check error.");
        return false;
    }

    value.resize(count);
    if (memcpy_s(value.data(), count, buffer.data() + offset, count) != 0) {
        HiLog::Error(LABEL, "GetData memcpy error.");
        return false;
    }

    return true;
}

std::string ExifMakerNote::Dump(const std::vector<unsigned char> &data, uint32_t offset, uint32_t sum)
{
    std::string ret;
    char buffer[BUFFER_SIZE] = {0};

    auto size = data.size();
    for (size_t loc = 0, cur = offset; ((loc < sum) && (cur < size)); loc++, cur++) {
        if (loc == 0) {
            if (sprintf_s(buffer, sizeof(buffer), "%02X", data[cur]) == -1) {
                HiLog::Error(LABEL, "Dump sprintf error.");
                break;
            }
        } else {
            if (sprintf_s(buffer, sizeof(buffer), " %02X", data[cur]) == -1) {
                HiLog::Error(LABEL, "Dump sprintf error.");
                break;
            }
        }
        ret.append(buffer);
    }

    return ret;
}
} // namespace ImagePlugin
} // namespace OHOS