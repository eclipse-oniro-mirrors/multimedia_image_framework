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

#include "jpeg_mpf_parser.h"

#include <vector>
#include <array>
#include "hilog/log_cpp.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_func_timer.h"
#include "media_errors.h"
#include "picture.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "JpegMpfParser"

namespace OHOS {
namespace Media {

using namespace std;

constexpr uint8_t MP_INDEX_IFD_BYTE_SIZE = 12;
constexpr uint8_t MP_ENTRY_BYTE_SIZE = 16;
constexpr uint8_t UINT16_BYTE_SIZE = 2;
constexpr uint8_t UINT32_BYTE_SIZE = 4;
constexpr uint16_t TAG_TYPE_UNDEFINED = 0x07;
constexpr uint16_t TAG_TYPE_LONG = 0x04;
constexpr uint16_t HDR_MULTI_PICTURE_APP_LENGTH = 90;
constexpr uint16_t FRAGMENT_METADATA_LENGTH = 20;
constexpr uint16_t TAG_FIRST_BYTE_TABLE_SIZE = 256;

constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP2 = 0xE2;

constexpr uint8_t MAX_IMAGE_NUM = 32;
constexpr uint32_t JPEG_MARKER_SIZE = 2;


static constexpr uint8_t MULTI_PICTURE_HEADER_FLAG[] = {
    'M', 'P', 'F', '\0'
};
static constexpr uint8_t BIG_ENDIAN_FLAG[] = {
    0x4D, 0x4D, 0x00, 0x2A
};
static constexpr uint8_t LITTLE_ENDIAN_FLAG[] = {
    0x49, 0x49, 0x2A, 0x00
};

static constexpr uint8_t MPF_VERSION_DEFAULT[] = {
    '0', '1', '0', '0'
};

static constexpr uint8_t FRAGMENT_META_FLAG[] = {
    0xFF, 0xEC, 0x00, 0x12
};

enum MpfIFDTag : uint16_t {
    MPF_VERSION_TAG = 45056,
    NUMBERS_OF_IMAGES_TAG = 45057,
    MP_ENTRY_TAG = 45058,
    IMAGE_UID_LIST_TAG = 45059,
    TOTAL_FRAMES_TAG = 45060,
};

static const std::map<MetadataType, std::vector<std::string>> BLOB_METADATA_DECODE_TAG_MAP = {
    {MetadataType::XTSTYLE, {METADATA_TAG_XTSTYLE}},
    {MetadataType::RFDATAB, {
        METADATA_TAG_RFDATAB, METADATA_TAG_RFDATAB_DEPTHEN, std::string(METADATA_TAG_RFDATAB_DEPTHP, TAG_NAME_LENGTH)
    }},
    {MetadataType::RESMAP, {METADATA_TAG_RESMAP}},
    {MetadataType::STDATA, {METADATA_TAG_STDATA}},
};

bool JpegMpfParser::CheckMpfOffset(uint8_t* data, uint32_t size, uint32_t& offset)
{
    if (data == nullptr || size < JPEG_MARKER_SIZE) {
        return false;
    }
    for (offset = 0; offset < size - 1; offset++) {
        if (data[offset] == JPEG_MARKER_PREFIX && (data[offset + 1] == JPEG_MARKER_APP2)) {
            if (offset + UINT32_BYTE_SIZE > size) {
                return false;
            }
            offset += UINT32_BYTE_SIZE;
            return true;
        }
    }
    return false;
}

bool JpegMpfParser::Parsing(uint8_t* data, uint32_t size)
{
    if (data == nullptr || size == 0 || size < sizeof(MULTI_PICTURE_HEADER_FLAG)) {
        return false;
    }
    if (memcmp(data, MULTI_PICTURE_HEADER_FLAG, sizeof(MULTI_PICTURE_HEADER_FLAG)) != 0) {
        return false;
    }
    if (size < UINT32_BYTE_SIZE) {
        return false;
    }
    data += UINT32_BYTE_SIZE;
    size -= UINT32_BYTE_SIZE;
    uint32_t dataOffset = 0;
    bool isBigEndian = false;
    if (memcmp(data, BIG_ENDIAN_FLAG, sizeof(BIG_ENDIAN_FLAG)) == 0) {
        isBigEndian = true;
    } else if (memcmp(data, LITTLE_ENDIAN_FLAG, sizeof(LITTLE_ENDIAN_FLAG)) == 0) {
        isBigEndian = false;
    } else {
        return false;
    }
    dataOffset += UINT32_BYTE_SIZE;
    uint32_t ifdOffset = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
    if (ifdOffset < dataOffset || ifdOffset > size) {
        IMAGE_LOGD("get ifd offset error");
        return false;
    }
    dataOffset = ifdOffset;
    return ParsingMpIndexIFD(data, size, dataOffset, isBigEndian);
}

bool JpegMpfParser::ParsingMpIndexIFD(uint8_t* data, uint32_t size, uint32_t dataOffset, bool isBigEndian)
{
    uint16_t tagCount = ImageUtils::BytesToUint16(data, dataOffset, size, isBigEndian);
    if (dataOffset + MP_INDEX_IFD_BYTE_SIZE * tagCount > size) {
        return false;
    }
    uint16_t previousTag = 0;
    for (uint16_t i = 0; i < tagCount; i++) {
        uint16_t tag = ImageUtils::BytesToUint16(data, dataOffset, size, isBigEndian);
        if (tag <= previousTag) {
            return false;
        }
        previousTag = tag;
        uint16_t type = ImageUtils::BytesToUint16(data, dataOffset, size, isBigEndian);
        uint32_t count = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
        uint32_t value = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
        IMAGE_LOGD("mpf tag=%{public}d,type=%{public}d,count=%{public}d,value=%{public}d", tag, type, count, value);
        switch (tag) {
            case MpfIFDTag::MPF_VERSION_TAG:
                if (dataOffset - UINT32_BYTE_SIZE < 0 || memcmp(data + (dataOffset - UINT32_BYTE_SIZE),
                    MPF_VERSION_DEFAULT, sizeof(MPF_VERSION_DEFAULT)) != 0) {
                    return false;
                }
                break;
            case MpfIFDTag::NUMBERS_OF_IMAGES_TAG:
                imageNums_ = value;
                break;
            case MpfIFDTag::MP_ENTRY_TAG:
                if (count != MP_ENTRY_BYTE_SIZE * imageNums_ || value < dataOffset || value > size) {
                    return false;
                }
                if (!ParsingMpEntry(data + value, size - value, isBigEndian, imageNums_)) {
                    IMAGE_LOGD("mpf parse entry failed");
                    return false;
                }
                break;
            default:
                break;
        }
    }
    uint32_t mpAttrIFDOffset = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
    if (mpAttrIFDOffset > 0 && dataOffset > mpAttrIFDOffset) {
        return false;
    }
    return true;
}

bool JpegMpfParser::ParsingMpEntry(uint8_t* data, uint32_t size, bool isBigEndian, uint32_t imageNums)
{
    uint32_t dataOffset = 0;
    if (imageNums == 0 || imageNums * MP_ENTRY_BYTE_SIZE > size || imageNums > MAX_IMAGE_NUM) {
        IMAGE_LOGE("Parsing imageNums error");
        return false;
    }
    images_.resize(imageNums);
    for (uint32_t i = 0; i < imageNums; i++) {
        uint32_t imageAttr = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
        images_[i].size = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
        images_[i].offset = ImageUtils::BytesToUint32(data, dataOffset, size, isBigEndian);
        uint16_t image1EntryNum = ImageUtils::BytesToUint16(data, dataOffset, size, isBigEndian);
        uint16_t image2EntryNum = ImageUtils::BytesToUint16(data, dataOffset, size, isBigEndian);
        IMAGE_LOGD("index=%{public}d, imageAttr=%{public}d, image1entrynum=%{public}d, image2entryNum=%{public}d",
            i, imageAttr, image1EntryNum, image2EntryNum);
    }
    return true;
}

// |<------------------ Auxiliary picture/Blob Metadata structure ----------------->|
// |<- Image data ->|<- Image size(4 Bytes) ->|<- Tag name(8 Bytes) ->|
static void BuildKnownTagFirstByte(std::array<bool, TAG_FIRST_BYTE_TABLE_SIZE>& table)
{
    table.fill(false);
    for (const auto &kv : AUXILIARY_TAG_TYPE_MAP) {
        if (!kv.first.empty()) {
            unsigned char first = static_cast<unsigned char>(kv.first[0]);
            table[first] = true;
        }
    }
    for (const auto &kv : BLOB_METADATA_TAG_TYPE_MAP) {
        if (!kv.first.empty()) {
            unsigned char first = static_cast<unsigned char>(kv.first[0]);
            table[first] = true;
        }
    }
}

bool JpegMpfParser::TryMatchBlobAt(uint8_t* data, uint32_t dataSize, uint32_t tagOffset, uint32_t &nextOffset)
{
    const uint8_t firstByte = data[tagOffset];
    for (const auto &kv : BLOB_METADATA_TAG_TYPE_MAP) {
        const std::string &tagName = kv.first;
        const MetadataType metadataType = kv.second;
        const size_t tagLength = tagName.size();
        if (tagLength == 0 || tagOffset + tagLength > dataSize) {
            continue;
        }
        if (static_cast<uint8_t>(tagName[0]) != firstByte) {
            continue;
        }
        if (memcmp(data + tagOffset, tagName.data(), tagLength) != 0) {
            continue;
        }

        if (tagOffset < UINT32_BYTE_SIZE) {
            return false;
        }
        const uint32_t sizeOffset = tagOffset - UINT32_BYTE_SIZE;
        uint32_t tmpOffset = sizeOffset;
        const uint32_t payloadSize = ImageUtils::BytesToUint32(data, tmpOffset, dataSize, false);
        if (payloadSize == 0 || payloadSize > sizeOffset) {
            return false;
        }

        const uint32_t dataStart = sizeOffset - payloadSize;
        blobMetadatas_.push_back(SingleBlobMetadata{
            .offset = dataStart,
            .size = payloadSize,
            .blobType = metadataType,
        });

        IMAGE_LOGD(
            "[%{public}s] Blob metadata found: type=%{public}d, offset=%{public}u, size=%{public}u, tag=%{public}s",
            __func__, metadataType, dataStart, dataSize, tagName.c_str());

        nextOffset = dataStart;
        return true;
    }
    return false;
}

bool JpegMpfParser::TryMatchAuxAt(uint8_t* data, uint32_t dataSize, uint32_t tagOffset, uint32_t &nextOffset)
{
    const uint8_t firstByte = data[tagOffset];
    for (const auto &kv : AUXILIARY_TAG_TYPE_MAP) {
        const std::string &tagName = kv.first;
        const AuxiliaryPictureType auxType = kv.second;
        const size_t tagLength = tagName.size();
        if (tagLength == 0 || tagOffset + tagLength > dataSize) {
            continue;
        }
        if (static_cast<uint8_t>(tagName[0]) != firstByte) {
            continue;
        }
        if (memcmp(data + tagOffset, tagName.data(), tagLength) != 0) {
            continue;
        }

        if (tagOffset < UINT32_BYTE_SIZE) {
            return false;
        }
        const uint32_t sizeOffset = tagOffset - UINT32_BYTE_SIZE;
        uint32_t tmpOffset = sizeOffset;
        const uint32_t imageSize = ImageUtils::BytesToUint32(data, tmpOffset, dataSize, false);
        if (imageSize == 0 || imageSize > sizeOffset) {
            return false;
        }

        const uint32_t dataStart = sizeOffset - imageSize;
        images_.push_back(SingleJpegImage{
            .offset = dataStart,
            .size = imageSize,
            .auxType = auxType,
            .auxTagName = tagName,
        });

        IMAGE_LOGD(
            "[%{public}s] Auxiliary picture found: type=%{public}d, offset=%{public}u, size=%{public}u, tag=%{public}s",
            __func__, auxType, dataStart, imageSize, tagName.c_str());

        nextOffset = dataStart;
        return true;
    }
    return false;
}

bool JpegMpfParser::ParsingExtendInfo(uint8_t* data, uint32_t dataSize, bool isBigEndian)
{
    ImageFuncTimer imageFuncTimer("%s enter", __func__);
    if (data == nullptr || dataSize == 0) {
        return false;
    }

    std::array<bool, TAG_FIRST_BYTE_TABLE_SIZE> firstByteLookup{};
    BuildKnownTagFirstByte(firstByteLookup);

    uint32_t currentOffset = (dataSize >= TAG_NAME_LENGTH) ? (dataSize - TAG_NAME_LENGTH) : 0;
    while (currentOffset > 0) {
        const uint8_t firstByte = data[currentOffset];
        if (!firstByteLookup[firstByte]) {
            --currentOffset;
            continue;
        }

        uint32_t nextOffsetBlob = 0;
        bool matchBlob = TryMatchBlobAt(data, dataSize, currentOffset, nextOffsetBlob);
        uint32_t nextOffsetAux = 0;
        bool matchAux = TryMatchAuxAt(data, dataSize, currentOffset, nextOffsetAux);
        if (matchBlob && matchAux && nextOffsetBlob != nextOffsetAux) {
            return false;
        }
        if (matchBlob || matchAux) {
            currentOffset = matchBlob ? nextOffsetBlob : nextOffsetAux;
            continue;
        }
        --currentOffset;
    }
    return true;
}

bool JpegMpfParser::ParsingFragmentMetadata(uint8_t* data, uint32_t size, Rect& fragmentRect, bool isBigEndian)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    for (uint32_t offset = 0; offset < size; offset++) {
        if (offset + FRAGMENT_METADATA_LENGTH + sizeof(FRAGMENT_META_FLAG) > size) {
            return false;
        }
        if (memcmp(data + offset, FRAGMENT_META_FLAG, sizeof(FRAGMENT_META_FLAG)) == 0) {
            offset += UINT32_BYTE_SIZE;
            fragmentRect.left = ImageUtils::BytesToInt32(data, offset, size, isBigEndian);
            fragmentRect.top = ImageUtils::BytesToInt32(data, offset, size, isBigEndian);
            fragmentRect.width = ImageUtils::BytesToInt32(data, offset, size, isBigEndian);
            fragmentRect.height = ImageUtils::BytesToInt32(data, offset, size, isBigEndian);
            IMAGE_LOGD("[%{public}s] left=%{public}d, top=%{public}d, width=%{public}d, height=%{public}d",
                __func__, fragmentRect.left, fragmentRect.top, fragmentRect.width, fragmentRect.height);
            return true;
        }
    }
    return false;
}

// |<------------------ Blob Metadata structure ----------------->|
// |<- Data ->|<- dataSize(4 Bytes) ->|<- Tag name(8 Bytes) ->|
bool JpegMpfParser::ParsingBlobMetadata(uint8_t* data, uint32_t size, vector<uint8_t>& metadata,
    MetadataType type)
{
    if (data == nullptr || size < TAG_NAME_LENGTH) {
        return false;
    }
    auto it = BLOB_METADATA_DECODE_TAG_MAP.find(type);
    if (it == BLOB_METADATA_DECODE_TAG_MAP.end()) {
        IMAGE_LOGW("%{public}s unknown blobmetadata tag: %{public}d", __func__, type);
        return false;
    }
    for (uint32_t offset = size - TAG_NAME_LENGTH; offset > 0; --offset) {
        bool match = false;
        for (const auto& tagName: it->second) {
            match = memcmp((data + offset), tagName.c_str(), TAG_NAME_LENGTH) == 0;
            if (match) {
                break;
            }
        }
        if (!match) {
            continue;
        }
        if (offset < UINT32_BYTE_SIZE) {
            return false;
        }
        offset -= UINT32_BYTE_SIZE;
        uint32_t dataSize = static_cast<uint32_t>(ImageUtils::BytesToInt32(data, offset, size, false));
        if (dataSize == 0 || dataSize > MAX_BLOB_METADATA_LENGTH || offset < (dataSize + UINT32_BYTE_SIZE)) {
            return false;
        }
        offset -= (dataSize + UINT32_BYTE_SIZE);
        metadata.assign(data + offset, data + offset + dataSize);
        return true;
    }
    return false;
}

static void WriteMPEntryToBytes(vector<uint8_t>& bytes, uint32_t& offset, std::vector<SingleJpegImage> images)
{
    for (uint32_t i = 0; i < images.size(); i++) {
        uint32_t attributeData = 0;
        if (i == 0) {
            // 0x20: representative image flag / 0x03: primary image type code;
            attributeData = 0x20030000;
        }
        ImageUtils::Uint32ToBytes(attributeData, bytes, offset);
        ImageUtils::Uint32ToBytes(images[i].size, bytes, offset);
        ImageUtils::Uint32ToBytes(images[i].offset, bytes, offset);
        const uint16_t dependentImage1EntryNumber = 0;
        const uint16_t dependentImage2EntryNumber = 0;
        ImageUtils::Uint16ToBytes(dependentImage1EntryNumber, bytes, offset);
        ImageUtils::Uint16ToBytes(dependentImage2EntryNumber, bytes, offset);
    }
}

static void WriteMpIndexIFD(vector<uint8_t>& bytes, uint32_t& offset, uint8_t imageNum)
{
    // tag count is three(MPF_VERSION_TAG, NUMBERS_OF_IMAGES_TAG, MP_ENTRY_TAG)
    const uint16_t tagCount = 3;
    ImageUtils::Uint16ToBytes(tagCount, bytes, offset);

    // tag MPF_VERSION_TAG
    const uint16_t versionTagCount = 4;
    ImageUtils::Uint16ToBytes(MPF_VERSION_TAG, bytes, offset);
    ImageUtils::Uint16ToBytes(TAG_TYPE_UNDEFINED, bytes, offset);
    ImageUtils::Uint32ToBytes(versionTagCount, bytes, offset);
    ImageUtils::ArrayToBytes(MPF_VERSION_DEFAULT, UINT32_BYTE_SIZE, bytes, offset);

    // tag NUMBERS_OF_IMAGES_TAG
    const uint16_t imageNumTagCount = 1;
    ImageUtils::Uint16ToBytes(NUMBERS_OF_IMAGES_TAG, bytes, offset);
    ImageUtils::Uint16ToBytes(TAG_TYPE_LONG, bytes, offset);
    ImageUtils::Uint32ToBytes(imageNumTagCount, bytes, offset);
    ImageUtils::Uint32ToBytes(imageNum, bytes, offset);

    // tag MP_ENTRY_TAG
    const uint32_t mpEntryCount = static_cast<uint32_t>(MP_ENTRY_BYTE_SIZE) * static_cast<uint32_t>(imageNum);
    ImageUtils::Uint16ToBytes(MP_ENTRY_TAG, bytes, offset);
    ImageUtils::Uint16ToBytes(TAG_TYPE_UNDEFINED, bytes, offset);
    ImageUtils::Uint32ToBytes(mpEntryCount, bytes, offset);

    // offset-markerSize(2)-lengthSize(2)-MULTI_PICTURE_FLAG size(4)+mpEntryOffsetSize(4)+attributeIfdOffset(4)
    uint32_t mpEntryOffset = offset - UINT16_BYTE_SIZE - UINT16_BYTE_SIZE - UINT32_BYTE_SIZE +
        UINT32_BYTE_SIZE + UINT32_BYTE_SIZE;
    ImageUtils::Uint32ToBytes(mpEntryOffset, bytes, offset);
}

std::vector<uint8_t> JpegMpfPacker::PackHdrJpegMpfMarker(SingleJpegImage base, SingleJpegImage gainmap)
{
    vector<uint8_t> bytes(HDR_MULTI_PICTURE_APP_LENGTH);
    uint32_t index = 0;
    bytes[index++] = 0xFF;
    bytes[index++] = 0xE2;

    // length dont combine marker(0xFFE2)
    ImageUtils::Uint16ToBytes(HDR_MULTI_PICTURE_APP_LENGTH - UINT16_BYTE_SIZE, bytes, index);
    ImageUtils::ArrayToBytes(MULTI_PICTURE_HEADER_FLAG, UINT32_BYTE_SIZE, bytes, index);
    ImageUtils::ArrayToBytes(BIG_ENDIAN_FLAG, UINT32_BYTE_SIZE, bytes, index);

    // BIG_ENDIAN_FLAG size + IFDOffset size
    const uint32_t IFDOffset = UINT32_BYTE_SIZE + UINT32_BYTE_SIZE;
    ImageUtils::Uint32ToBytes(IFDOffset, bytes, index);
    std::vector<SingleJpegImage> images = {base, gainmap};
    WriteMpIndexIFD(bytes, index, images.size());
    const uint32_t attributeIfdOffset = 0;
    ImageUtils::Uint32ToBytes(attributeIfdOffset, bytes, index);
    WriteMPEntryToBytes(bytes, index, images);
    return bytes;
}

std::vector<uint8_t> JpegMpfPacker::PackFragmentMetadata(Rect& fragmentRect, bool isBigEndian)
{
    std::vector<uint8_t> bytes(FRAGMENT_METADATA_LENGTH);
    uint32_t offset = 0;
    ImageUtils::ArrayToBytes(FRAGMENT_META_FLAG, UINT32_BYTE_SIZE, bytes, offset);
    ImageUtils::Int32ToBytes(fragmentRect.left, bytes, offset, isBigEndian);
    ImageUtils::Int32ToBytes(fragmentRect.top, bytes, offset, isBigEndian);
    ImageUtils::Int32ToBytes(fragmentRect.width, bytes, offset, isBigEndian);
    ImageUtils::Int32ToBytes(fragmentRect.height, bytes, offset, isBigEndian);
    return bytes;
}

std::vector<uint8_t> JpegMpfPacker::PackDataSize(uint32_t size, bool isBigEndian)
{
    std::vector<uint8_t> bytes(UINT32_BYTE_SIZE);
    uint32_t offset = 0;
    ImageUtils::Uint32ToBytes(size, bytes, offset, isBigEndian);
    return bytes;
}

std::vector<uint8_t> JpegMpfPacker::PackAuxiliaryTagName(std::string& tagName)
{
    std::vector<uint8_t> bytes(AUXILIARY_TAG_NAME_LENGTH, 0x00);
    std::copy(tagName.begin(), tagName.end(), bytes.begin());
    return bytes;
}
}
}
