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
#include "hilog/log_cpp.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

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
constexpr uint16_t AUXILIARY_TAG_NAME_LENGTH = 8;

constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP2 = 0xE2;

constexpr uint8_t MAX_IMAGE_NUM = 32;

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

static const std::map<std::string, AuxiliaryPictureType> AUXILIARY_TAG_TYPE_MAP = {
    {AUXILIARY_TAG_DEPTH_MAP_BACK, AuxiliaryPictureType::DEPTH_MAP},
    {AUXILIARY_TAG_DEPTH_MAP_FRONT, AuxiliaryPictureType::DEPTH_MAP},
    {AUXILIARY_TAG_UNREFOCUS_MAP, AuxiliaryPictureType::UNREFOCUS_MAP},
    {AUXILIARY_TAG_LINEAR_MAP, AuxiliaryPictureType::LINEAR_MAP},
    {AUXILIARY_TAG_FRAGMENT_MAP, AuxiliaryPictureType::FRAGMENT_MAP}
};

bool JpegMpfParser::CheckMpfOffset(uint8_t* data, uint32_t size, uint32_t& offset)
{
    if (data == nullptr) {
        return false;
    }
    for (offset = 0; offset < size; offset++) {
        if (data[offset] == JPEG_MARKER_PREFIX && (data[offset + 1] == JPEG_MARKER_APP2)) {
            offset += UINT32_BYTE_SIZE;
            return true;
        }
    }
    return false;
}

bool JpegMpfParser::Parsing(uint8_t* data, uint32_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    if (memcmp(data, MULTI_PICTURE_HEADER_FLAG, sizeof(MULTI_PICTURE_HEADER_FLAG)) != 0) {
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
                if (memcmp(data + (dataOffset - UINT32_BYTE_SIZE), MPF_VERSION_DEFAULT,
                    sizeof(MPF_VERSION_DEFAULT)) != 0) {
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

static bool FindAuxiliaryTags(const uint8_t* data, uint32_t size, std::string& foundTag)
{
    if (data == nullptr || size < AUXILIARY_TAG_NAME_LENGTH) {
        return false;
    }
    for (const auto &[tagName, _] : AUXILIARY_TAG_TYPE_MAP) {
        if (memcmp(data, tagName.c_str(), tagName.size()) == 0) {
            foundTag = tagName;
            return true;
        }
    }
    return false;
}

// |<------------------ Auxiliary picture structure ----------------->|
// |<- Image data ->|<- Image size(4 Bytes) ->|<- Tag name(8 Bytes) ->|
static int32_t GetLastAuxiliaryTagOffset(const uint8_t* data, uint32_t size, std::string& foundTag)
{
    if (data == nullptr || size < AUXILIARY_TAG_NAME_LENGTH) {
        return ERR_MEDIA_INVALID_VALUE;
    }
    uint32_t offset = size - AUXILIARY_TAG_NAME_LENGTH;
    while (offset > 0) {
        if (FindAuxiliaryTags(data + offset, size - offset, foundTag)) {
            return static_cast<int32_t>(offset);
        }
        --offset;
    }
    return ERR_MEDIA_INVALID_VALUE;
}

// Parse the following types of auxiliary pictures: DEPTH_MAP, UNREFOCUS_MAP, LINEAR_MAP, FRAGMENT_MAP
bool JpegMpfParser::ParsingAuxiliaryPictures(uint8_t* data, uint32_t dataSize, bool isBigEndian)
{
    if (data == nullptr || dataSize == 0) {
        return false;
    }

    uint32_t offset = dataSize;
    while (offset > 0) {
        std::string foundTag("");
        int32_t matchedPos = GetLastAuxiliaryTagOffset(data, offset, foundTag);
        if (matchedPos == ERR_MEDIA_INVALID_VALUE) {
            IMAGE_LOGI("%{public}s no more auxiliary pictures", __func__);
            break;
        }
        offset = static_cast<uint32_t>(matchedPos);
        auto it = AUXILIARY_TAG_TYPE_MAP.find(foundTag);
        if (it == AUXILIARY_TAG_TYPE_MAP.end()) {
            IMAGE_LOGW("%{public}s unknown auxiliary tag: %{public}s", __func__, foundTag.c_str());
            continue;
        }

        if (offset < UINT32_BYTE_SIZE) {
            IMAGE_LOGW("%{public}s invalid offset: %{public}u, auxiliary tag: %{public}s",
                __func__, offset, foundTag.c_str());
            continue;
        }
        offset -= UINT32_BYTE_SIZE;
        // tag and image size before this position
        uint32_t imageSize = ImageUtils::BytesToUint32(data, offset, dataSize, isBigEndian);
        if (offset < imageSize + UINT32_BYTE_SIZE) {
            IMAGE_LOGW("%{public}s invalid image size: %{public}u, offset: %{public}u, auxiliary tag: %{public}s",
                __func__, imageSize, offset, foundTag.c_str());
            continue;
        }
        offset = offset - imageSize - UINT32_BYTE_SIZE;
        SingleJpegImage auxImage = {
            .offset = offset,
            .size = imageSize,
            .auxType = it->second,
            .auxTagName = it->first,
        };
        images_.push_back(auxImage);
        IMAGE_LOGD("[%{public}s] auxType=%{public}d, offset=%{public}u, size=%{public}u, tagName=%{public}s",
            __func__, auxImage.auxType, auxImage.offset, auxImage.size, auxImage.auxTagName.c_str());
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
