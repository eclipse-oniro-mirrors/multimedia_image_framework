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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "JpegMpfParser"

namespace OHOS {
namespace Media {

using namespace std;

constexpr uint8_t MP_INDEX_IFD_BYTE_SIZE = 12;
constexpr uint8_t MP_ENTRY_BYTE_SIZE = 16;
constexpr uint8_t BYTE_SIZE_4 = 4;

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

enum MpfIFDTag : uint16_t {
    MPF_VERSION_TAG = 45056,
    NUMBERS_OF_IMAGES_TAG = 45057,
    MP_ENTRY_TAG = 45058,
    IMAGE_UID_LIST_TAG = 45059,
    TOTAL_FRAMES_TAG = 45060,
};

bool JpegMpfParser::Parsing(uint8_t* data, uint32_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    if (memcmp(data, MULTI_PICTURE_HEADER_FLAG, sizeof(MULTI_PICTURE_HEADER_FLAG)) != 0) {
        return false;
    }
    data += BYTE_SIZE_4;
    size -= BYTE_SIZE_4;
    uint32_t dataOffset = 0;
    bool isBigEndian = false;
    if (memcmp(data, BIG_ENDIAN_FLAG, sizeof(BIG_ENDIAN_FLAG)) == 0) {
        isBigEndian = true;
    } else if (memcmp(data, LITTLE_ENDIAN_FLAG, sizeof(LITTLE_ENDIAN_FLAG)) == 0) {
        isBigEndian = false;
    } else {
        return false;
    }
    dataOffset += BYTE_SIZE_4;
    uint32_t ifdOffset = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
    if (ifdOffset < dataOffset || ifdOffset > size) {
        IMAGE_LOGD("get ifd offset error");
        return false;
    }
    dataOffset = ifdOffset;
    return ParsingMpIndexIFD(data, size, dataOffset, isBigEndian);
}

bool JpegMpfParser::ParsingMpIndexIFD(uint8_t* data, uint32_t size, uint32_t dataOffset, bool isBigEndian)
{
    uint16_t tagCount = ImageUtils::BytesToUint16(data, dataOffset, isBigEndian);
    if (dataOffset + MP_INDEX_IFD_BYTE_SIZE * tagCount > size) {
        return false;
    }
    uint16_t previousTag = 0;
    for (int i = 0; i < tagCount; i++) {
        uint16_t tag = ImageUtils::BytesToUint16(data, dataOffset, isBigEndian);
        if (tag <= previousTag) {
            return false;
        }
        previousTag = tag;
        uint16_t type = ImageUtils::BytesToUint16(data, dataOffset, isBigEndian);
        uint32_t count = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
        uint32_t value = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
        IMAGE_LOGD("mpf tag=%{public}d,type=%{public}d,count=%{public}d,value=%{public}d", tag, type, count, value);
        switch (tag) {
            case MpfIFDTag::MPF_VERSION_TAG:
                if (memcmp(data + (dataOffset - BYTE_SIZE_4), MPF_VERSION_DEFAULT, sizeof(MPF_VERSION_DEFAULT)) != 0) {
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
    uint32_t mpAttrIFDOffset = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
    if (mpAttrIFDOffset > 0 && dataOffset > mpAttrIFDOffset) {
        return false;
    }
    return true;
}

bool JpegMpfParser::ParsingMpEntry(uint8_t* data, uint32_t size, bool isBigEndian, uint32_t imageNums)
{
    uint32_t dataOffset = 0;
    if (imageNums == 0 || imageNums * MP_ENTRY_BYTE_SIZE > size) {
        return false;
    }
    images_.resize(imageNums);
    for (uint32_t i = 0; i < imageNums; i++) {
        uint32_t imageAttr = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
        images_[i].size = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
        images_[i].offset = ImageUtils::BytesToUint32(data, dataOffset, isBigEndian);
        uint16_t image1EntryNum = ImageUtils::BytesToUint16(data, dataOffset, isBigEndian);
        uint16_t image2EntryNum = ImageUtils::BytesToUint16(data, dataOffset, isBigEndian);
        IMAGE_LOGD("index=%{public}d, imageAttr=%{public}d, image1entrynum=%{public}d, image2entryNum=%{puublic}d",
            i, imageAttr, image1EntryNum, image2EntryNum);
    }
    return true;
}
}
}
