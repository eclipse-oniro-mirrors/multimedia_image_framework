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

#include "hdr_helper.h"

#include <dlfcn.h>
#include <securec.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "image_log.h"
#include "jpeg_mpf_parser.h"
#include "xmp_parser.h"
#include "image_utils.h"
#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "src/codec/SkHeifCodec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HdrHelper"

namespace OHOS {
namespace Media {
using namespace std;
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP0 = 0xE0;
constexpr uint8_t JPEG_MARKER_APP1 = 0xE1;
constexpr uint8_t JPEG_MARKER_APP2 = 0xE2;
constexpr uint8_t JPEG_MARKER_APP5 = 0xE5;
constexpr uint8_t JPEG_MARKER_APP8 = 0xE8;
constexpr uint32_t MOVE_THREE_BYTES = 24;
constexpr uint32_t MOVE_TWO_BYTES = 16;
constexpr uint32_t MOVE_ONE_BYTE = 8;
constexpr uint32_t CUVA_BASE_IMAGE_MARKER_SIZE = 24;
constexpr uint32_t VIVID_BASE_IMAGE_MARKER_SIZE = 22;
constexpr int JPEG_MARKER_LEGNTH_SIZE = 2;
constexpr int JPEG_MARKER_TAG_SIZE = 2;
constexpr int MPF_TAG_SIZE = 4;
constexpr uint32_t UINT16_BYTE_COUNT = 2;
constexpr uint32_t UINT32_BYTE_COUNT = 4;
constexpr uint8_t JPEG_IMAGE_NUM = 2;
constexpr uint8_t VIVID_FILE_TYPE_BASE = 1;
constexpr uint8_t VIVID_FILE_TYPE_GAINMAP = 2;
constexpr uint8_t VIVID_BASE_UNUSERD_BYTE_NUM = 3;

static constexpr uint8_t ITUT35_TAG[] = {
    'I', 'T', 'U', 'T', '3', '5',
};
constexpr uint8_t JPEG_XMP_HEADER_TAG_SIZE = 29;
constexpr uint8_t JPEG_XMP_HEADER_TAG[JPEG_XMP_HEADER_TAG_SIZE] = {
    'h', 't', 't', 'p', ':', '/', '/', 'n', 's', '.', 'a', 'd', 'o', 'b', 'e', '.', 'c', 'o', 'm', '/', 'x', 'a', 'p',
    '/', '1', '.', '0', '/', '\0'
};

static constexpr uint8_t VIVID_BASE_PRE_INFO[] {
    0x26, // itu35countryCode
    0x04, // terminalProvideCode
    0x07, //terminalProvideOrientedCode
    0x02, // extendedFrameNumber
    0x01, // fileType
    0x00, // metaType
    0x00, // enhenceType
    0x00 // hdrType
};

static constexpr uint8_t VIVID_META_PRE_INFO[] {
    0x26, // itu35countryCode
    0x04, // terminalProvideCode
    0x07, //terminalProvideOrientedCode
    0x02, // extendedFrameNumber
    0x02, // fileType
    0x01, // metaType
    0x00, // enhenceType
    0x00 // hdrType
};
constexpr uint8_t VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE = 5;
static constexpr uint8_t VIVID_DYNAMIC_METADATA_PRE_INFO[VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE] {
    0x26, // itu35countryCode
    0x00, 0x04, // terminalProvideCode
    0x00, 0x07, //terminalProvideOrientedCode
};

typedef bool (*GetCuvaGainMapOffsetT)(jpeg_marker_struct* marker, bool& isNewCuvaType, uint32_t& offset);
typedef bool (*GetCuvaGainMapMetadataT)(jpeg_marker_struct* marker, std::vector<uint8_t>& metadata);

static bool GetCuvaGainMapOffset(jpeg_marker_struct* marker, bool& isNewCuvaType, uint32_t& offset)
{
    if (JPEG_MARKER_APP5 != marker->marker || marker->data_length < CUVA_BASE_IMAGE_MARKER_SIZE) {
        return false;
    }
    auto handle = dlopen("libimage_cuva_parser.z.so", RTLD_LAZY);
    if (!handle) {
        return false;
    }
    GetCuvaGainMapOffsetT check = (GetCuvaGainMapOffsetT)dlsym(handle, "GetCuvaGainMapOffset");
    if (!check) {
        dlclose(handle);
        return false;
    }
    bool result = check(marker, isNewCuvaType, offset);
    dlclose(handle);
    return result;
}

static bool GetHdrVividGainMapOffset(jpeg_marker_struct* marker, std::vector<uint32_t>& offset)
{
    if (JPEG_MARKER_APP8 != marker->marker || marker->data_length < VIVID_BASE_IMAGE_MARKER_SIZE) {
        return false;
    }
    uint8_t* data = marker->data;
    uint32_t dataOffset = 0;
    if (memcmp(marker->data, ITUT35_TAG, sizeof(ITUT35_TAG)) != 0) {
        return false;
    }
    dataOffset += sizeof(ITUT35_TAG);
    uint8_t itut35CountryCode = data[dataOffset++];
    uint16_t terminalProvideCode = data[dataOffset++];
    uint16_t terminalProvideOrientedCode = data[dataOffset++];
    IMAGE_LOGD("vivid base info countryCode=%{public}d,terminalCode=%{public}d,orientedcode=%{public}d",
        itut35CountryCode, terminalProvideCode, terminalProvideOrientedCode);
    uint8_t extendedFrameNumber = data[dataOffset++];
    if (extendedFrameNumber < JPEG_IMAGE_NUM) {
        return false;
    }
    uint8_t fileType = data[dataOffset++];
    if (fileType != VIVID_FILE_TYPE_BASE) {
        return false;
    }
    // skip three unused bytes
    dataOffset += VIVID_BASE_UNUSERD_BYTE_NUM;
    const uint8_t imageOffsetSize = JPEG_IMAGE_NUM;
    offset.resize(imageOffsetSize);
    offset[0] = ImageUtils::BytesToUint32(data, dataOffset);
    offset[1] = ImageUtils::BytesToUint32(data, dataOffset);
    return true;
}

static uint8_t GetIsoGainMapIndex(jpeg_marker_struct* marker)
{
    uint8_t index = 0;
    if (JPEG_MARKER_APP1 != marker->marker) {
        return index;
    }
    if (marker->data_length <= JPEG_XMP_HEADER_TAG_SIZE) {
        return index;
    }
    if (memcmp(marker->data, JPEG_XMP_HEADER_TAG, JPEG_XMP_HEADER_TAG_SIZE) != 0) {
        return index;
    }
    uint8_t* xmpData = marker->data + JPEG_XMP_HEADER_TAG_SIZE;
    uint32_t xmpDataLength = marker->data_length - JPEG_XMP_HEADER_TAG_SIZE;
    auto xmp = make_unique<Media::XmpParser>();
    if (!xmp->ParseBaseImageXmp(xmpData, xmpDataLength, index)) {
        IMAGE_LOGD("parse base image xmp error");
    }
    return index;
}

static bool GetIsoGainMapOffset(jpeg_marker_struct* marker, uint32_t markerOffset, vector<uint32_t>& offsetArray)
{
    if (JPEG_MARKER_APP2 != marker->marker) {
        return false;
    }
    auto jpegMpf = std::make_unique<JpegMpfParser>();
    if (!jpegMpf->Parsing(marker->data, marker->data_length)) {
        return false;
    }
    uint32_t imageNum = jpegMpf->images_.size();
    if (imageNum < JPEG_IMAGE_NUM) {
        return false;
    }
    offsetArray.resize(imageNum);
    // gain map offset need add Mpf marker offset;
    uint32_t markerHeaderOffset = markerOffset + JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LEGNTH_SIZE + MPF_TAG_SIZE;
    for (uint32_t i = 0; i < imageNum; i++) {
        offsetArray[i] = jpegMpf->images_[i].offset + markerHeaderOffset;
    }
    return true;
}

static HdrType CheckJpegGainMapHdrType(SkJpegCodec* jpegCodec, uint32_t& offset)
{
    offset = 0;
    HdrType type = HdrType::SDR;
    uint32_t allAppSize = JPEG_MARKER_TAG_SIZE;
    bool isNewCuvaType = false;
    uint8_t gainMapIndex = 0;
    std::vector<uint32_t> imagesOffset;
    for (jpeg_marker_struct* marker = jpegCodec->decoderMgr()->dinfo()->marker_list; marker; marker = marker->next) {
        if (GetHdrVividGainMapOffset(marker, imagesOffset)) {
            type = HdrType::HDR_VIVID;
            break;
        }
        if (GetCuvaGainMapOffset(marker, isNewCuvaType, offset)) {
            type = HdrType::HDR_CUVA;
        }
        if (type == HdrType::SDR && GetIsoGainMapOffset(marker, allAppSize, imagesOffset)) {
            type = HdrType::HDR_ISO;
        }
        if (type == HdrType::HDR_ISO && gainMapIndex == 0) {
            gainMapIndex = GetIsoGainMapIndex(marker);
        }
        if (JPEG_MARKER_APP0 == (marker->marker & 0xF0)) {
            allAppSize += marker->data_length + JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LEGNTH_SIZE;
        }
    }
    if (type == HdrType::HDR_CUVA && isNewCuvaType) {
        offset = offset + allAppSize;
    } else if (type == HdrType::HDR_VIVID && imagesOffset.size() > 0) {
        offset = imagesOffset[0];
    } else if (type == HdrType::HDR_ISO && gainMapIndex > 0 && gainMapIndex < imagesOffset.size()) {
        offset = imagesOffset[gainMapIndex];
    } else if (type == HdrType::HDR_ISO && imagesOffset.size() > 1) {
        offset = imagesOffset[1];
    }
    return type;
}

static HdrType CheckHeifHdrType(SkHeifCodec* codec)
{
    return HdrType::SDR;
}

HdrType HdrHelper::CheckHdrType(SkCodec* codec, uint32_t& offset)
{
    offset = 0;
    HdrType type = HdrType::SDR;
    if (codec == nullptr) {
        return type;
    }
    switch (codec->getEncodedFormat()) {
        case SkEncodedImageFormat::kJPEG: {
            SkJpegCodec* jpegCodec = static_cast<SkJpegCodec*>(codec);
            if (jpegCodec == nullptr || jpegCodec->decoderMgr() == nullptr) {
                break;
            }
            type = CheckJpegGainMapHdrType(jpegCodec, offset);
            break;
        }
        case SkEncodedImageFormat::kHEIF: {
            SkHeifCodec* heifCodec = static_cast<SkHeifCodec*>(codec);
            if (heifCodec == nullptr) {
                break;
            }
            type = CheckHeifHdrType(heifCodec);
            break;
        }
        default:
            type = HdrType::SDR;
            break;
    }
    return type;
}

// parse metadata
static bool GetCuvaGainMapMetadata(jpeg_marker_struct* markerList, std::vector<uint8_t>& metadata)
{
    auto handle = dlopen("libimage_cuva_parser.z.so", RTLD_LAZY);
    if (!handle) {
        return false;
    }
    GetCuvaGainMapMetadataT getMetadata = (GetCuvaGainMapMetadataT)dlsym(handle, "GetCuvaGainMapMetadata");
    if (!getMetadata) {
        dlclose(handle);
        return false;
    }
    const uint32_t CUVA_METADATA_MARKER_LENGTH = 50;
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP5 != marker->marker || marker->data_length < CUVA_METADATA_MARKER_LENGTH) {
            continue;
        }
        if (getMetadata(marker, metadata)) {
            dlclose(handle);
            return true;
        }
    }
    dlclose(handle);
    return false;
}

static bool ParseVividMetadata(uint8_t* data, uint32_t& dataOffset, uint32_t length, HdrMetadata& metadata)
{
    uint16_t metadataSize = ImageUtils::BytesToUint16(data, dataOffset);
    if (metadataSize > length - dataOffset) {
        return false;
    }
    uint16_t staticMetaSize = ImageUtils::BytesToUint16(data, dataOffset);
    if (staticMetaSize > 0) {
        if (staticMetaSize > length - dataOffset) {
            return false;
        }
        metadata.staticMetadata.resize(staticMetaSize);
        if (memcpy_s(metadata.staticMetadata.data(), staticMetaSize, data + dataOffset, staticMetaSize) != 0) {
            IMAGE_LOGD("get vivid static metadata failed");
        }
        dataOffset += staticMetaSize;
    }
    uint16_t dynamicMetaSize = ImageUtils::BytesToUint16(data, dataOffset);
    if (dynamicMetaSize > 0) {
        if (dynamicMetaSize > length - dataOffset || dynamicMetaSize < VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE) {
            return false;
        }
        // skip 5 unused bytes, (itu35countryCode,terminalProvideCode,terminalProvideOrientedCode)
        dataOffset += VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
        dynamicMetaSize -= VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
        metadata.dynamicMetadata.resize(dynamicMetaSize);
        if (memcpy_s(metadata.dynamicMetadata.data(), dynamicMetaSize, data + dataOffset, dynamicMetaSize) != 0) {
            IMAGE_LOGD("get vivid dynamic metadata failed");
            return false;
        }

        dataOffset += dynamicMetaSize;
    }
    return true;
}

static bool GetVividGainMapMetadata(jpeg_marker_struct* markerList, HdrMetadata& metadata)
{
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP8 != marker->marker) {
            continue;
        }
        uint8_t* data = marker->data;
        uint32_t length = marker->data_length;
        uint32_t dataOffset = 0;
        if (memcmp(marker->data, ITUT35_TAG, sizeof(ITUT35_TAG)) != 0) {
            return false;
        }
        dataOffset += sizeof(ITUT35_TAG);
        uint8_t itut35CountryCode = data[dataOffset++];
        uint16_t terminalProvideCode = data[dataOffset++];
        uint16_t terminalProvideOrientedCode = data[dataOffset++];
        IMAGE_LOGD("vivid metadata countryCode=%{public}d,terminalCode=%{public}d,orientedcode=%{public}d",
            itut35CountryCode, terminalProvideCode, terminalProvideOrientedCode);
        uint8_t extendedFrameNumber = data[dataOffset++];
        if (extendedFrameNumber < JPEG_IMAGE_NUM) {
            return false;
        }
        uint8_t fileType = data[dataOffset++];
        if (fileType != VIVID_FILE_TYPE_GAINMAP) {
            return false;
        }
        uint8_t metaType = data[dataOffset++];
        uint8_t enhenceType = data[dataOffset++];
        uint8_t hdrType = data[dataOffset++];
        IMAGE_LOGD("vivid metadata info hdrType=%{public}d, enhenceType=%{public}d", hdrType, enhenceType);
        bool getMetadata = false;
        if (metaType > 0 && length > dataOffset + UINT16_BYTE_COUNT) {
            getMetadata = ParseVividMetadata(data, dataOffset, length, metadata);
        }
        return getMetadata;
    }
    return false;
}

static bool GetIsoGainMapMetadata(jpeg_marker_struct* markerList, vector<uint8_t>& metadata)
{
    IsoMetadata isoMetadata = {
        {0.0, 0.0, 0.0},
        {1.0, 1.0, 1.0},
        {1.0, 1.0, 1.0},
        {0.0, 0.0, 0.0},
        {0.0, 0.0, 0.0},
        0.0,
        0.0,
        false,
        0,
    };
    metadata.resize(sizeof(isoMetadata));
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP1 != marker->marker) {
            continue;
        }
        if (marker->data_length <= JPEG_XMP_HEADER_TAG_SIZE &&
            memcmp(marker->data, JPEG_XMP_HEADER_TAG, JPEG_XMP_HEADER_TAG_SIZE) != 0) {
            continue;
        }
        uint8_t* xmpData = marker->data + JPEG_XMP_HEADER_TAG_SIZE;
        uint32_t xmpDataLength = marker->data_length - JPEG_XMP_HEADER_TAG_SIZE;
        auto xmp = make_unique<Media::XmpParser>();
        if (!xmp->ParseGainMapMetadata(xmpData, xmpDataLength, isoMetadata)) {
            continue;
        }
        if (memcpy_s(metadata.data(), metadata.size(), &isoMetadata, sizeof(IsoMetadata)) == 0) {
            return true;
        }
    }
    return false;
}

static bool GetJpegGainMapMetadata(SkJpegCodec* codec, HdrType type, HdrMetadata& metadata)
{
    if (codec == nullptr || codec->decoderMgr() == nullptr) {
        return false;
    }
    jpeg_marker_struct* markerList = codec->decoderMgr()->dinfo()->marker_list;
    if (!markerList) {
        return false;
    }
    switch (type) {
        case HdrType::HDR_VIVID:
            return GetVividGainMapMetadata(markerList, metadata);
        case HdrType::HDR_CUVA:
            return GetCuvaGainMapMetadata(markerList, metadata.dynamicMetadata);
        case HdrType::HDR_ISO:
            return GetIsoGainMapMetadata(markerList, metadata.dynamicMetadata);
        default:
            return false;
    }
}

static bool GetHeifMetadata(SkHeifCodec* codec, HdrType type, HdrMetadata& metadata)
{
    return false;
}

bool HdrHelper::GetMetadata(SkCodec* codec, HdrType type, HdrMetadata& metadata)
{
    if (type <= HdrType::SDR || codec == nullptr) {
        return false;
    }
    switch (codec->getEncodedFormat()) {
        case SkEncodedImageFormat::kJPEG: {
            SkJpegCodec* jpegCodec = static_cast<SkJpegCodec*>(codec);
            return GetJpegGainMapMetadata(jpegCodec, type, metadata);
        }
        case SkEncodedImageFormat::kHEIF: {
            SkHeifCodec* heifCodec = static_cast<SkHeifCodec*>(codec);
            return GetHeifMetadata(heifCodec, type, metadata);
        }
        default:
            return false;
    }
}

/// pack jpeg base image vivid marker
vector<uint8_t> HdrHelper::PackJpegVividBaseInfo(uint32_t offset, uint32_t gainMapSize)
{
    uint32_t it35TagSize = sizeof(ITUT35_TAG);
    uint32_t basePreInfoSize = sizeof(VIVID_BASE_PRE_INFO);
    const uint32_t baseInfoMarkerLength = JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LEGNTH_SIZE + it35TagSize +
                                           basePreInfoSize + UINT32_BYTE_COUNT + // offset size
                                           UINT32_BYTE_COUNT; // gainmap length size
    vector<uint8_t> bytes(baseInfoMarkerLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP8;
    // length does not contain marker tag size;
    uint32_t markerDataLength = baseInfoMarkerLength - JPEG_MARKER_TAG_SIZE;
    bytes[index++] = (markerDataLength >> MOVE_ONE_BYTE) & 0xff;
    bytes[index++] = markerDataLength & 0xff;
    if (memcpy_s(bytes.data() + index, it35TagSize, ITUT35_TAG, it35TagSize) != 0) {
        return {};
    }
    index += it35TagSize;
    if (memcpy_s(bytes.data() + index, basePreInfoSize, VIVID_BASE_PRE_INFO, basePreInfoSize) != 0) {
        return {};
    }
    index += basePreInfoSize;
    // offset need add vivid marker size;
    offset += baseInfoMarkerLength;
    // set gainmap offset
    bytes[index++] = (offset >> MOVE_THREE_BYTES) & 0xff;
    bytes[index++] = (offset >> MOVE_TWO_BYTES) & 0xff;
    bytes[index++] = (offset >> MOVE_ONE_BYTE) & 0xff;
    bytes[index++] = offset & 0xff;
    // set gainmap size
    bytes[index++] = (gainMapSize >> MOVE_THREE_BYTES) & 0xff;
    bytes[index++] = (gainMapSize >> MOVE_TWO_BYTES) & 0xff;
    bytes[index++] = (gainMapSize >> MOVE_ONE_BYTE) & 0xff;
    bytes[index++] = gainMapSize & 0xff;
    return bytes;
}

vector<uint8_t> HdrHelper::PackJpegVividMetadata(HdrMetadata metadata)
{
    uint32_t it35TagSize = sizeof(ITUT35_TAG);
    uint32_t metaPreInfoSize = sizeof(VIVID_META_PRE_INFO);
    const uint32_t metaMarkerPreSize = JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LEGNTH_SIZE + it35TagSize + metaPreInfoSize;
    uint32_t dynamicMetadataSize = metadata.dynamicMetadata.size() + VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
    // metadata size
    const uint32_t metadataSize = metadata.staticMetadata.size() + UINT16_BYTE_COUNT +
                                  dynamicMetadataSize + UINT16_BYTE_COUNT;
    const uint32_t vividMetaMarkerLength = metaMarkerPreSize + metadataSize + UINT16_BYTE_COUNT;
    vector<uint8_t> bytes(vividMetaMarkerLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP8;
    // length does not contain marker tag size
    uint32_t markerLength = vividMetaMarkerLength - JPEG_MARKER_TAG_SIZE;
    bytes[index++] = (markerLength >> MOVE_ONE_BYTE) & 0xFF;
    bytes[index++] = markerLength & 0xFF;
    if (memcpy_s(bytes.data() + index, it35TagSize, ITUT35_TAG, it35TagSize) != EOK) {
        return {};
    }
    index += it35TagSize;
    if (memcpy_s(bytes.data() + index, metaPreInfoSize, VIVID_META_PRE_INFO, metaPreInfoSize) != EOK) {
        return {};
    }
    index += metaPreInfoSize;
    bytes[index++] = (metadataSize >> MOVE_ONE_BYTE) & 0xFF; // set metadata total size
    bytes[index++] = metadataSize & 0xFF;
    bytes[index++] = (metadata.staticMetadata.size() >> MOVE_ONE_BYTE) & 0xFF; // set staticmetadata size
    bytes[index++] = metadata.staticMetadata.size() & 0xFF;
    uint32_t staticMetadataSize = metadata.staticMetadata.size();
    if (memcpy_s(bytes.data() + index, staticMetadataSize, metadata.staticMetadata.data(), staticMetadataSize) != EOK) {
        return {};
    };
    index += staticMetadataSize;
    bytes[index++] = (dynamicMetadataSize >> MOVE_ONE_BYTE) & 0xFF;
    bytes[index++] = dynamicMetadataSize & 0xFF;
    if (memcpy_s(bytes.data() + index, VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE,
        VIVID_DYNAMIC_METADATA_PRE_INFO, VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE) != EOK) {
        return {};
    };
    index += VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
    if (memcpy_s(bytes.data() + index, metadata.dynamicMetadata.size(),
        metadata.dynamicMetadata.data(), metadata.dynamicMetadata.size()) != EOK) {
        return {};
    };
    return bytes;
}
}
}