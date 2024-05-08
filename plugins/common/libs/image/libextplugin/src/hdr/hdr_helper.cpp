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
#include "image_utils.h"
#include "media_errors.h"
#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "src/codec/SkHeifCodec.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/hdr_static_metadata.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HdrHelper"

namespace OHOS {
namespace Media {
using namespace std;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
#endif
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP0 = 0xE0;

constexpr uint8_t JPEG_MARKER_APP2 = 0xE2;
constexpr uint8_t JPEG_MARKER_APP5 = 0xE5;
constexpr uint8_t JPEG_MARKER_APP8 = 0xE8;
constexpr uint8_t JPEG_SOI = 0xD8;
constexpr uint32_t MOVE_ONE_BYTE = 8;
constexpr uint32_t VIVID_BASE_IMAGE_MARKER_SIZE = 22;
constexpr int JPEG_MARKER_LENGTH_SIZE = 2;
constexpr int JPEG_MARKER_TAG_SIZE = 2;
constexpr int MPF_TAG_SIZE = 4;
constexpr uint32_t UINT8_BYTE_COUNT = 1;
constexpr uint32_t UINT16_BYTE_COUNT = 2;
constexpr uint32_t UINT32_BYTE_COUNT = 4;
constexpr uint8_t JPEG_IMAGE_NUM = 2;
constexpr uint8_t VIVID_FILE_TYPE_BASE = 1;
constexpr uint8_t VIVID_FILE_TYPE_GAINMAP = 2;
constexpr uint8_t EMPTY_SIZE = 0;
constexpr uint8_t VIVID_STATIC_METADATA_SIZE_IN_IMAGE = 24;
constexpr uint8_t ITUT35_TAG_SIZE = 6;
constexpr uint8_t INDEX_ZERO = 0;
constexpr uint8_t INDEX_ONE = 1;
constexpr uint8_t INDEX_TWO = 2;
constexpr uint8_t INDEX_THREE = 3;
constexpr uint8_t COLOR_INFO_BYTES = 3;
constexpr uint8_t ONE_COMPONENT = 1;
constexpr uint8_t THREE_COMPONENTS = 3;
constexpr uint8_t VIVID_PRE_INFO_SIZE = 10;
constexpr uint8_t VIVID_METADATA_PRE_INFO_SIZE = 10;
constexpr uint32_t HDR_MULTI_PICTURE_APP_LENGTH = 90;
constexpr uint32_t EXTEND_INFO_MAIN_SIZE = 60;
constexpr uint32_t ISO_GAINMAP_METADATA_PAYLOAD_MIN_SIZE = 38;
constexpr uint32_t DENOMINATOR = 1000000;

const float SM_COLOR_SCALE = 0.00002f;
const float SM_LUM_SCALE = 0.0001f;

static constexpr uint8_t ITUT35_TAG[ITUT35_TAG_SIZE] = {
    'I', 'T', 'U', 'T', '3', '5',
};

constexpr uint8_t ISO_GAINMAP_TAG_SIZE = 28;
constexpr uint8_t ISO_GAINMAP_TAG[ISO_GAINMAP_TAG_SIZE] = {
    'u', 'r', 'n', ':', 'i', 's', 'o', ':', 's', 't', 'd', ':', 'i', 's', 'o', ':', 't', 's', ':', '2', '1', '4', '9',
    '6', ':', '-', '1', '\0'
};

constexpr uint8_t VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE = 5;
static constexpr uint8_t VIVID_DYNAMIC_METADATA_PRE_INFO[VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE] {
    0x26, // itu35countryCode
    0x00, 0x04, // terminalProvideCode
    0x00, 0x07, //terminalProvideOrientedCode
};

typedef bool (*GetCuvaGainMapOffsetT)(jpeg_marker_struct* marker, uint32_t appSize, uint32_t& offset);
typedef bool (*GetCuvaGainMapMetadataT)(jpeg_marker_struct* marker, std::vector<uint8_t>& metadata);

struct ColorInfo {
    uint8_t primary;
    uint8_t transFunc;
    uint8_t model;
};

struct ExtendInfoMain {
    float gainMapMax[3];
    float gainMapMin[3];
    float gamma[3];
    float baseSdrImageOffset[3];
    float altHdrImageOffset[3];
};

struct TransformInfo {
    uint8_t mappingFlag;
    std::vector<uint8_t> mapping;
};

struct ExtendInfoExtention {
    ColorInfo baseColor;
    ColorInfo enhanceDataColor;
    ColorInfo combineColor;
    ColorInfo enhanceColor;
    TransformInfo baseMapping;
    TransformInfo combineMapping;
};

static bool GetVividJpegGainMapOffset(vector<jpeg_marker_struct*>& markerList, uint32_t appSize, uint32_t& offset)
{
    if (markerList.size() == EMPTY_SIZE) {
        return false;
    }
    for (auto marker : markerList) {
        if (JPEG_MARKER_APP8 != marker->marker || marker->data_length < VIVID_BASE_IMAGE_MARKER_SIZE) {
            continue;
        }
        uint8_t* data = marker->data;
        uint32_t dataOffset = 0;
        if (memcmp(marker->data, ITUT35_TAG, sizeof(ITUT35_TAG)) != EOK) {
            continue;
        }
        dataOffset += ITUT35_TAG_SIZE;
        uint8_t itut35CountryCode = data[dataOffset++];
        uint16_t terminalProvideCode = ImageUtils::BytesToUint16(data, dataOffset);
        uint16_t terminalProvideOrientedCode = ImageUtils::BytesToUint16(data, dataOffset);
        IMAGE_LOGD("vivid base info countryCode=%{public}d,terminalCode=%{public}d,orientedcode=%{public}d",
            itut35CountryCode, terminalProvideCode, terminalProvideOrientedCode);
        uint8_t extendedFrameNumber = data[dataOffset++];
        if (extendedFrameNumber < JPEG_IMAGE_NUM) {
            continue;
        }
        uint8_t fileType = data[dataOffset++];
        uint8_t metaType = data[dataOffset++];
        uint8_t enhanceType = data[dataOffset++];
        uint8_t hdrType = data[dataOffset++];
        IMAGE_LOGD("vivid base info metaType=%{public}d, enhanceType=%{public}d, hdrType=%{public}d",
            metaType, enhanceType, hdrType);
        if (fileType != VIVID_FILE_TYPE_BASE) {
            continue;
        }
        uint32_t originOffset = ImageUtils::BytesToUint32(data, dataOffset);
        uint32_t relativeOffset = ImageUtils::BytesToUint32(data, dataOffset); // offset minus all app size
        IMAGE_LOGD("vivid base info originOffset=%{public}d, relativeOffset=%{public}d",
            originOffset, relativeOffset);
        offset = appSize + relativeOffset;
        return true;
    }
    return false;
}

static bool GetCuvaJpegGainMapOffset(vector<jpeg_marker_struct*>& markerList, uint32_t appSize, uint32_t& offset)
{
    if (markerList.size() == EMPTY_SIZE) {
        return false;
    }
    auto handle = dlopen("libimage_cuva_parser.z.so", RTLD_LAZY);
    if (!handle) {
        dlclose(handle);
        return false;
    }
    GetCuvaGainMapOffsetT check = (GetCuvaGainMapOffsetT)dlsym(handle, "GetCuvaGainMapOffset");
    if (!check) {
        dlclose(handle);
        return false;
    }
    bool result = false;
    for (auto marker : markerList) {
        if (JPEG_MARKER_APP5 != marker->marker) {
            continue;
        }
        result = check(marker, appSize, offset);
        if (result) {
            break;
        }
    }
    dlclose(handle);
    return result;
}

static vector<uint32_t> ParseMpfOffset(jpeg_marker_struct* marker, uint32_t preOffset)
{
    if (JPEG_MARKER_APP2 != marker->marker) {
        return {};
    }
    auto jpegMpf = std::make_unique<JpegMpfParser>();
    if (!jpegMpf->Parsing(marker->data, marker->data_length)) {
        return {};
    }
    uint32_t imageNum = jpegMpf->images_.size();
    if (imageNum < JPEG_IMAGE_NUM) {
        return {};
    }
    vector<uint32_t> offsetArray(imageNum);
    // gain map offset need add Mpf marker offset;
    uint32_t markerHeaderOffset = preOffset + JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LENGTH_SIZE + MPF_TAG_SIZE;
    for (uint32_t i = INDEX_ONE; i < imageNum; i++) {
        offsetArray[i] = jpegMpf->images_[i].offset + markerHeaderOffset;
    }
    return offsetArray;
}

static bool ParseBaseISOTag(jpeg_marker_struct* marker)
{
    if (JPEG_MARKER_APP2 != marker->marker) {
        return false;
    }
    if (marker->data_length <= ISO_GAINMAP_TAG_SIZE) {
        return false;
    }
    if (memcmp(marker->data, ISO_GAINMAP_TAG, ISO_GAINMAP_TAG_SIZE) == EOK) {
        return true;
    }
    return false;
}

static bool GetISOJpegGainMapOffset(vector<jpeg_marker_struct*>& markerList,
    vector<uint32_t> preOffsets, uint32_t& offset)
{
    if (markerList.size() == EMPTY_SIZE) {
        return false;
    }
    vector<uint32_t> offsetArray;
    bool isoTag = false;
    for (uint32_t i = 0; i < markerList.size(); i++) {
        jpeg_marker_struct* marker = markerList[i];
        if (JPEG_MARKER_APP2 != marker->marker) {
            continue;
        }
        uint32_t markerOffset = preOffsets[i];
        if (offsetArray.size() == EMPTY_SIZE) {
            offsetArray = ParseMpfOffset(marker, markerOffset);
        }
        if (!isoTag) {
            isoTag = ParseBaseISOTag(marker);
        }
    }
    if (isoTag && offsetArray.size() == INDEX_TWO) {
        offset = offsetArray[INDEX_ONE];
        return true;
    }
    return false;
}


static ImageHdrType CheckJpegGainMapHdrType(SkJpegCodec* jpegCodec, uint32_t& offset)
{
    uint32_t allAppSize = JPEG_MARKER_TAG_SIZE;
    vector<jpeg_marker_struct*> vividMarkerList;
    vector<jpeg_marker_struct*> cuvaMarkerList;
    vector<jpeg_marker_struct*> isoMarkerList;
    vector<uint32_t> isoPreMarkerOffset;
    for (jpeg_marker_struct* marker = jpegCodec->decoderMgr()->dinfo()->marker_list; marker; marker = marker->next) {
        if (JPEG_MARKER_APP8 == marker->marker) {
            vividMarkerList.push_back(marker);
        }
        if (JPEG_MARKER_APP5 == marker->marker) {
            cuvaMarkerList.push_back(marker);
        }
        if (JPEG_MARKER_APP2 == marker->marker) {
            isoMarkerList.push_back(marker);
            isoPreMarkerOffset.push_back(allAppSize);
        }
        if (JPEG_MARKER_APP0 == (marker->marker & 0xF0)) {
            allAppSize += marker->data_length + JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LENGTH_SIZE;
        }
    }
    if (GetVividJpegGainMapOffset(vividMarkerList, allAppSize, offset)) {
        return ImageHdrType::HDR_VIVID_DUAL;
    }
    if (GetCuvaJpegGainMapOffset(cuvaMarkerList, allAppSize, offset)) {
        return ImageHdrType::HDR_CUVA;
    }
    if (GetISOJpegGainMapOffset(isoMarkerList, isoPreMarkerOffset, offset)) {
        return ImageHdrType::HDR_ISO_DUAL;
    }
    return ImageHdrType::SDR;
}

static ImageHdrType CheckHeifHdrType(SkHeifCodec* codec)
{
    return ImageHdrType::SDR;
}

ImageHdrType HdrHelper::CheckHdrType(SkCodec* codec, uint32_t& offset)
{
    offset = 0;
    ImageHdrType type = ImageHdrType::SDR;
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
            type = ImageHdrType::SDR;
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

static bool ParseVividJpegStaticMetadata(uint8_t* data, uint32_t& offset, uint32_t size, vector<uint8_t>& staticMetaVec)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    return false;
#else
    uint16_t staticMetadataSize = ImageUtils::BytesToUint16(data, offset);
    if (staticMetadataSize == EMPTY_SIZE) {
        staticMetaVec.resize(EMPTY_SIZE);
        return true;
    }
    if (staticMetadataSize > size || staticMetadataSize < VIVID_STATIC_METADATA_SIZE_IN_IMAGE) {
        return false;
    }

    HdrStaticMetadata staticMeta{};
    staticMeta.smpte2086.displayPrimaryRed.x = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.displayPrimaryRed.y = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.displayPrimaryGreen.x = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.displayPrimaryGreen.y = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.displayPrimaryBlue.x = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.displayPrimaryBlue.y = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.whitePoint.x = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.whitePoint.y = (float)ImageUtils::BytesToUint16(data, offset) * SM_COLOR_SCALE;
    staticMeta.smpte2086.maxLuminance = (float)ImageUtils::BytesToUint16(data, offset);
    staticMeta.smpte2086.minLuminance = (float)ImageUtils::BytesToUint16(data, offset) * SM_LUM_SCALE;
    staticMeta.cta861.maxContentLightLevel = (float)ImageUtils::BytesToUint16(data, offset);
    staticMeta.cta861.maxFrameAverageLightLevel = (float)ImageUtils::BytesToUint16(data, offset);
    uint32_t vecSize = sizeof(HdrStaticMetadata);
    staticMetaVec.resize(vecSize);
    if (memcpy_s(staticMetaVec.data(), vecSize, &staticMeta, vecSize) != EOK) {
        return false;
    }
    if (staticMetadataSize > VIVID_STATIC_METADATA_SIZE_IN_IMAGE) {
        offset += (staticMetadataSize - VIVID_STATIC_METADATA_SIZE_IN_IMAGE);
    }
    return true;
#endif
}

static ExtendInfoMain ParseExtendInfoMain(uint8_t* data, uint32_t& offset, bool isThreeCom)
{
    ExtendInfoMain infoMain{};
    infoMain.gainMapMin[INDEX_ZERO] = ImageUtils::BytesToFloat(data, offset);
    infoMain.gainMapMax[INDEX_ZERO] = ImageUtils::BytesToFloat(data, offset);
    infoMain.gamma[INDEX_ZERO] = ImageUtils::BytesToFloat(data, offset);
    infoMain.baseSdrImageOffset[INDEX_ZERO] = ImageUtils::BytesToFloat(data, offset);
    infoMain.altHdrImageOffset[INDEX_ZERO] = ImageUtils::BytesToFloat(data, offset);
    if (isThreeCom) {
        infoMain.gainMapMin[INDEX_ONE] = ImageUtils::BytesToFloat(data, offset);
        infoMain.gainMapMax[INDEX_ONE] = ImageUtils::BytesToFloat(data, offset);
        infoMain.gamma[INDEX_ONE] = ImageUtils::BytesToFloat(data, offset);
        infoMain.baseSdrImageOffset[INDEX_ONE] = ImageUtils::BytesToFloat(data, offset);
        infoMain.altHdrImageOffset[INDEX_ONE] = ImageUtils::BytesToFloat(data, offset);
        infoMain.gainMapMin[INDEX_TWO] = ImageUtils::BytesToFloat(data, offset);
        infoMain.gainMapMax[INDEX_TWO] = ImageUtils::BytesToFloat(data, offset);
        infoMain.gamma[INDEX_TWO] = ImageUtils::BytesToFloat(data, offset);
        infoMain.baseSdrImageOffset[INDEX_TWO] = ImageUtils::BytesToFloat(data, offset);
        infoMain.altHdrImageOffset[INDEX_TWO] = ImageUtils::BytesToFloat(data, offset);
    } else {
        infoMain.gainMapMin[INDEX_ONE] = infoMain.gainMapMin[INDEX_ZERO];
        infoMain.gainMapMax[INDEX_ONE] = infoMain.gainMapMax[INDEX_ZERO];
        infoMain.gamma[INDEX_ONE] = infoMain.gamma[INDEX_ZERO];
        infoMain.baseSdrImageOffset[INDEX_ONE] = infoMain.baseSdrImageOffset[INDEX_ZERO];
        infoMain.altHdrImageOffset[INDEX_ONE] = infoMain.altHdrImageOffset[INDEX_ZERO];
        infoMain.gainMapMin[INDEX_TWO] = infoMain.gainMapMin[INDEX_ZERO];
        infoMain.gainMapMax[INDEX_TWO] = infoMain.gainMapMax[INDEX_ZERO];
        infoMain.gamma[INDEX_TWO] = infoMain.gamma[INDEX_ZERO];
        infoMain.baseSdrImageOffset[INDEX_TWO] = infoMain.baseSdrImageOffset[INDEX_ZERO];
        infoMain.altHdrImageOffset[INDEX_TWO] = infoMain.altHdrImageOffset[INDEX_ZERO];
    }
    return infoMain;
}

static bool ParseColorInfo(uint8_t* data, uint32_t& offset, uint32_t length, ColorInfo& colorInfo)
{
    uint8_t size = data[offset++];
    if (size == EMPTY_SIZE) {
        return true;
    }
    if (size > length - offset || size != COLOR_INFO_BYTES) {
        return false;
    }
    colorInfo.primary = data[offset++];
    colorInfo.transFunc = data[offset++];
    colorInfo.model = data[offset++];
    return true;
}

static bool ParseTransformInfo(uint8_t* data, uint32_t& offset, uint32_t length, TransformInfo& info)
{
    uint8_t size = ImageUtils::BytesToUint16(data, offset);
    if (size == EMPTY_SIZE) {
        info.mappingFlag = EMPTY_SIZE;
        info.mapping.resize(EMPTY_SIZE);
        return true;
    }
    if (size > length - offset || size <= UINT8_BYTE_COUNT) {
        info.mappingFlag = EMPTY_SIZE;
        info.mapping.resize(EMPTY_SIZE);
        return false;
    }
    info.mappingFlag = data[offset++];
    if (info.mappingFlag == INDEX_ZERO) {
        info.mapping.resize(EMPTY_SIZE);
        return true;
    } else if (info.mappingFlag > size - UINT16_BYTE_COUNT) {
        return false;
    }
    info.mapping.resize(info.mappingFlag);
    if (memcpy_s(info.mapping.data(), info.mappingFlag, data + offset, info.mappingFlag) != EOK) {
        return false;
    }
    offset += info.mappingFlag;
    return true;
}

static void ConvertExtendInfoMain(ExtendInfoMain info, HDRVividGainmapMetadata& metadata)
{
    metadata.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] = info.gainMapMax[INDEX_ZERO];
    metadata.enhanceClippedThreholdMaxGainmap[INDEX_ONE] = info.gainMapMax[INDEX_ONE];
    metadata.enhanceClippedThreholdMaxGainmap[INDEX_TWO] = info.gainMapMax[INDEX_TWO];
    metadata.enhanceClippedThreholdMinGainmap[INDEX_ZERO] = info.gainMapMin[INDEX_ZERO];
    metadata.enhanceClippedThreholdMinGainmap[INDEX_ONE] = info.gainMapMin[INDEX_ONE];
    metadata.enhanceClippedThreholdMinGainmap[INDEX_TWO] = info.gainMapMin[INDEX_TWO];
    metadata.enhanceMappingGamma[INDEX_ZERO] = info.gamma[INDEX_ZERO];
    metadata.enhanceMappingGamma[INDEX_ONE] = info.gamma[INDEX_ONE];
    metadata.enhanceMappingGamma[INDEX_TWO] = info.gamma[INDEX_TWO];
    metadata.enhanceMappingBaselineOffset[INDEX_ZERO] = info.baseSdrImageOffset[INDEX_ZERO];
    metadata.enhanceMappingBaselineOffset[INDEX_ONE] = info.baseSdrImageOffset[INDEX_ONE];
    metadata.enhanceMappingBaselineOffset[INDEX_TWO] = info.baseSdrImageOffset[INDEX_TWO];
    metadata.enhanceMappingAlternateOffset[INDEX_ZERO] = info.altHdrImageOffset[INDEX_ZERO];
    metadata.enhanceMappingAlternateOffset[INDEX_ONE] = info.altHdrImageOffset[INDEX_ONE];
    metadata.enhanceMappingAlternateOffset[INDEX_TWO] = info.altHdrImageOffset[INDEX_TWO];
}

static void ConvertExtendInfoExtention(ExtendInfoExtention ext, HDRVividGainmapMetadata& metadata)
{
    metadata.baseColorPrimary = ext.baseColor.primary;
    metadata.baseTransFunction = ext.baseColor.transFunc;
    metadata.baseColorModel = ext.baseColor.model;
    metadata.enhanceDataColorPrimary = ext.enhanceDataColor.primary;
    metadata.enhanceDataTransFunction = ext.enhanceDataColor.transFunc;
    metadata.enhanceDataColorModel = ext.enhanceDataColor.model;
    metadata.combineColorPrimary = ext.combineColor.primary;
    metadata.combineTransFunction = ext.combineColor.transFunc;
    metadata.combineColorModel = ext.combineColor.model;
    metadata.enhanceColorPrimary = ext.enhanceColor.primary;
    metadata.enhanceTransFunction = ext.enhanceColor.transFunc;
    metadata.enhanceColorModel = ext.enhanceColor.model;
    metadata.baseMappingFlag = ext.baseMapping.mappingFlag;
    metadata.baseMapping = ext.baseMapping.mapping;
    metadata.baseMappingSize = ext.baseMapping.mapping.size();
    metadata.combineMappingFlag = ext.combineMapping.mappingFlag;
    metadata.combineMapping = ext.combineMapping.mapping;
    metadata.combineMappingSize = ext.combineMapping.mapping.size();
    metadata.baseIccSize = EMPTY_SIZE;
    metadata.baseICC.resize(EMPTY_SIZE);
    metadata.enhanceICCSize = EMPTY_SIZE;
    metadata.enhanceICC.resize(EMPTY_SIZE);
}

static bool ParseVividJpegMetadata(uint8_t* data, uint32_t& dataOffset, uint32_t length, HdrMetadata& metadata)
{
    uint16_t metadataSize = ImageUtils::BytesToUint16(data, dataOffset);
    if (metadataSize > length - dataOffset) {
        return false;
    }
    if (!ParseVividJpegStaticMetadata(data, dataOffset, metadataSize, metadata.staticMetadata)) {
        return false;
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

static bool ParseVividJpegExtendInfo(uint8_t* data, uint32_t length, HDRVividGainmapMetadata& metadata)
{
    uint32_t dataOffset = 0;
    uint16_t metadataSize = ImageUtils::BytesToUint16(data, dataOffset);
    if (metadataSize > length - UINT16_BYTE_COUNT) {
        return false;
    }
    uint8_t components = data[dataOffset++];
    if (components != THREE_COMPONENTS && components != ONE_COMPONENT) {
        return false;
    }
    ExtendInfoMain extendInfoMain = ParseExtendInfoMain(data, dataOffset, components == THREE_COMPONENTS);
    ExtendInfoExtention extendInfoExtention;
    if (!ParseColorInfo(data, dataOffset, length, extendInfoExtention.baseColor)) {
        return false;
    }
    if (!ParseColorInfo(data, dataOffset, length, extendInfoExtention.enhanceDataColor)) {
        return false;
    }
    if (!ParseColorInfo(data, dataOffset, length, extendInfoExtention.enhanceColor)) {
        return false;
    }
    if (!ParseColorInfo(data, dataOffset, length, extendInfoExtention.combineColor)) {
        return false;
    }
    if (!ParseTransformInfo(data, dataOffset, length, extendInfoExtention.baseMapping)) {
        return false;
    }
    if (!ParseTransformInfo(data, dataOffset, length, extendInfoExtention.combineMapping)) {
        return false;
    }
    ConvertExtendInfoMain(extendInfoMain, metadata);
    ConvertExtendInfoExtention(extendInfoExtention, metadata);
    return true;
}

static bool GetVividJpegMetadata(jpeg_marker_struct* markerList, HdrMetadata& metadata)
{
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP8 != marker->marker) {
            continue;
        }
        uint8_t* data = marker->data;
        uint32_t length = marker->data_length;
        uint32_t dataOffset = 0;
        if (memcmp(marker->data, ITUT35_TAG, sizeof(ITUT35_TAG)) != 0) {
            continue;
        }
        dataOffset += sizeof(ITUT35_TAG);
        uint8_t itut35CountryCode = data[dataOffset++];
        uint16_t terminalProvideCode = ImageUtils::BytesToUint16(data, dataOffset);
        uint16_t terminalProvideOrientedCode = ImageUtils::BytesToUint16(data, dataOffset);
        IMAGE_LOGD("vivid metadata countryCode=%{public}d,terminalCode=%{public}d,orientedcode=%{public}d",
            itut35CountryCode, terminalProvideCode, terminalProvideOrientedCode);
        uint8_t extendedFrameNumber = data[dataOffset++];
        if (extendedFrameNumber < JPEG_IMAGE_NUM) {
            return false;
        }
        uint8_t fileType = data[dataOffset++];
        uint8_t metaType = data[dataOffset++];
        uint8_t enhanceType = data[dataOffset++];
        uint8_t hdrType = data[dataOffset++];
        IMAGE_LOGD("vivid metadata info hdrType=%{public}d, enhanceType=%{public}d", hdrType, enhanceType);
        if (fileType != VIVID_FILE_TYPE_GAINMAP) {
            return false;
        }
        bool getMetadata = false;
        if (metaType > 0 && length > dataOffset + UINT16_BYTE_COUNT) {
            getMetadata = ParseVividJpegMetadata(data, dataOffset, length, metadata);
        }
        const uint8_t hasEnhanceInfo = 1;
        if (enhanceType == hasEnhanceInfo && length > dataOffset + UINT16_BYTE_COUNT) {
            metadata.gainmapMetadataFlag =
                ParseVividJpegExtendInfo(data + dataOffset, length - dataOffset, metadata.gainmapMetadata);
            IMAGE_LOGD("vivid get extend info result = %{public}d", metadata.gainmapMetadataFlag);
        }
        return getMetadata;
    }
    return false;
}

static void ParseISOExtendInfoMain(uint8_t* data, uint32_t& offset, ExtendInfoMain& info, uint8_t index)
{
    if (index > INDEX_TWO) {
        return;
    }
    int32_t minGainmapNumerator = ImageUtils::BytesToInt32(data, offset);
    uint32_t minGainmapDenominator = ImageUtils::BytesToUint32(data, offset);
    int32_t maxGainmapNumerator = ImageUtils::BytesToInt32(data, offset);
    uint32_t maxGainmapDenominator = ImageUtils::BytesToUint32(data, offset);
    uint32_t gammaNumerator = ImageUtils::BytesToUint32(data, offset);
    uint32_t gammaDenominator = ImageUtils::BytesToUint32(data, offset);
    int32_t baseImageOffsetNumerator = ImageUtils::BytesToInt32(data, offset);
    uint32_t baseImageOffsetDenominator = ImageUtils::BytesToUint32(data, offset);
    int32_t altImageOffsetNumerator = ImageUtils::BytesToInt32(data, offset);
    uint32_t altImageOffsetDenominator = ImageUtils::BytesToUint32(data, offset);
    if (minGainmapDenominator == EMPTY_SIZE) {
        info.gainMapMin[index] = EMPTY_SIZE;
    } else {
        info.gainMapMin[index] = (float)minGainmapNumerator / (float)minGainmapDenominator;
    }

    if (maxGainmapDenominator == EMPTY_SIZE) {
        info.gainMapMax[index] = EMPTY_SIZE;
    } else {
        info.gainMapMax[index] = (float)maxGainmapNumerator / (float)maxGainmapDenominator;
    }

    if (gammaDenominator == EMPTY_SIZE) {
        info.gamma[index] = EMPTY_SIZE;
    } else {
        info.gamma[index] = (float)gammaNumerator / (float)gammaDenominator;
    }

    if (baseImageOffsetDenominator == EMPTY_SIZE) {
        info.baseSdrImageOffset[index] = EMPTY_SIZE;
    } else {
        info.baseSdrImageOffset[index] = (float)baseImageOffsetNumerator / (float)baseImageOffsetDenominator;
    }

    if (altImageOffsetDenominator == EMPTY_SIZE) {
        info.altHdrImageOffset[index] = EMPTY_SIZE;
    } else {
        info.altHdrImageOffset[index] = (float)altImageOffsetNumerator / (float)altImageOffsetDenominator;
    }
}

static void ParseISOExtendInfoThreeCom(uint8_t* data, uint32_t& offset, bool threeCom, ExtendInfoMain& info)
{
    ParseISOExtendInfoMain(data, offset, info, INDEX_ZERO);
    if (threeCom) {
        ParseISOExtendInfoMain(data, offset, info, INDEX_ONE);
        ParseISOExtendInfoMain(data, offset, info, INDEX_TWO);
    } else {
        info.gainMapMin[INDEX_ONE] = info.gainMapMin[INDEX_ZERO];
        info.gainMapMax[INDEX_ONE] = info.gainMapMax[INDEX_ZERO];
        info.gamma[INDEX_ONE] = info.gamma[INDEX_ZERO];
        info.baseSdrImageOffset[INDEX_ONE] = info.baseSdrImageOffset[INDEX_ZERO];
        info.altHdrImageOffset[INDEX_ONE] = info.altHdrImageOffset[INDEX_ZERO];
        info.gainMapMin[INDEX_TWO] = info.gainMapMin[INDEX_ZERO];
        info.gainMapMax[INDEX_TWO] = info.gainMapMax[INDEX_ZERO];
        info.gamma[INDEX_TWO] = info.gamma[INDEX_ZERO];
        info.baseSdrImageOffset[INDEX_TWO] = info.baseSdrImageOffset[INDEX_ZERO];
        info.altHdrImageOffset[INDEX_TWO] = info.altHdrImageOffset[INDEX_ZERO];
    }
}

static bool GetISOGainmapMetadata(jpeg_marker_struct* markerList, HdrMetadata& metadata)
{
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP2 != marker->marker) {
            continue;
        }
        if (marker->data_length <= ISO_GAINMAP_TAG_SIZE ||
            memcmp(marker->data, ISO_GAINMAP_TAG, ISO_GAINMAP_TAG_SIZE) != 0) {
            continue;
        }
        uint8_t* data = marker->data + ISO_GAINMAP_TAG_SIZE;
        uint32_t length = marker->data_length - ISO_GAINMAP_TAG_SIZE;
        uint32_t dataOffset = 0;
        if (length < ISO_GAINMAP_METADATA_PAYLOAD_MIN_SIZE) {
            return false;
        }
        uint32_t version = ImageUtils::BytesToUint32(data, dataOffset);
        if ((version & 0xFF) != EMPTY_SIZE) {
            return false;
        }
        uint8_t flag = data[dataOffset++];

        uint32_t baseHeadroomNumerator = ImageUtils::BytesToUint32(data, dataOffset);
        uint32_t baseHeadroomDenominator = ImageUtils::BytesToUint32(data, dataOffset);
        uint32_t altHeadroomNumerator = ImageUtils::BytesToUint32(data, dataOffset);
        uint32_t altHeadroomDenominator = ImageUtils::BytesToUint32(data, dataOffset);
        float baseHeadroom = (float)EMPTY_SIZE;
        float altHeadroom = (float)EMPTY_SIZE;
        if (baseHeadroomDenominator != EMPTY_SIZE) {
            baseHeadroom = (float)baseHeadroomNumerator / (float)baseHeadroomDenominator;
        }
        if (altHeadroomDenominator != EMPTY_SIZE) {
            altHeadroom = (float)altHeadroomNumerator / (float)altHeadroomDenominator;
        }
        IMAGE_LOGD("iso version = %{public}d, flag = %{public}d, baseHeadroom = %{public}f,"
            "altHeadroom = %{public}f", version, flag, baseHeadroom, altHeadroom);
        bool isThreeCom = (flag & 0x01) ? true : false;
        ExtendInfoMain infoMain{};
        ParseISOExtendInfoThreeCom(data, dataOffset, isThreeCom, infoMain);
        ConvertExtendInfoMain(infoMain, metadata.gainmapMetadata);
        metadata.gainmapMetadataFlag = true;
        return true;
    }
    return false;
}

static bool GetJpegGainMapMetadata(SkJpegCodec* codec, ImageHdrType type, HdrMetadata& metadata)
{
    if (codec == nullptr || codec->decoderMgr() == nullptr) {
        return false;
    }
    jpeg_marker_struct* markerList = codec->decoderMgr()->dinfo()->marker_list;
    if (!markerList) {
        return false;
    }
    switch (type) {
        case ImageHdrType::HDR_VIVID_DUAL:
            return GetVividJpegMetadata(markerList, metadata);
        case ImageHdrType::HDR_CUVA:
            return GetCuvaGainMapMetadata(markerList, metadata.dynamicMetadata);
        case ImageHdrType::HDR_ISO_DUAL:
            return GetISOGainmapMetadata(markerList, metadata);
        default:
            return false;
    }
}

static bool GetHeifMetadata(SkHeifCodec* codec, ImageHdrType type, HdrMetadata& metadata)
{
    return false;
}

bool HdrHelper::GetMetadata(SkCodec* codec, ImageHdrType type, HdrMetadata& metadata)
{
    if (type <= ImageHdrType::SDR || codec == nullptr) {
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
static void PackVividPreInfo(vector<uint8_t>& bytes, uint32_t& offset, bool base, bool enhanceType)
{
    bytes[offset++] = 0x26; // itut35 country code
    bytes[offset++] = 0x00;
    bytes[offset++] = 0x04; // terminalProvideCode
    bytes[offset++] = 0x00;
    bytes[offset++] = 0x07; // terminalProvideOrientedCode
    bytes[offset++] = 0x02; // extendFrameNumber
    bytes[offset++] = base ? INDEX_ONE : INDEX_TWO; // fileType
    bytes[offset++] = base ? INDEX_ZERO : INDEX_ONE; // metaType
    bytes[offset++] = ((!base) & enhanceType) ? INDEX_ONE : INDEX_ZERO; // enhanceType
    bytes[offset++] = INDEX_ZERO;
}


uint32_t HdrJpegPackerHelper::GetBaseVividMarkerSize()
{
    const uint32_t baseInfoMarkerLength =
        JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LENGTH_SIZE + ITUT35_TAG_SIZE +
        VIVID_PRE_INFO_SIZE + UINT32_BYTE_COUNT + // offset size
        UINT32_BYTE_COUNT; // gainmap length size
    return baseInfoMarkerLength;
}

uint32_t HdrJpegPackerHelper::GetMpfMarkerSize()
{
    return HDR_MULTI_PICTURE_APP_LENGTH;
}

vector<uint8_t> HdrJpegPackerHelper::PackBaseVividMarker(uint32_t gainmapOffset, uint32_t appSize)
{
    const uint32_t baseInfoMarkerLength = GetBaseVividMarkerSize();
    vector<uint8_t> bytes(baseInfoMarkerLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP8;
    // length does not contain marker tag size;
    uint32_t markerDataLength = baseInfoMarkerLength - JPEG_MARKER_TAG_SIZE;
    ImageUtils::Uint16ToBytes(markerDataLength, bytes, index);
    ImageUtils::ArrayToBytes(ITUT35_TAG, ITUT35_TAG_SIZE, bytes, index);
    PackVividPreInfo(bytes, index, true, false);
    // set gainmap offset
    ImageUtils::Uint32ToBytes(gainmapOffset, bytes, index);
    // set (gainmap size - app size)
    ImageUtils::Uint32ToBytes(gainmapOffset - appSize, bytes, index);
    return bytes;
}

vector<uint8_t> HdrJpegPackerHelper::PackBaseMpfMarker(uint32_t baseSize, uint32_t gainmapSize, uint32_t appOffset)
{
    SingleJpegImage baseImage = {
        .offset = 0,
        .size = baseSize,
    };
    SingleJpegImage gainmapImage = {
        .offset = baseSize - appOffset - JPEG_MARKER_TAG_SIZE - JPEG_MARKER_LENGTH_SIZE - MPF_TAG_SIZE,
        .size = gainmapSize,
    };
    return JpegMpfPacker::PackHdrJpegMpfMarker(baseImage, gainmapImage);
}

vector<uint8_t> HdrJpegPackerHelper::PackBaseISOMarker()
{
    // marker + isoGainmapTag + ISOPayload
    uint32_t isoBaseLength = UINT32_BYTE_COUNT + ISO_GAINMAP_TAG_SIZE + UINT32_BYTE_COUNT;
    vector<uint8_t> bytes(isoBaseLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP2;
    // length dose not contain marker
    uint32_t length = isoBaseLength - JPEG_MARKER_TAG_SIZE;
    ImageUtils::Uint16ToBytes(length, bytes, index); // set iso marker size
    ImageUtils::ArrayToBytes(ISO_GAINMAP_TAG, ISO_GAINMAP_TAG_SIZE, bytes, index);
    ImageUtils::Uint32ToBytes(EMPTY_SIZE, bytes, index); // set iso payload size
    return bytes;
}

static void PackExtendInfoMain(vector<uint8_t>& bytes, uint32_t& offset, HDRVividGainmapMetadata& metadata)
{
    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMinGainmap[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMaxGainmap[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingGamma[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingBaselineOffset[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingAlternateOffset[INDEX_ZERO], bytes, offset);

    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMinGainmap[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMaxGainmap[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingGamma[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingBaselineOffset[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingAlternateOffset[INDEX_ONE], bytes, offset);

    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMinGainmap[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceClippedThreholdMaxGainmap[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingGamma[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingBaselineOffset[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.enhanceMappingAlternateOffset[INDEX_TWO], bytes, offset);
}

static void PackTransformInfo(vector<uint8_t>& bytes, uint32_t& offset, uint8_t flag, vector<uint8_t> mapping)
{
    if (flag == EMPTY_SIZE || flag != mapping.size()) {
        ImageUtils::Uint16ToBytes((uint16_t)EMPTY_SIZE, bytes, offset);
        return;
    }
    uint16_t transformSize = flag + UINT8_BYTE_COUNT;
    ImageUtils::Uint16ToBytes(transformSize, bytes, offset);
    bytes[offset++] = flag;
    if (memcpy_s(bytes.data() + offset, flag, mapping.data(), flag) != 0) {
        offset -= (UINT8_BYTE_COUNT + UINT16_BYTE_COUNT);
        ImageUtils::Uint16ToBytes((uint16_t)EMPTY_SIZE, bytes, offset);
        return;
    }
    offset += flag;
}

static void PackExtendInfoExtention(vector<uint8_t>& bytes, uint32_t& offset, HDRVividGainmapMetadata& metadata)
{
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.baseColorPrimary;
    bytes[offset++] = metadata.baseTransFunction;
    bytes[offset++] = metadata.baseColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.enhanceDataColorPrimary;
    bytes[offset++] = metadata.enhanceDataTransFunction;
    bytes[offset++] = metadata.enhanceDataColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.enhanceColorPrimary;
    bytes[offset++] = metadata.enhanceTransFunction;
    bytes[offset++] = metadata.enhanceColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.combineColorPrimary;
    bytes[offset++] = metadata.combineTransFunction;
    bytes[offset++] = metadata.combineColorModel;
    PackTransformInfo(bytes, offset, metadata.baseMappingFlag, metadata.baseMapping);
    PackTransformInfo(bytes, offset, metadata.combineMappingFlag, metadata.combineMapping);
}

static uint16_t GetExtendMetadataSize(bool vividExtendFlag, HDRVividGainmapMetadata& metadata)
{
    if (vividExtendFlag) {
        return EMPTY_SIZE;
    }
    const uint8_t colorInfoNum = 4;
    uint16_t extendInfoExtentionSize = (COLOR_INFO_BYTES + UINT8_BYTE_COUNT) * colorInfoNum +
        UINT16_BYTE_COUNT + UINT16_BYTE_COUNT; // "baseTransformInfoSize" count + "EnhanceTransformInfoSize" count
    if (metadata.baseMappingFlag > EMPTY_SIZE) {
        // "mapping" + "mapping" bytes
        extendInfoExtentionSize += metadata.baseMappingFlag + UINT8_BYTE_COUNT;
    }
    if (metadata.combineMappingFlag > EMPTY_SIZE) {
        extendInfoExtentionSize += metadata.combineMappingFlag + UINT8_BYTE_COUNT;
    }
    uint16_t extendSize = UINT8_BYTE_COUNT + EXTEND_INFO_MAIN_SIZE + extendInfoExtentionSize;
    return extendSize;
}

static void PackExtendMetadata(vector<uint8_t>& bytes, uint32_t& index, HDRVividGainmapMetadata metadata)
{
    uint16_t length = GetExtendMetadataSize(true, metadata);
    ImageUtils::Uint16ToBytes(length, bytes, index);
    bytes[index++] = THREE_COMPONENTS;
    PackExtendInfoMain(bytes, index, metadata);
    PackExtendInfoExtention(bytes, index, metadata);
}

static bool PackVividStaticMetadata(vector<uint8_t>& bytes, uint32_t& index, vector<uint8_t>& staticVec)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    return false;
#else
    HdrStaticMetadata staticMeta;
    uint32_t vecSize = sizeof(HdrStaticMetadata);
    if (memcpy_s(&staticMeta, vecSize, staticVec.data(), vecSize) != EOK) {
        return false;
    }
    ImageUtils::Uint16ToBytes(VIVID_STATIC_METADATA_SIZE_IN_IMAGE, bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryRed.x / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryRed.y / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryGreen.x / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryGreen.y / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryBlue.x / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.displayPrimaryBlue.y / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.whitePoint.x / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.whitePoint.y / SM_COLOR_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.maxLuminance), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)(staticMeta.smpte2086.minLuminance / SM_LUM_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)staticMeta.cta861.maxContentLightLevel, bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)staticMeta.cta861.maxFrameAverageLightLevel, bytes, index);
    return true;
#endif
}

static bool PackVividMetadata(vector<uint8_t>& bytes, uint32_t& index, HdrMetadata& metadata)
{
    uint32_t dynamicMetadataSize = metadata.dynamicMetadata.size() + VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
    const uint32_t metadataSize =
        UINT16_BYTE_COUNT + VIVID_STATIC_METADATA_SIZE_IN_IMAGE + UINT16_BYTE_COUNT + dynamicMetadataSize;
    PackVividPreInfo(bytes, index, false, metadata.gainmapMetadataFlag);
    ImageUtils::Uint16ToBytes(metadataSize, bytes, index);
    if (!PackVividStaticMetadata(bytes, index, metadata.staticMetadata)) {
        return false;
    }
    ImageUtils::Uint16ToBytes(dynamicMetadataSize, bytes, index);
    ImageUtils::ArrayToBytes(VIVID_DYNAMIC_METADATA_PRE_INFO, VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE, bytes, index);
    if (memcpy_s(bytes.data() + index, bytes.size() - index,
        metadata.dynamicMetadata.data(), metadata.dynamicMetadata.size()) != EOK) {
        return false;
    }
    index += metadata.dynamicMetadata.size();
    if (metadata.gainmapMetadataFlag) {
        PackExtendMetadata(bytes, index, metadata.gainmapMetadata);
    }
    return true;
}

std::vector<uint8_t> HdrJpegPackerHelper::PackVividMetadataMarker(HdrMetadata& metadata)
{
    uint32_t dynamicMetadataSize = metadata.dynamicMetadata.size() + VIVID_DYNAMIC_METADATA_PRE_INFO_SIZE;
    // metadataSize + staticMetadataSize + staticMetadata + dynamicMetadataSize + dynamicMetadata
    const uint32_t metadataSize = UINT16_BYTE_COUNT + UINT16_BYTE_COUNT + VIVID_STATIC_METADATA_SIZE_IN_IMAGE +
        UINT16_BYTE_COUNT + dynamicMetadataSize;
    uint32_t extendInfoSize = GetExtendMetadataSize(metadata.gainmapMetadataFlag, metadata.gainmapMetadata);
    uint32_t markerLength = UINT32_BYTE_COUNT + ITUT35_TAG_SIZE + VIVID_METADATA_PRE_INFO_SIZE +
        metadataSize + UINT16_BYTE_COUNT + extendInfoSize;
    vector<uint8_t> bytes(markerLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP8;
    uint32_t storeLength = markerLength - JPEG_MARKER_TAG_SIZE;
    ImageUtils::Uint16ToBytes(storeLength, bytes, index);
    ImageUtils::ArrayToBytes(ITUT35_TAG, ITUT35_TAG_SIZE, bytes, index);
    if (!PackVividMetadata(bytes, index, metadata)) {
        IMAGE_LOGE("hdr image package metadata failed");
        return {};
    }
    return bytes;
}

static float GetMaxGainmapMax(float gainmapMax[THREE_COMPONENTS])
{
    float max = gainmapMax[INDEX_ZERO] > gainmapMax[INDEX_ONE] ? gainmapMax[INDEX_ZERO] : gainmapMax[INDEX_ONE];
    return max > gainmapMax[INDEX_TWO] ? max : gainmapMax[INDEX_TWO];
}


static void PackISOExtendInfo(vector<uint8_t>& bytes, uint32_t& offset, HDRVividGainmapMetadata& metadata)
{
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMinGainmap[INDEX_ZERO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Uint32ToBytes((uint32_t)(DENOMINATOR * metadata.enhanceMappingGamma[INDEX_ZERO]), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingBaselineOffset[INDEX_ZERO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingAlternateOffset[INDEX_ZERO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);

    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMinGainmap[INDEX_ONE] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMaxGainmap[INDEX_ONE] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Uint32ToBytes((uint32_t)(DENOMINATOR * metadata.enhanceMappingGamma[INDEX_ONE]), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingBaselineOffset[INDEX_ONE] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingAlternateOffset[INDEX_ONE] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);

    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMinGainmap[INDEX_TWO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceClippedThreholdMaxGainmap[INDEX_TWO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Uint32ToBytes((uint32_t)(DENOMINATOR * metadata.enhanceMappingGamma[INDEX_TWO]), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingBaselineOffset[INDEX_TWO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
    ImageUtils::Int32ToBytes(
        (int32_t)(metadata.enhanceMappingAlternateOffset[INDEX_TWO] * DENOMINATOR), bytes, offset);
    ImageUtils::Uint32ToBytes(DENOMINATOR, bytes, offset);
}

vector<uint8_t> HdrJpegPackerHelper::PackISOMetadataMarker(HdrMetadata& metadata)
{
    HDRVividGainmapMetadata gainmapMetadata = metadata.gainmapMetadata;
    // flag(u8)+baseheadroomNumerator(u32)+baseheadroomDenomintor(u32)+altheadroom(u32)+altheadroomDenominator(u32)
    uint32_t isoInfoSize =
        UINT8_BYTE_COUNT + UINT32_BYTE_COUNT + UINT32_BYTE_COUNT + UINT32_BYTE_COUNT + UINT32_BYTE_COUNT;
    const uint32_t extendInfoMainParaNum = 10;
    const uint32_t isoExtendInfoSize = UINT32_BYTE_COUNT * extendInfoMainParaNum * THREE_COMPONENTS;
    // marker + isoGainmapTag + version + isoinfo + extendInfoMain
    uint32_t markerLength = UINT32_BYTE_COUNT + ISO_GAINMAP_TAG_SIZE + UINT32_BYTE_COUNT +
        isoInfoSize + isoExtendInfoSize;
    vector<uint8_t> bytes(markerLength);
    uint32_t index = 0;
    bytes[index++] = JPEG_MARKER_PREFIX;
    bytes[index++] = JPEG_MARKER_APP2;
    uint32_t storeLength = markerLength - JPEG_MARKER_TAG_SIZE;
    ImageUtils::Uint16ToBytes(storeLength, bytes, index);
    if (memcpy_s(bytes.data() + index, bytes.size() - index, ISO_GAINMAP_TAG, ISO_GAINMAP_TAG_SIZE) != EOK) {
        return {};
    }
    index += ISO_GAINMAP_TAG_SIZE;
    const uint32_t isoVersion = 0;
    ImageUtils::Uint32ToBytes(isoVersion, bytes, index);
    bytes[index++] = 0x01; // flag three components
    uint32_t baseHeadroomNumerator = 0x00;
    uint32_t baseHeadroomDenominator = 0x01;
    ImageUtils::Uint32ToBytes(baseHeadroomNumerator, bytes, index);
    ImageUtils::Uint32ToBytes(baseHeadroomDenominator, bytes, index);
    float alternateHeadroom = GetMaxGainmapMax(gainmapMetadata.enhanceClippedThreholdMaxGainmap);
    uint32_t altHeadroomNumerator = 0x00;
    uint32_t altHeadroomDenominator = 0x01;
    if (alternateHeadroom > (float)EMPTY_SIZE) {
        altHeadroomNumerator = (uint32_t)(DENOMINATOR * alternateHeadroom);
        altHeadroomDenominator = DENOMINATOR;
    }
    ImageUtils::Uint32ToBytes(altHeadroomNumerator, bytes, index);
    ImageUtils::Uint32ToBytes(altHeadroomDenominator, bytes, index);
    PackISOExtendInfo(bytes, index, gainmapMetadata);
    return bytes;
}

static bool WriteJpegPreApp(sk_sp<SkData>& imageData, SkWStream& outputStream, uint32_t& index)
{
    const uint8_t* imageBytes = reinterpret_cast<const uint8_t*>(imageData->data());
    if (*imageBytes != JPEG_MARKER_PREFIX || *(imageBytes + INDEX_ONE) != JPEG_SOI) {
        IMAGE_LOGE("hdr encode, the spliced image is not a jpeg");
        return false;
    }
    uint32_t dataSize = imageData->size();
    outputStream.write(imageBytes, JPEG_MARKER_TAG_SIZE);
    index += JPEG_MARKER_TAG_SIZE;
    while (index < dataSize) {
        if (imageBytes[index] != JPEG_MARKER_PREFIX) {
            return false;
        }
        if ((imageBytes[index + INDEX_ONE] & 0xF0) != JPEG_MARKER_APP0) {
            return true;
        }
        uint16_t markerSize = (imageBytes[index + INDEX_TWO] << MOVE_ONE_BYTE) | imageBytes[index + INDEX_THREE];
        if (markerSize > dataSize) {
            return false;
        }
        outputStream.write(imageBytes + index, markerSize + JPEG_MARKER_TAG_SIZE);
        index += (markerSize + JPEG_MARKER_TAG_SIZE);
    }
    return false;
}

uint32_t HdrJpegPackerHelper::SpliceHdrStream(sk_sp<SkData>& baseImage, sk_sp<SkData>& gainmapImage,
    SkWStream& output, HdrMetadata& metadata)
{
    if (baseImage == nullptr || gainmapImage == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    uint32_t offset = 0;
    if (!WriteJpegPreApp(baseImage, output, offset)) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    std::vector<uint8_t> gainmapMetadataPack = PackVividMetadataMarker(metadata);
    std::vector<uint8_t> gainmapISOMetadataPack = PackISOMetadataMarker(metadata);
    uint32_t gainmapSize = gainmapImage->size() + gainmapMetadataPack.size() + gainmapISOMetadataPack.size();
    std::vector<uint8_t> baseISOInfo = PackBaseISOMarker();
    uint32_t baseVividApp8Size = GetBaseVividMarkerSize();
    uint32_t baseMpfApp2Size = GetMpfMarkerSize();
    uint32_t baseSize = baseImage->size() + baseISOInfo.size() + baseVividApp8Size + baseMpfApp2Size;
    uint32_t allAppSize = offset + baseISOInfo.size() + baseVividApp8Size + baseMpfApp2Size;
    std::vector<uint8_t> baseVividInfo = PackBaseVividMarker(baseSize, allAppSize);
    std::vector<uint8_t> mpfInfo = PackBaseMpfMarker(baseSize, gainmapSize, offset + baseVividApp8Size);
    output.write(baseVividInfo.data(), baseVividInfo.size());
    output.write(mpfInfo.data(), mpfInfo.size());
    output.write(baseISOInfo.data(), baseISOInfo.size());
    const uint8_t* baseBytes = reinterpret_cast<const uint8_t*>(baseImage->data());
    output.write(baseBytes + offset, baseImage->size() - offset);

    // write gainmap
    offset = 0;
    const uint8_t* gainmapBytes = reinterpret_cast<const uint8_t*>(gainmapImage->data());
    output.write(gainmapBytes, JPEG_MARKER_TAG_SIZE);
    output.write(gainmapISOMetadataPack.data(), gainmapISOMetadataPack.size());
    output.write(gainmapMetadataPack.data(), gainmapMetadataPack.size());
    output.write(gainmapBytes + offset, gainmapImage->size() - offset);
    return SUCCESS;
}
}
}