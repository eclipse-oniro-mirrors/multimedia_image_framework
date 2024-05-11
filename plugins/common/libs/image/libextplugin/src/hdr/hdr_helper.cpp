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
#ifdef HEIF_HW_DECODE_ENABLE
#include "heif_impl/HeifDecoder.h"
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/hdr_static_metadata.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HdrHelper"

namespace OHOS {
namespace ImagePlugin {
using namespace std;
using namespace Media;
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
constexpr uint8_t VIVID_STATIC_METADATA_SIZE_IN_IMAGE = 28;
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

#ifdef HEIF_HW_DECODE_ENABLE
static const map<HeifImageHdrType, ImageHdrType> HEIF_HDR_TYPE_MAP = {
    { HeifImageHdrType::UNKNOWN, ImageHdrType::UNKNOWN},
    { HeifImageHdrType::VIVID_DUAL, ImageHdrType::HDR_VIVID_DUAL},
    { HeifImageHdrType::ISO_DUAL, ImageHdrType::HDR_ISO_DUAL},
};
#endif

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

static bool GetVividJpegGainMapOffset(vector<jpeg_marker_struct*>& markerList, vector<uint32_t> preOffsets,
    uint32_t& offset)
{
    if (markerList.size() == EMPTY_SIZE) {
        return false;
    }
    for (uint32_t i = 0; i < markerList.size(); i++) {
        jpeg_marker_struct* marker = markerList[i];
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
        uint32_t appCurOffset = preOffsets[i] + dataOffset + JPEG_MARKER_TAG_SIZE + JPEG_MARKER_LENGTH_SIZE;
        uint32_t originOffset = ImageUtils::BytesToUint32(data, dataOffset);
        offset = originOffset + appCurOffset;
        uint32_t relativeOffset = ImageUtils::BytesToUint32(data, dataOffset); // offset minus all app size
        IMAGE_LOGD("vivid base info originOffset=%{public}d, relativeOffset=%{public}d",
            originOffset, relativeOffset);
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
    vector<uint32_t> vividPreMarkerOffset;
    for (jpeg_marker_struct* marker = jpegCodec->decoderMgr()->dinfo()->marker_list; marker; marker = marker->next) {
        if (JPEG_MARKER_APP8 == marker->marker) {
            vividMarkerList.push_back(marker);
            vividPreMarkerOffset.push_back(allAppSize);
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
    if (GetVividJpegGainMapOffset(vividMarkerList, vividPreMarkerOffset, offset)) {
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

#ifdef HEIF_HW_DECODE_ENABLE
static ImageHdrType CheckHeifHdrType(HeifDecoder* decoder)
{
    if (decoder == nullptr) {
        return ImageHdrType::UNKNOWN;
    }
    HeifImageHdrType heifHdrType = decoder->getHdrType();
    auto findItem = std::find_if(HEIF_HDR_TYPE_MAP.begin(), HEIF_HDR_TYPE_MAP.end(),
        [heifHdrType](const map<HeifImageHdrType, ImageHdrType>::value_type item) {
        return item.first == heifHdrType;
    });
    if (findItem == HEIF_HDR_TYPE_MAP.end()) {
        return ImageHdrType::UNKNOWN;
    }
    return findItem->second;
}
#endif

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
#ifdef HEIF_HW_DECODE_ENABLE
            auto decoder = reinterpret_cast<HeifDecoder*>(codec->getHeifContext());
            if (decoder == nullptr) {
                break;
            }
            type = CheckHeifHdrType(decoder);
#endif
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
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
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
    staticMeta.smpte2086.maxLuminance = (float)ImageUtils::BytesToUint32(data, offset);
    staticMeta.smpte2086.minLuminance = (float)ImageUtils::BytesToUint32(data, offset) * SM_LUM_SCALE;
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

static void ConvertExtendInfoMain(ExtendInfoMain info, HDRVividExtendMetadata& metadata)
{
    metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] = info.gainMapMax[INDEX_ZERO];
    metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE] = info.gainMapMax[INDEX_ONE];
    metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO] = info.gainMapMax[INDEX_TWO];
    metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO] = info.gainMapMin[INDEX_ZERO];
    metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE] = info.gainMapMin[INDEX_ONE];
    metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO] = info.gainMapMin[INDEX_TWO];
    metadata.metaISO.enhanceMappingGamma[INDEX_ZERO] = info.gamma[INDEX_ZERO];
    metadata.metaISO.enhanceMappingGamma[INDEX_ONE] = info.gamma[INDEX_ONE];
    metadata.metaISO.enhanceMappingGamma[INDEX_TWO] = info.gamma[INDEX_TWO];
    metadata.metaISO.enhanceMappingBaselineOffset[INDEX_ZERO] = info.baseSdrImageOffset[INDEX_ZERO];
    metadata.metaISO.enhanceMappingBaselineOffset[INDEX_ONE] = info.baseSdrImageOffset[INDEX_ONE];
    metadata.metaISO.enhanceMappingBaselineOffset[INDEX_TWO] = info.baseSdrImageOffset[INDEX_TWO];
    metadata.metaISO.enhanceMappingAlternateOffset[INDEX_ZERO] = info.altHdrImageOffset[INDEX_ZERO];
    metadata.metaISO.enhanceMappingAlternateOffset[INDEX_ONE] = info.altHdrImageOffset[INDEX_ONE];
    metadata.metaISO.enhanceMappingAlternateOffset[INDEX_TWO] = info.altHdrImageOffset[INDEX_TWO];
    const float eps = 1e-5;
    if ((fabs(metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] -
            metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE]) < eps) &&
        (fabs(metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] -
            metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO]) < eps) &&
        (fabs(metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO] -
            metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE]) < eps) &&
        (fabs(metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO] -
            metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO]) < eps)) {
        metadata.metaISO.gainmapChannelNum = INDEX_ONE;
    }
}

static void ConvertExtendInfoExtention(ExtendInfoExtention ext, HDRVividExtendMetadata& metadata)
{
    metadata.baseColorMeta.baseColorPrimary = ext.baseColor.primary;
    metadata.baseColorMeta.baseTransFunction = ext.baseColor.transFunc;
    metadata.baseColorMeta.baseColorModel = ext.baseColor.model;
    metadata.gainmapColorMeta.enhanceDataColorPrimary = ext.enhanceDataColor.primary;
    metadata.gainmapColorMeta.enhanceDataTransFunction = ext.enhanceDataColor.transFunc;
    metadata.gainmapColorMeta.enhanceDataColorModel = ext.enhanceDataColor.model;
    metadata.gainmapColorMeta.combineColorPrimary = ext.combineColor.primary;
    metadata.gainmapColorMeta.combineTransFunction = ext.combineColor.transFunc;
    metadata.gainmapColorMeta.combineColorModel = ext.combineColor.model;
    metadata.gainmapColorMeta.alternateColorPrimary = ext.enhanceColor.primary;
    metadata.gainmapColorMeta.alternateTransFunction = ext.enhanceColor.transFunc;
    metadata.gainmapColorMeta.alternateColorModel = ext.enhanceColor.model;
    metadata.baseColorMeta.baseMappingFlag = ext.baseMapping.mappingFlag;
    metadata.baseColorMeta.baseMapping = ext.baseMapping.mapping;
    metadata.baseColorMeta.baseMappingSize = ext.baseMapping.mapping.size();
    metadata.gainmapColorMeta.combineMappingFlag = ext.combineMapping.mappingFlag;
    metadata.gainmapColorMeta.combineMapping = ext.combineMapping.mapping;
    metadata.gainmapColorMeta.combineMappingSize = ext.combineMapping.mapping.size();
    metadata.baseColorMeta.baseIccSize = EMPTY_SIZE;
    metadata.baseColorMeta.baseICC.resize(EMPTY_SIZE);
    metadata.gainmapColorMeta.enhanceICCSize = EMPTY_SIZE;
    metadata.gainmapColorMeta.enhanceICC.resize(EMPTY_SIZE);
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
        if (dynamicMetaSize > length - dataOffset) {
            return false;
        }
        metadata.dynamicMetadata.resize(dynamicMetaSize);
        if (memcpy_s(metadata.dynamicMetadata.data(), dynamicMetaSize, data + dataOffset, dynamicMetaSize) != 0) {
            IMAGE_LOGD("get vivid dynamic metadata failed");
            return false;
        }
        dataOffset += dynamicMetaSize;
    }
    return true;
}

static bool ParseVividJpegExtendInfo(uint8_t* data, uint32_t length, HDRVividExtendMetadata& metadata)
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

static bool ParseVividMetadata(uint8_t* data, uint32_t length, HdrMetadata& metadata)
{
    uint32_t dataOffset = 0;
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
        metadata.extendMetaFlag =
            ParseVividJpegExtendInfo(data + dataOffset, length - dataOffset, metadata.extendMeta);
        IMAGE_LOGD("vivid get extend info result = %{public}d", metadata.extendMetaFlag);
    } else {
        metadata.extendMetaFlag = false;
    }
    return getMetadata;
}

static bool GetVividJpegMetadata(jpeg_marker_struct* markerList, HdrMetadata& metadata)
{
    for (jpeg_marker_struct* marker = markerList; marker; marker = marker->next) {
        if (JPEG_MARKER_APP8 != marker->marker) {
            continue;
        }
        if (memcmp(marker->data, ITUT35_TAG, ITUT35_TAG_SIZE) != 0) {
            continue;
        }
        uint8_t* data = marker->data + ITUT35_TAG_SIZE;
        uint32_t length = marker->data_length - ITUT35_TAG_SIZE;
        return ParseVividMetadata(data, length, metadata);
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

static void ParseISOExtendInfoThreeCom(uint8_t* data, uint32_t& offset, uint8_t channelNum, ExtendInfoMain& info)
{
    ParseISOExtendInfoMain(data, offset, info, INDEX_ZERO);
    if (channelNum == THREE_COMPONENTS) {
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

static bool ParseISOMetadata(uint8_t* data, uint32_t length, HdrMetadata& metadata)
{
    uint32_t dataOffset = 0;
    if (length < ISO_GAINMAP_METADATA_PAYLOAD_MIN_SIZE) {
        return false;
    }
    metadata.extendMeta.metaISO.writeVersion = ImageUtils::BytesToUint32(data, dataOffset);
    metadata.extendMeta.metaISO.miniVersion = metadata.extendMeta.metaISO.writeVersion & 0xFF;
    if (metadata.extendMeta.metaISO.miniVersion != EMPTY_SIZE) {
        return false;
    }
    uint8_t flag = data[dataOffset++];
    metadata.extendMeta.metaISO.gainmapChannelNum = (flag & 0x01) * INDEX_TWO + INDEX_ONE;
    metadata.extendMeta.metaISO.useBaseColorFlag = (flag >> INDEX_ONE) & 0x01;

    uint32_t baseHeadroomNumerator = ImageUtils::BytesToUint32(data, dataOffset);
    uint32_t baseHeadroomDenominator = ImageUtils::BytesToUint32(data, dataOffset);
    uint32_t altHeadroomNumerator = ImageUtils::BytesToUint32(data, dataOffset);
    uint32_t altHeadroomDenominator = ImageUtils::BytesToUint32(data, dataOffset);

    if (baseHeadroomDenominator != EMPTY_SIZE) {
        metadata.extendMeta.metaISO.baseHeadroom = (float)baseHeadroomNumerator / (float)baseHeadroomDenominator;
    } else {
        metadata.extendMeta.metaISO.baseHeadroom = (float)EMPTY_SIZE;
    }
    if (altHeadroomDenominator != EMPTY_SIZE) {
        metadata.extendMeta.metaISO.alternateHeadroom = (float)altHeadroomNumerator / (float)altHeadroomDenominator;
    } else {
        metadata.extendMeta.metaISO.alternateHeadroom = (float)EMPTY_SIZE;
    }
    ExtendInfoMain infoMain{};
    ParseISOExtendInfoThreeCom(data, dataOffset, metadata.extendMeta.metaISO.gainmapChannelNum, infoMain);
    ConvertExtendInfoMain(infoMain, metadata.extendMeta);
    metadata.extendMetaFlag = true;
    return true;
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
        return ParseISOMetadata(data, length, metadata);
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
        case ImageHdrType::HDR_VIVID_DUAL: {
            bool res = GetVividJpegMetadata(markerList, metadata);
            if (res && !metadata.extendMetaFlag) {
                GetISOGainmapMetadata(markerList, metadata);
            }
            return res;
        }
        case ImageHdrType::HDR_CUVA:
            return GetCuvaGainMapMetadata(markerList, metadata.dynamicMetadata);
        case ImageHdrType::HDR_ISO_DUAL:
            return GetISOGainmapMetadata(markerList, metadata);
        default:
            return false;
    }
}

#ifdef HEIF_HW_DECODE_ENABLE
static vector<uint8_t> ParseHeifStaticMetadata(const vector<uint8_t>& displayInfo, const vector<uint8_t>& lightInfo)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return {};
#else
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata staticMetadata{};
    DisplayColourVolume displayColourVolume{};
    ContentLightLevelInfo lightLevelInfo{};
    if (!lightInfo.empty()) {
        if (memcpy_s(&lightLevelInfo, sizeof(ContentLightLevelInfo), lightInfo.data(), lightInfo.size()) != EOK) {
            return {};
        }
    }
    if (!displayInfo.empty()) {
        if (memcpy_s(&displayColourVolume, sizeof(DisplayColourVolume),
            displayInfo.data(), displayInfo.size()) != EOK) {
            return {};
        }
    }
    const float colorScale = 0.00002f;
    const float lumScale = 0.0001f;
    staticMetadata.smpte2086.displayPrimaryRed.x = colorScale * (float)displayColourVolume.red.x;
    staticMetadata.smpte2086.displayPrimaryRed.y = colorScale * (float)displayColourVolume.red.y;
    staticMetadata.smpte2086.displayPrimaryGreen.x = colorScale * (float)displayColourVolume.green.x;
    staticMetadata.smpte2086.displayPrimaryGreen.y = colorScale * (float)displayColourVolume.green.y;
    staticMetadata.smpte2086.displayPrimaryBlue.x = colorScale * (float)displayColourVolume.blue.x;
    staticMetadata.smpte2086.displayPrimaryBlue.y = colorScale * (float)displayColourVolume.blue.y;
    staticMetadata.smpte2086.whitePoint.x = colorScale * (float)displayColourVolume.whitePoint.x;
    staticMetadata.smpte2086.whitePoint.y = colorScale * (float)displayColourVolume.whitePoint.y;
    staticMetadata.smpte2086.maxLuminance = (float)displayColourVolume.luminanceMax;
    staticMetadata.smpte2086.minLuminance = lumScale * (float)displayColourVolume.luminanceMin;
    staticMetadata.cta861.maxContentLightLevel = (float)lightLevelInfo.maxContentLightLevel;
    staticMetadata.cta861.maxFrameAverageLightLevel = (float)lightLevelInfo.maxPicAverageLightLevel;
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    std::vector<uint8_t> staticMetadataVec(vecSize);
    if (memcpy_s(staticMetadataVec.data(), vecSize, &staticMetadata, vecSize) != EOK) {
        return {};
    }
    return staticMetadataVec;
#endif
}

static bool GetHeifMetadata(HeifDecoder* heifDecoder, ImageHdrType type, HdrMetadata& metadata)
{
    if (heifDecoder == nullptr) {
        return false;
    }
    if (type == ImageHdrType::HDR_VIVID_DUAL || type == ImageHdrType::HDR_VIVID_SINGLE) {
        vector<uint8_t> uwaInfo;
        vector<uint8_t> displayInfo;
        vector<uint8_t> lightInfo;
        heifDecoder->getVividMetadata(uwaInfo, displayInfo, lightInfo);
        if (uwaInfo.empty()) {
            return false;
        }
        metadata.staticMetadata = ParseHeifStaticMetadata(displayInfo, lightInfo);
        bool res = ParseVividMetadata(uwaInfo.data(), uwaInfo.size(), metadata);
        if (!res) {
            IMAGE_LOGI("get heif vivid metadata failed");
            return false;
        }
        if (!metadata.extendMetaFlag) {
            vector<uint8_t> isoMetadata;
            heifDecoder->getISOMetadata(isoMetadata);
            if (isoMetadata.empty()) {
                return res;
            }
            if (isoMetadata.size() > EMPTY_SIZE && isoMetadata[INDEX_ZERO] == EMPTY_SIZE) {
                ParseISOMetadata(isoMetadata.data() + INDEX_ONE, isoMetadata.size() - INDEX_ONE, metadata);
            }
        }
        return res;
    } else if (type == ImageHdrType::HDR_ISO_DUAL) {
        vector<uint8_t> isoMetadata;
        heifDecoder->getISOMetadata(isoMetadata);
        if (isoMetadata.empty()) {
            return false;
        }
        if (isoMetadata.size() > EMPTY_SIZE && isoMetadata[INDEX_ZERO] == EMPTY_SIZE) {
            return ParseISOMetadata(isoMetadata.data() + INDEX_ONE, isoMetadata.size() - INDEX_ONE, metadata);
        }
    }
    return false;
}
#endif

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
#ifdef HEIF_HW_DECODE_ENABLE
            auto decoder = reinterpret_cast<HeifDecoder*>(codec->getHeifContext());
            return GetHeifMetadata(decoder, type, metadata);
#else
            return false;
#endif
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

vector<uint8_t> HdrJpegPackerHelper::PackBaseVividMarker(uint32_t gainmapOffset, uint32_t preOffset, uint32_t appSize)
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
    uint32_t curOffset = index + preOffset;
    // set gainmap offset1 (gainmapOffset - current position offset)
    ImageUtils::Uint32ToBytes(gainmapOffset - curOffset, bytes, index);
    // set gainmap offset2 (gainmap size - app size)
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

static void PackExtendInfoMain(vector<uint8_t>& bytes, uint32_t& offset, HDRVividExtendMetadata& metadata)
{
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingGamma[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingBaselineOffset[INDEX_ZERO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingAlternateOffset[INDEX_ZERO], bytes, offset);

    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingGamma[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingBaselineOffset[INDEX_ONE], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingAlternateOffset[INDEX_ONE], bytes, offset);

    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingGamma[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingBaselineOffset[INDEX_TWO], bytes, offset);
    ImageUtils::FloatToBytes(metadata.metaISO.enhanceMappingAlternateOffset[INDEX_TWO], bytes, offset);
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

static void PackExtendInfoExtention(vector<uint8_t>& bytes, uint32_t& offset, HDRVividExtendMetadata& metadata)
{
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.baseColorMeta.baseColorPrimary;
    bytes[offset++] = metadata.baseColorMeta.baseTransFunction;
    bytes[offset++] = metadata.baseColorMeta.baseColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.gainmapColorMeta.enhanceDataColorPrimary;
    bytes[offset++] = metadata.gainmapColorMeta.enhanceDataTransFunction;
    bytes[offset++] = metadata.gainmapColorMeta.enhanceDataColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.gainmapColorMeta.alternateColorPrimary;
    bytes[offset++] = metadata.gainmapColorMeta.alternateTransFunction;
    bytes[offset++] = metadata.gainmapColorMeta.alternateColorModel;
    bytes[offset++] = COLOR_INFO_BYTES;
    bytes[offset++] = metadata.gainmapColorMeta.combineColorPrimary;
    bytes[offset++] = metadata.gainmapColorMeta.combineTransFunction;
    bytes[offset++] = metadata.gainmapColorMeta.combineColorModel;
    PackTransformInfo(bytes, offset, metadata.baseColorMeta.baseMappingFlag, metadata.baseColorMeta.baseMapping);
    PackTransformInfo(bytes, offset, metadata.gainmapColorMeta.combineMappingFlag,
        metadata.gainmapColorMeta.combineMapping);
}

static uint16_t GetExtendMetadataSize(bool vividExtendFlag, HDRVividExtendMetadata& metadata)
{
    if (!vividExtendFlag) {
        return EMPTY_SIZE;
    }
    const uint8_t colorInfoNum = 4;
    uint16_t extendInfoExtentionSize = (COLOR_INFO_BYTES + UINT8_BYTE_COUNT) * colorInfoNum +
        UINT16_BYTE_COUNT + UINT16_BYTE_COUNT; // "baseTransformInfoSize" count + "EnhanceTransformInfoSize" count
    if (metadata.baseColorMeta.baseMappingFlag > EMPTY_SIZE) {
        // "mapping" + "mapping" bytes
        extendInfoExtentionSize += metadata.baseColorMeta.baseMappingFlag + UINT8_BYTE_COUNT;
    }
    if (metadata.gainmapColorMeta.combineMappingFlag > EMPTY_SIZE) {
        extendInfoExtentionSize += metadata.gainmapColorMeta.combineMappingFlag + UINT8_BYTE_COUNT;
    }
    uint16_t extendSize = UINT8_BYTE_COUNT + EXTEND_INFO_MAIN_SIZE + extendInfoExtentionSize;
    return extendSize;
}

static void PackExtendMetadata(vector<uint8_t>& bytes, uint32_t& index, HDRVividExtendMetadata& metadata)
{
    uint16_t length = GetExtendMetadataSize(true, metadata);
    if (index + length > bytes.size()) {
        return;
    }
    ImageUtils::Uint16ToBytes(length, bytes, index);
    bytes[index++] = THREE_COMPONENTS;
    PackExtendInfoMain(bytes, index, metadata);
    PackExtendInfoExtention(bytes, index, metadata);
}

static bool PackVividStaticMetadata(vector<uint8_t>& bytes, uint32_t& index, vector<uint8_t>& staticVec)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
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
    ImageUtils::Uint32ToBytes((uint16_t)(staticMeta.smpte2086.maxLuminance), bytes, index);
    ImageUtils::Uint32ToBytes((uint16_t)(staticMeta.smpte2086.minLuminance / SM_LUM_SCALE), bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)staticMeta.cta861.maxContentLightLevel, bytes, index);
    ImageUtils::Uint16ToBytes((uint16_t)staticMeta.cta861.maxFrameAverageLightLevel, bytes, index);
    return true;
#endif
}

static bool PackVividMetadata(vector<uint8_t>& bytes, uint32_t& index, HdrMetadata& metadata)
{
    uint32_t dynamicMetadataSize = metadata.dynamicMetadata.size();
    const uint32_t metadataSize =
        UINT16_BYTE_COUNT + VIVID_STATIC_METADATA_SIZE_IN_IMAGE + UINT16_BYTE_COUNT + dynamicMetadataSize;
    PackVividPreInfo(bytes, index, false, false);
    ImageUtils::Uint16ToBytes(metadataSize, bytes, index);
    if (!PackVividStaticMetadata(bytes, index, metadata.staticMetadata)) {
        return false;
    }
    ImageUtils::Uint16ToBytes(dynamicMetadataSize, bytes, index);
    if (memcpy_s(bytes.data() + index, bytes.size() - index,
        metadata.dynamicMetadata.data(), metadata.dynamicMetadata.size()) != EOK) {
        return false;
    }
    index += metadata.dynamicMetadata.size();
    PackExtendMetadata(bytes, index, metadata.extendMeta);
    return true;
}

std::vector<uint8_t> HdrJpegPackerHelper::PackVividMetadataMarker(HdrMetadata& metadata)
{
    uint32_t dynamicMetadataSize = metadata.dynamicMetadata.size();
    // metadataSize + staticMetadataSize + staticMetadata + dynamicMetadataSize + dynamicMetadata
    const uint32_t metadataSize = UINT16_BYTE_COUNT + UINT16_BYTE_COUNT + VIVID_STATIC_METADATA_SIZE_IN_IMAGE +
        UINT16_BYTE_COUNT + dynamicMetadataSize;
    uint32_t extendInfoSize = GetExtendMetadataSize(false, metadata.extendMeta);
    uint32_t markerLength = UINT32_BYTE_COUNT + ITUT35_TAG_SIZE + VIVID_METADATA_PRE_INFO_SIZE +
        metadataSize;
    if (extendInfoSize != EMPTY_SIZE) {
        markerLength += (UINT16_BYTE_COUNT + extendInfoSize);
    }
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

static void PackISOExtendInfo(vector<uint8_t>& bytes, uint32_t& offset, ISOMetadata& metadata)
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
    HDRVividExtendMetadata extendMeta = metadata.extendMeta;
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
    ImageUtils::Uint32ToBytes(extendMeta.metaISO.writeVersion, bytes, index);
    bytes[index++] = (extendMeta.metaISO.useBaseColorFlag << INDEX_ONE) | (extendMeta.metaISO.gainmapChannelNum & 0x01);
    uint32_t baseHeadroomNumerator = EMPTY_SIZE;
    if (extendMeta.metaISO.baseHeadroom > (float)EMPTY_SIZE) {
        baseHeadroomNumerator = (uint32_t)(extendMeta.metaISO.baseHeadroom * DENOMINATOR);
    }
    uint32_t baseHeadroomDenominator = DENOMINATOR;
    ImageUtils::Uint32ToBytes(baseHeadroomNumerator, bytes, index);
    ImageUtils::Uint32ToBytes(baseHeadroomDenominator, bytes, index);
    uint32_t altHeadroomNumerator = EMPTY_SIZE;
    uint32_t altHeadroomDenominator = 0x01;
    if (extendMeta.metaISO.alternateHeadroom > (float)EMPTY_SIZE) {
        altHeadroomNumerator = (uint32_t)(extendMeta.metaISO.alternateHeadroom * DENOMINATOR);
        altHeadroomDenominator = DENOMINATOR;
    }
    ImageUtils::Uint32ToBytes(altHeadroomNumerator, bytes, index);
    ImageUtils::Uint32ToBytes(altHeadroomDenominator, bytes, index);
    PackISOExtendInfo(bytes, index, extendMeta.metaISO);
    return bytes;
}

static bool WriteJpegPreApp(sk_sp<SkData>& imageData, SkWStream& outputStream, uint32_t& index, uint32_t& jfifSize)
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
        if (imageBytes[index + INDEX_ONE] == JPEG_MARKER_APP0) {
            jfifSize = markerSize + JPEG_MARKER_TAG_SIZE;
        }
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
    uint32_t jfifSize = 0;
    if (!WriteJpegPreApp(baseImage, output, offset, jfifSize)) {
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
    uint32_t appWithoutJfif = allAppSize - jfifSize - JPEG_MARKER_TAG_SIZE;
    std::vector<uint8_t> baseVividInfo = PackBaseVividMarker(baseSize, offset, appWithoutJfif);
    std::vector<uint8_t> mpfInfo = PackBaseMpfMarker(baseSize, gainmapSize, offset + baseVividApp8Size);
    output.write(baseVividInfo.data(), baseVividInfo.size());
    output.write(mpfInfo.data(), mpfInfo.size());
    output.write(baseISOInfo.data(), baseISOInfo.size());
    const uint8_t* baseBytes = reinterpret_cast<const uint8_t*>(baseImage->data());
    output.write(baseBytes + offset, baseImage->size() - offset);

    // write gainmap
    const uint8_t* gainmapBytes = reinterpret_cast<const uint8_t*>(gainmapImage->data());
    output.write(gainmapBytes, JPEG_MARKER_TAG_SIZE);
    output.write(gainmapISOMetadataPack.data(), gainmapISOMetadataPack.size());
    output.write(gainmapMetadataPack.data(), gainmapMetadataPack.size());
    output.write(gainmapBytes + JPEG_MARKER_TAG_SIZE, gainmapImage->size() - JPEG_MARKER_TAG_SIZE);
    return SUCCESS;
}
}
}