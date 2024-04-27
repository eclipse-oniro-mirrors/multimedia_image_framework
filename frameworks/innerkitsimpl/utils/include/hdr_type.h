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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HDR_TYPE_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HDR_TYPE_H
#include <vector>
namespace OHOS {
namespace Media {
enum class ImageHdrType : int32_t {
    UNKNOWN,
    SDR,
    HDR_ISO_DUAL,
    HDR_CUVA,
    HDR_VIVID_DUAL,
    HDR_VIVID_SINGLE
};

typedef struct ISOMetadata {
    unsigned short writeVersion;
    unsigned short miniVersion;
    unsigned char gainmapChannelNum;
    unsigned char useBaseColorFlag;
    float baseHeadroom;
    float alternateHeadroom;
    float enhanceClippedThreholdMaxGainmap[3];
    float enhanceClippedThreholdMinGainmap[3];
    float enhanceMappingGamma[3];
    float enhanceMappingBaselineOffset[3];
    float enhanceMappingAlternateOffset[3];
} ISOMetadata;

typedef struct GainmapColorMetadata {
    unsigned char enhanceDataColorPrimary;
    unsigned char enhanceDataTransFunction;
    unsigned char enhanceDataColorModel;

    unsigned char combineColorPrimary;
    unsigned char combineTransFunction;
    unsigned char combineColorModel;

    unsigned char alternateColorPrimary;
    unsigned char alternateTransFunction;
    unsigned char alternateColorModel;

    unsigned short enhanceICCSize;
    std::vector<unsigned char> enhanceICC;

    unsigned char combineMappingFlag;
    unsigned short combineMappingSize;
    unsigned char combineMappingMatrix[9];
    std::vector<unsigned char> combineMapping;
} GainmapColorMetadata;

typedef struct BaseColorMetadata {
    unsigned char baseColorPrimary;
    unsigned char baseTransFunction;
    unsigned char baseColorModel;

    unsigned short baseIccSize;
    std::vector<unsigned char> baseICC;

    unsigned char baseMappingFlag;
    unsigned short baseMappingSize;
    unsigned char baseMappingMatrix[9];
    std::vector<unsigned char> baseMapping;
} BaseColorMetadata;

typedef struct HDRVividExtendMetadata {
    ISOMetadata metaISO;
    GainmapColorMetadata gainmapColorMeta;
    BaseColorMetadata baseColorMeta;
} HDRVividExtendMetadata;

struct HdrMetadata {
    std::vector<uint8_t> staticMetadata;
    std::vector<uint8_t> dynamicMetadata;
    bool extendMetaFlag = false;
    HDRVividExtendMetadata extendMeta;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HDR_TYPE_H