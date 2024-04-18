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

typedef struct {
    float enhanceClippedThreholdMaxGainmap[3];
    float enhanceClippedThreholdMinGainmap[3];
    float enhanceMappingGamma[3];
    float enhanceMappingBaselineOffset[3];
    float enhanceMappingAlternateOffset[3];

    unsigned char baseColorPrimary;
    unsigned char baseTransFunction;
    unsigned char baseColorModel;
    unsigned char baseMappingFlag;
    unsigned short baseMappingSize;
    std::vector<unsigned char> baseMapping;
    unsigned short baseIccSize;
    std::vector<unsigned char> baseICC;

    unsigned char enhanceDataColorPrimary;
    unsigned char enhanceDataTransFunction;
    unsigned char enhanceDataColorModel;

    unsigned char combineColorPrimary;
    unsigned char combineTransFunction;
    unsigned char combineColorModel;

    unsigned char enhanceColorPrimary;
    unsigned char enhanceTransFunction;
    unsigned char enhanceColorModel;

    unsigned char combineMappingFlag;
    unsigned short combineMappingSize;
    std::vector<unsigned char> combineMapping;

    unsigned short enhanceICCSize;
    std::vector<unsigned char> enhanceICC;
} HDRVividGainmapMetadata;

struct HdrMetadata {
    std::vector<uint8_t> staticMetadata;
    std::vector<uint8_t> dynamicMetadata;
    bool gainmapMetadataFlag = false;
    HDRVividGainmapMetadata gainmapMetadata;
};

struct IsoMetadata {
    std::vector<double> gainMapMin;
    std::vector<double> gainMapMax;
    std::vector<double> gamma;
    std::vector<double> offsetSdr;
    std::vector<double> offsetHdr;
    double hdrCapacityMin;
    double hdrCapacityMax;
    bool baseIsHdr;
    int numberOfComponents;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HDR_TYPE_H