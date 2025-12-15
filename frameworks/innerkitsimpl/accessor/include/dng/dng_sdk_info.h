/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_SDK_INFO_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_SDK_INFO_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include "dng_info.h"
#include "dng_tag_codes.h"
#include "image_type.h"

namespace OHOS {
namespace Media {
class DngSdkInfo : public dng_info {
public:
    using TagName = std::string;
    using TagCode = uint16_t;
    using ParentCode = uint32_t;
    using UniqueTagKey = std::pair<ParentCode, TagCode>;

    using ExifGetType = std::function<uint32_t(const dng_exif& fExif, MetadataValue& value)>;
    using ExifSetType = std::function<uint32_t(dng_exif& fExif, const MetadataValue& value)>;

    using SharedGetType = std::function<uint32_t(const dng_shared& fShared, MetadataValue& value)>;
    using SharedSetType = std::function<uint32_t(dng_shared& fShared, const MetadataValue& value)>;

    using IfdGetType = std::function<uint32_t(const dng_ifd& fIFD, MetadataValue& value)>;
    using IfdSetType = std::function<uint32_t(dng_ifd& fIFD, const MetadataValue& value)>;

    using ParseTagType =
        std::function<uint32_t(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)>;

    void ParseTag(dng_host& host, dng_stream& stream, dng_exif* exif, dng_shared* shared, dng_ifd* ifd,
        uint32 parentCode, uint32 tagCode, uint32 tagType, uint32 tagCount, uint64 tagOffset, int64 offsetDelta)
        override;
    uint32_t GetProperty(MetadataValue& value, const DngPropertyOption& option);
    uint32_t SetProperty(const MetadataValue& value, const DngPropertyOption& option);
    uint32_t RemoveProperty(const std::string& key, const DngPropertyOption& option);

    static std::set<std::string> GetAllPropertyKeys();

    // Parse special tag that have not been parsed or value have been changed in dng_sdk
    static uint32_t ParseAsciiTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseShortTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseShortTagToString(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseLongTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseRationalTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseUndefinedTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseIntTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);
    static uint32_t ParseDoubleTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value);

    // Get value from dng_exif
    static uint32_t GetExifImageDescription(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSVersionID(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSLatitudeRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSLatitude(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSLongitudeRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSLongitude(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSAltitudeRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSAltitude(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSTimeStamp(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSSatellites(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSStatus(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSMeasureMode(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDOP(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSSpeedRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSSpeed(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSTrackRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSTrack(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSImgDirectionRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSImgDirection(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSMapDatum(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestLatitudeRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestLatitude(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestLongitudeRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestLongitude(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestBearingRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestBearing(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestDistanceRef(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDestDistance(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSProcessingMethod(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSAreaInformation(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDateStamp(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSDifferential(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGPSHPositioningError(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifMake(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifModel(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSoftware(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifDateTime(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifArtist(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifCopyright(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFNumber(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifExposureProgram(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifISOSpeedRatings(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifExifVersion(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSensitivityType(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifStandardOutputSensitivity(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifRecommendedExposureIndex(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifISOSpeedLatitudeyyy(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifISOSpeedLatitudezzz(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifDateTimeOriginal(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifDateTimeDigitized(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifComponentsConfiguration(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifCompressedBitsPerPixel(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifBrightnessValue(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifExposureBiasValue(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifMeteringMode(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifLightSource(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFlash(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFocalLength(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifUserComment(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSubsecTimeOriginal(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSubsecTimeDigitized(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFlashPixVersion(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifColorSpace(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifPixelXDimension(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifPixelYDimension(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFocalPlaneXResolution(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFocalPlaneYResolution(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFocalPlaneResolutionUnit(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifExposureIndex(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSensingMethod(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFileSource(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSceneType(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifCustomRendered(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifExposureMode(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifWhiteBalance(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifDigitalZoomRatio(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifFocalLengthIn35mmFilm(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSceneCaptureType(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGainControl(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifContrast(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSaturation(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSharpness(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifSubjectDistanceRange(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifImageUniqueID(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifCameraOwnerName(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifCameraSerialNumber(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifLensSpecification(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifLensMake(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifLensModel(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifLensSerialNumber(const dng_exif& fExif, MetadataValue& value);
    static uint32_t GetExifGamma(const dng_exif& fExif, MetadataValue& value);

    // Get value from dng_shared
    static uint32_t GetSharedDNGVersion(const dng_shared& fShared, MetadataValue& value);

    // Get value from dng_ifd
    static uint32_t GetIfdNewSubfileType(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdImageWidth(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdImageLength(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdBitsPerSample(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdCompression(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdPhotometricInterpretation(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdOrientation(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdSamplesPerPixel(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdRowsPerStrip(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdStripByteCounts(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdXResolution(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdYResolution(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdPlanarConfiguration(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdResolutionUnit(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdYCbCrCoefficients(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdYCbCrSubSampling(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdYCbCrPositioning(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdReferenceBlackWhite(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdDefaultCropSize(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdJPEGInterchangeFormat(const dng_ifd& fIFD, MetadataValue& value);
    static uint32_t GetIfdJPEGInterchangeFormatLength(const dng_ifd& fIFD, MetadataValue& value);

private:
    static uint32_t GetOrSetExifProperty(dng_exif& fExif, MetadataValue& value, UniqueTagKey& tagKey, bool isGet);
    static uint32_t GetOrSetSharedProperty(dng_shared& fShared, MetadataValue& value,
        UniqueTagKey& tagKey, bool isGet);
    static uint32_t GetOrSetIfdProperty(dng_ifd& fIFD, MetadataValue& value, UniqueTagKey& tagKey, bool isGet);

    bool SaveParsedTag(const UniqueTagKey& tagKey, uint16_t tagType, uint32_t tagCount, uint64_t tagOffset);
    void ProcessSpecialTag(const UniqueTagKey& tagKey, dng_stream& stream);
    uint32_t GetOrSetProperty(MetadataValue& value, const DngPropertyOption& option, UniqueTagKey& tagKey, bool isGet);
    uint32_t GetSpecialProperty(MetadataValue& value, const DngPropertyOption& option);
    bool IsParsedTag(const UniqueTagKey& tagKey);
    bool IsParsedParentCode(uint32_t parentCode);
    bool IsSpecialTagName(const std::string& tagName);
    UniqueTagKey GetSpecialUniqueTagKey(const std::string& tagName, const DngPropertyOption& option);

    // For Property Map
    static constexpr uint8_t TAG_CODE_INDEX = 0;
    static constexpr uint8_t PARENT_CODE_INDEX = 1;
    static constexpr uint8_t GET_FUNC_INDEX = 2;
    static constexpr uint8_t SET_FUNC_INDEX = 3;

    // Used to handle tags that have been parsed in dng_sdk
    static std::map<TagName, std::tuple<TagCode, ParentCode, ExifGetType>> exifPropertyMap_;
    static std::map<TagName, std::tuple<TagCode, ParentCode, SharedGetType>> sharedPropertyMap_;
    static std::map<TagName, std::tuple<TagCode, ParentCode, IfdGetType>> ifdPropertyMap_;

    // Used to handle tags that have not been parsed or value have been changed in dng_sdk
    static std::map<TagName, TagCode> specialTagNameMap_;
    static std::map<TagCode, ParseTagType> specialTagPraseMap_;

    std::set<ParentCode> parsedParentCode_;
    std::map<UniqueTagKey, DngTagRecord> parsedTagRecordMap_;
    std::map<UniqueTagKey, MetadataValue> parsedSpecialTagMap_;
    std::map<UniqueTagKey, DngUpdateTagItem> updateTagMap_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_SDK_INFO_H
