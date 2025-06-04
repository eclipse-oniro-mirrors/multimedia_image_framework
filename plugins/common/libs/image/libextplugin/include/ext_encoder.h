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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H

#include <vector>

#include "abs_image_encoder.h"
#include "plugin_class_base.h"
#include "include/core/SkStream.h"
#include "ext_wstream.h"
#include "include/core/SkBitmap.h"
#ifdef USE_M133_SKIA
#include "include/codec/SkEncodedImageFormat.h"
#else
#include "include/core/SkEncodedImageFormat.h"
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif
#include "hdr_type.h"

#ifdef HEIF_HW_ENCODE_ENABLE
namespace OHOS::HDI::Codec::Image::V2_0 {
    struct ImageItem;
    struct SharedBuffer;
    struct ColourInfo;
    struct ContentLightLevel;
    struct MasteringDisplayColourVolume;
    struct ToneMapMetadata;
    struct MetaItem;
    struct ItemRef;
    struct ToneMapMetadata;
    struct ToneMapChannel;
}
#endif

namespace OHOS::Media {
    class AbsMemory;
}

namespace OHOS {
namespace ImagePlugin {
class ExtEncoder : public AbsImageEncoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    ExtEncoder();
    ~ExtEncoder() override;
    uint32_t StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option) override;
    uint32_t AddImage(Media::PixelMap &pixelMap) override;
    uint32_t AddPicture(Media::Picture &picture) override;
    uint32_t FinalizeEncode() override;

private:
    DISALLOW_COPY_AND_MOVE(ExtEncoder);
    static bool IsHardwareEncodeSupported(const PlEncodeOptions &opts, Media::PixelMap* pixelMap);
    bool IsPictureSupportHardwareEncode();
    uint32_t TryHardwareEncodePicture(SkWStream& skStream, std::string& errorMsg);
    uint32_t DoHardWareEncode(SkWStream* skStream);
    bool HardwareEncode(SkWStream &skStream, bool needExif);
#ifdef USE_M133_SKIA
    bool SkEncodeImage(SkWStream* dst, const SkBitmap& src, SkEncodedImageFormat format, int quality);
#endif
    uint32_t DoEncode(SkWStream* skStream, const SkBitmap& src, const SkEncodedImageFormat& skFormat);
    uint32_t DoHdrEncode(ExtWStream& wStream);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    sptr<SurfaceBuffer> ConvertToSurfaceBuffer(Media::PixelMap* pixelmap);
    uint32_t EncodeSdrImage(ExtWStream& outputStream);
    uint32_t EncodeDualVivid(ExtWStream& outputStream);
    uint32_t EncodeSingleVivid(ExtWStream& outputStream);
    uint32_t EncodePicture();
    uint32_t EncodeCameraScenePicture(SkWStream& skStream);
    uint32_t EncodeEditScenePicture();
    void CheckJpegAuxiliaryTagName();
    uint32_t EncodeJpegPicture(SkWStream& skStream);
    uint32_t EncodeJpegPictureDualVividInner(SkWStream& skStream, std::shared_ptr<PixelMap>& mainPixelmap,
        std::shared_ptr<PixelMap>& gainmapPixelmap);
    uint32_t EncodeJpegPictureDualVivid(SkWStream& skStream);
    uint32_t EncodeJpegPictureSdr(SkWStream& skStream);
    void EncodeJpegAuxiliaryPictures(SkWStream& skStream);
    uint32_t WriteJpegCodedData(std::shared_ptr<AuxiliaryPicture>& auxPicture, SkWStream& skStream);
    uint32_t SpliceFragmentStream(SkWStream& skStream, sk_sp<SkData>& skData);
    uint32_t WriteJpegUncodedData(std::shared_ptr<AuxiliaryPicture>& auxPicture, SkWStream& skStream);
    void WriteJpegAuxiliarySizeAndTag(uint32_t size, std::shared_ptr<AuxiliaryPicture>& auxPicture,
        SkWStream& skStream);
    uint32_t EncodeHeifPicture(sptr<SurfaceBuffer>& mainSptr, SkImageInfo mainInfo, bool sdrIsSRGB);
    sk_sp<SkData> GetImageEncodeData(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info, bool needExif);
    uint32_t EncodeImageBySurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info,
        bool needExif, SkWStream& outputStream);
    uint32_t EncodeHeifDualHdrImage(sptr<SurfaceBuffer>& sdr, sptr<SurfaceBuffer>& gainmap,
        Media::HdrMetadata& metadata, bool sdrIsSRGB = false);
    uint32_t EncodeHeifSdrImage(sptr<SurfaceBuffer>& sdr, SkImageInfo sdrInfo);
    void SetHdrColorSpaceType(sptr<SurfaceBuffer>& surfaceBuffer);
#endif
    uint32_t EncodeImageByBitmap(SkBitmap& bitmap, bool needExif, SkWStream& outStream);
    uint32_t EncodeImageByPixelMap(Media::PixelMap* pixelMap, bool needExif, SkWStream& outputStream);
#ifdef HEIF_HW_ENCODE_ENABLE
    std::shared_ptr<HDI::Codec::Image::V2_0::ImageItem> AssembleTmapImageItem(ColorManager::ColorSpaceName color,
        Media::HdrMetadata metadata, const PlEncodeOptions &opts);
    std::shared_ptr<Media::AbsMemory> AllocateNewSharedMem(size_t memorySize, std::string tag);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::shared_ptr<HDI::Codec::Image::V2_0::ImageItem> AssemblePrimaryImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
        const PlEncodeOptions &opts);
    std::shared_ptr<HDI::Codec::Image::V2_0::ImageItem> AssembleHdrBaseImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
        ColorManager::ColorSpaceName color, Media::HdrMetadata& metadata, const PlEncodeOptions &opts);
    std::shared_ptr<HDI::Codec::Image::V2_0::ImageItem> AssembleGainmapImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
        ColorManager::ColorSpaceName color, const PlEncodeOptions& opts);

    uint32_t AssembleSdrImageItem(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo sdrInfo,
        std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs);
    uint32_t AssembleHeifHdrPicture(
        sptr<SurfaceBuffer>& mainSptr, bool sdrIsSRGB, std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs);
    uint32_t AssembleHeifAuxiliaryNoncodingMap(std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs,
        AuxiliaryPictureType auxType);
    uint32_t AssembleHeifUnrefocusMap(std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs);
    uint32_t AssembleHeifFragmentMap(std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs);
    uint32_t AssembleHeifAuxiliaryPicture(std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs,
        std::vector<HDI::Codec::Image::V2_0::ItemRef>& refs);
    HDI::Codec::Image::V2_0::ImageItem InitAuxiliaryImageItem(uint32_t id, std::string itemName);
#endif
    bool GetStaticMetadata(Media::HdrMetadata& metadata, HDI::Codec::Image::V2_0::MasteringDisplayColourVolume& color,
        HDI::Codec::Image::V2_0::ContentLightLevel& light);
    bool GetToneMapChannel(Media::ISOMetadata& metadata, HDI::Codec::Image::V2_0::ToneMapChannel& channel,
        uint8_t index);
    bool GetToneMapMetadata(Media::HdrMetadata& metadata, HDI::Codec::Image::V2_0::ToneMapMetadata& toneMapMetadata);
    void GetColourInfo(ColorManager::ColorSpaceName color, HDI::Codec::Image::V2_0::ColourInfo& info);
    bool AssembleIT35SharedBuffer(Media::HdrMetadata metadata, HDI::Codec::Image::V2_0::SharedBuffer& outBuffer);
    bool AssembleICCImageProperty(sk_sp<SkData>& iccProfile, HDI::Codec::Image::V2_0::SharedBuffer& outBuffer);
    bool FillPixelSharedBuffer(sptr<SurfaceBuffer> sbBuffer, uint32_t capacity,
        HDI::Codec::Image::V2_0::SharedBuffer& outBuffer);
    bool FillNclxColorProperty(std::shared_ptr<HDI::Codec::Image::V2_0::ImageItem>& item, size_t& offset,
        HDI::Codec::Image::V2_0::ColourInfo& colorInfo);
    bool AssembleOutputSharedBuffer(HDI::Codec::Image::V2_0::SharedBuffer& outBuffer,
        std::shared_ptr<Media::AbsMemory>& outMem);
    void AssembleDualHdrRefItem(std::vector<HDI::Codec::Image::V2_0::ItemRef>& refs);
    uint32_t DoHeifEncode(std::vector<HDI::Codec::Image::V2_0::ImageItem>& inputImgs,
        std::vector<HDI::Codec::Image::V2_0::MetaItem>& inputMetas,
        std::vector<HDI::Codec::Image::V2_0::ItemRef>& refs);
    bool AssembleExifMetaItem(std::vector<HDI::Codec::Image::V2_0::MetaItem>& metaItems);
    void AssembleExifRefItem(std::vector<HDI::Codec::Image::V2_0::ItemRef>& refs);
    void AssembleAuxiliaryRefItem(AuxiliaryPictureType type, std::vector<HDI::Codec::Image::V2_0::ItemRef>& refs);
#endif
    uint32_t PixelmapEncode(ExtWStream& wStream);
    uint32_t EncodeHeifByPixelmap(Media::PixelMap* pixelmap, const PlEncodeOptions& opts);
    void RecycleResources();

    SkEncodedImageFormat encodeFormat_;
    OutputDataStream* output_ = nullptr;
    PlEncodeOptions opts_;
    Media::PixelMap* pixelmap_ = nullptr;
    Media::Picture* picture_ = nullptr;
    std::vector<std::shared_ptr<Media::AbsMemory>> tmpMemoryList_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H
