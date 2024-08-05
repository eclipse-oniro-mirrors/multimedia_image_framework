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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_DECODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_DECODER_H

#include <cstdint>
#include <string>

#include "abs_image_decoder.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "display_type.h"
#include "hardware/jpeg_hw_decoder.h"
#endif
#include "ext_stream.h"
#include "exif_info.h"
#include "include/codec/SkCodec.h"
#include "nocopyable.h"
#include "plugin_class_base.h"
#include "jpeg_yuv_decoder/jpeg_decoder_yuv.h"

namespace OHOS {
namespace ImagePlugin {
class ExtDecoder : public AbsImageDecoder, public OHOS::MultimediaPlugin::PluginClassBase, NoCopyable {
public:
    ExtDecoder();
    ~ExtDecoder() override;
    bool HasProperty(std::string key) override;
    uint32_t Decode(uint32_t index, DecodeContext &context) override;
    uint32_t DecodeToYuv420(uint32_t index, DecodeContext &context);
    #ifdef JPEG_HW_DECODE_ENABLE
    uint32_t AllocOutputBuffer(DecodeContext &context, OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer& outputBuffer);
    void ReleaseOutputBuffer(DecodeContext &context, Media::AllocatorType allocatorType);
    uint32_t HardWareDecode(DecodeContext &context);
    uint32_t DoHardWareDecode(DecodeContext &context);
    #endif
    uint32_t GifDecode(uint32_t index, DecodeContext &context, const uint64_t rowStride);
    uint32_t GetImageSize(uint32_t index, OHOS::Media::Size &size) override;
    uint32_t GetTopLevelImageNum(uint32_t &num) override;
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context) override;
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) override;
    void Reset() override;
    void SetSource(InputDataStream &sourceStream) override;

    uint32_t GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value) override;
    uint32_t GetImagePropertyString(uint32_t index, const std::string &key, std::string &value) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        const std::string &path) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        const int fd) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        uint8_t *data, uint32_t size) override;
    uint32_t GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges) override;
    Media::ImageHdrType CheckHdrType() override;
    uint32_t GetGainMapOffset() override;
    Media::HdrMetadata GetHdrMetadata(Media::ImageHdrType type) override;
    bool DecodeHeifGainMap(DecodeContext &context) override;
    bool GetHeifHdrColorSpace(ColorManager::ColorSpaceName &gainmap, ColorManager::ColorSpaceName &hdr) override;
    uint32_t GetHeifParseErr() override;
    bool DecodeHeifAuxiliaryMap(DecodeContext& context, Media::AuxiliaryPictureType type) override;
    bool CheckAuxiliaryMap(Media::AuxiliaryPictureType type) override;
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace getGrColorSpace() override;
    bool IsSupportICCProfile() override;
#endif

private:
    typedef struct FrameCacheInfo {
        int width;
        int height;
        uint64_t rowStride;
        uint64_t byteCount;
    } FrameCacheInfo;

    bool CheckCodec();
    bool CheckIndexValied(uint32_t index);
    bool DecodeHeader();
    bool IsSupportScaleOnDecode();
    bool GetScaledSize(int &dWidth, int &dHeight, float &scale);
    bool GetHardwareScaledSize(int &dWidth, int &dHeight, float &scale);
    bool IsSupportCropOnDecode();
    bool IsSupportCropOnDecode(SkIRect &target);
    bool IsSupportHardwareDecode();
    bool IsYuv420Format(OHOS::Media::PixelFormat format) const;
    bool IsHeifToYuvDecode(const DecodeContext &context) const;
    uint32_t DoHeifToYuvDecode(DecodeContext &context);
    bool ConvertInfoToAlphaType(SkAlphaType &alphaType, OHOS::Media::AlphaType &outputType);
    bool ConvertInfoToColorType(SkColorType &format, OHOS::Media::PixelFormat &outputFormat);
    bool GetPropertyCheck(uint32_t index, const std::string &key, uint32_t &res);
    SkAlphaType ConvertToAlphaType(OHOS::Media::AlphaType desiredType, OHOS::Media::AlphaType &outputType);
    uint32_t PreDecodeCheck(uint32_t index);
    uint32_t PreDecodeCheckYuv(uint32_t index, OHOS::Media::PixelFormat desiredFormat);
    uint32_t ReadJpegData(uint8_t* jpegBuffer, uint32_t jpegBufferSize);
    JpegYuvFmt GetJpegYuvOutFmt(OHOS::Media::PixelFormat desiredFormat);
    bool ResetCodec();
    SkColorType ConvertToColorType(OHOS::Media::PixelFormat format, OHOS::Media::PixelFormat &outputFormat);
    uint32_t SetContextPixelsBuffer(uint64_t byteCount, DecodeContext &context);
    uint32_t GetMakerImagePropertyString(const std::string &key, std::string &value);
    uint32_t CheckDecodeOptions(uint32_t index, const PixelDecodeOptions &opts);
    static void ReportImageType(SkEncodedImageFormat skEncodeFormat);
    bool CheckContext(const DecodeContext &context);
    uint32_t DmaMemAlloc(DecodeContext &context, uint64_t count, SkImageInfo &dstInfo);
    uint32_t HeifYUVMemAlloc(DecodeContext &context);
    void SetHeifDecodeError(DecodeContext &context);
    void SetHeifParseError();
    uint32_t ConvertFormatToYUV(DecodeContext &context, SkImageInfo &dstInfo,
        uint64_t byteCount, OHOS::Media::PixelFormat format);
    bool IsHeifToSingleHdrDecode(const DecodeContext &context) const;
    uint32_t DoHeifToSingleHdrDecode(OHOS::ImagePlugin::DecodeContext &context);
    uint32_t HandleGifCache(uint8_t* src, uint8_t* dst, uint64_t rowStride, int dstHeight);
    uint32_t GetFramePixels(SkImageInfo& info, uint8_t* buffer, uint64_t rowStride, SkCodec::Options options);
    FrameCacheInfo InitFrameCacheInfo(const uint64_t rowStride, SkImageInfo info);
    bool FrameCacheInfoIsEqual(FrameCacheInfo& src, FrameCacheInfo& dst);

    ImagePlugin::InputDataStream *stream_ = nullptr;
    uint32_t streamOff_ = 0;
    std::unique_ptr<SkCodec> codec_;
    SkImageInfo info_;
    SkImageInfo dstInfo_;
    SkCodec::Options dstOptions_;
    SkIRect dstSubset_;
    int32_t frameCount_ = 0;
    EXIFInfo exifInfo_;
    uint8_t *gifCache_ = nullptr;
    int gifCacheIndex_ = 0;
    FrameCacheInfo frameCacheInfo_ = {0, 0, 0, 0};
    uint32_t heifParseErr_ = 0;
#ifdef IMAGE_COLORSPACE_FLAG
    std::shared_ptr<OHOS::ColorManager::ColorSpace> dstColorSpace_ = nullptr;
#endif

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    // hardware
    SkImageInfo hwDstInfo_;
    OHOS::Media::Size orgImgSize_;
    OHOS::Media::Size outputBufferSize_;
    PixelFormat outputColorFmt_ = PIXEL_FMT_RGBA_8888;
    uint32_t sampleSize_ = 1;
    static constexpr uint32_t ALIGN_8 = 8;
    static constexpr uint32_t ALIGN_16 = 16;
#endif

    //Yuv
    OHOS::Media::Size desiredSizeYuv_;

    // hdr
    Media::ImageHdrType hdrType_ = Media::ImageHdrType::UNKNOWN;
    uint32_t gainMapOffset_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_DECODER_H
