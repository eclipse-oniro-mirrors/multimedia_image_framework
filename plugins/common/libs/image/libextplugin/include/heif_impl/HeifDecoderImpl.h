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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_IMPL_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_IMPL_H

#include "HeifDecoder.h"

#ifdef HEIF_HW_DECODE_ENABLE
#include "heif_parser.h"
#include "hevc_sw_decode_param.h"
#include "image_type.h"
#include "surface_buffer.h"
#include "v2_1/icodec_image.h"

#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif

namespace OHOS::Media {
    class ImageFwkExtManager;
}

namespace OHOS {
namespace ImagePlugin {
class HeifDecoderImpl : public HeifDecoder {
public:
    HeifDecoderImpl();

    ~HeifDecoderImpl() override;

    bool init(HeifStream *stream, HeifFrameInfo *frameInfo) override;

    bool getSequenceInfo(HeifFrameInfo *frameInfo, size_t *frameCount) override;

    bool setOutputColor(SkHeifColorFormat heifColor) override;

    bool decode(HeifFrameInfo *frameInfo) override;

    bool decodeSequence(int frameIndex, HeifFrameInfo *frameInfo) override;

    void setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context) override;

    bool getScanline(uint8_t *dst) override;

    size_t skipScanlines(int count) override;

    bool getImageInfo(HeifFrameInfo *frameInfo) override;
    bool decodeGainmap() override;
    void setGainmapDstBuffer(uint8_t* dstBuffer, size_t rowStride) override {}
    bool getGainmapInfo(HeifFrameInfo* frameInfo) override;
    bool getTmapInfo(HeifFrameInfo* frameInfo) override;
    HeifImageHdrType getHdrType() override;
    void getVividMetadata(std::vector<uint8_t>& uwaInfo, std::vector<uint8_t>& displayInfo,
        std::vector<uint8_t>& lightInfo) override;
    void getISOMetadata(std::vector<uint8_t>& isoMetadata) override;
    void getErrMsg(std::string& errMsg) override;
    uint32_t getColorDepth() override;
    GridInfo GetGridInfo();
    bool CheckAuxiliaryMap(Media::AuxiliaryPictureType type);
    bool setAuxiliaryMap(Media::AuxiliaryPictureType type);
    bool getAuxiliaryMapInfo(HeifFrameInfo* frameInfo);
    bool decodeAuxiliaryMap();
    void setAuxiliaryDstBuffer(uint8_t* dstBuffer, size_t dstSize, size_t rowStride, void *context);
    void getFragmentMetadata(Media::Rect& fragmentMetadata);
    bool SwDecode(bool isSharedMemory = false);
    bool IsHeifGainmapYuv400();
    bool IsHeifAlphaYuv400();
    void SetSampleFormat(uint32_t sampleSize, ColorManager::ColorSpaceName colorSpaceName);
    int32_t GetPrimaryLumaBitNum();
    void setGainmapDstBuffer(uint8_t* dstBuffer, size_t rowStride, void *context);
private:
    bool Reinit(HeifFrameInfo *frameInfo);

    void InitFrameInfo(HeifFrameInfo *frameInfo, const std::shared_ptr<HeifImage> &image);

    void InitGridInfo(const std::shared_ptr<HeifImage> &image, GridInfo &gridInfo);

    void GetTileSize(const std::shared_ptr<HeifImage> &image, GridInfo &gridInfo);

    void GetRowColNum(GridInfo &gridInfo);

    GraphicPixelFormat GetInPixelFormat(const std::shared_ptr<HeifImage> &image);

    bool ProcessChunkHead(uint8_t *data, size_t len);

    bool copyToAshmem(std::vector<std::vector<uint8_t>> &inputs, std::vector<sptr<Ashmem>> &hwInputs);

    void SetHwDecodeInfo(GridInfo &gridInfo,
        OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo &heifDecodeInfo);

    GSError HwSetColorSpaceData(sptr<SurfaceBuffer> &buffer, GridInfo &gridInfo);

    bool HwDecodeImage(std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
        sptr<SurfaceBuffer> *outBuffer, bool isPrimary);

    void PreparePackedInput(std::vector<std::shared_ptr<HeifImage>> tileImages,
        std::vector<std::vector<uint8_t>> &packedInput, size_t gridCount);

    bool AllocateHwOutputBuffer(sptr<SurfaceBuffer> &hwBuffer, bool isPrimary);

    bool HwDecodeGrids(std::shared_ptr<HeifImage> &image,
        GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer);

    bool HwDecodeIdenImage(std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
        sptr<SurfaceBuffer> *outBuffer, bool isPrimary);

    bool HwDecodeSingleImage(std::shared_ptr<HeifImage> &image,
        GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer);

    bool HwDecodeMimeImage(std::shared_ptr<HeifImage> &image);

    bool SwDecodeImage(std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param,
                       GridInfo &gridInfo, bool isPrimary);
    bool SwDecodeAuxiliaryImage(std::shared_ptr<HeifImage> &gainmapImage,
                                GridInfo &gainmapGridInfo, sptr<SurfaceBuffer> *outputBuf);
    bool DoSwDecodeAuxiliaryImage(std::shared_ptr<HeifImage> &gainmapImage, GridInfo &gainmapGridInfo,
                                  sptr<SurfaceBuffer> &output, sptr<SurfaceBuffer> *outputBuf);

    bool SwDecodeGrids(Media::ImageFwkExtManager &extManager,
                       std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param);

    bool SwDecodeIdenImage(std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param,
                           GridInfo &gridInfo, bool isPrimary);

    bool SwDecodeSingleImage(Media::ImageFwkExtManager &extManager,
                             std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param);

    bool HwApplyAlphaImage(std::shared_ptr<HeifImage> &masterImage, uint8_t *dstMemory, size_t dstRowStride);

    bool SwApplyAlphaImage(std::shared_ptr<HeifImage> &masterImage, uint8_t *dstMemory, size_t dstRowStride);

    bool ConvertHwBufferPixelFormat(sptr<SurfaceBuffer> &hwBuffer, GridInfo &gridInfo,
                                    uint8_t *dstMemory, size_t dstRowStride, bool isPrimary);

    bool IsDirectYUVDecode();

    bool IsAuxiliaryDirectYUVDecode(std::shared_ptr<HeifImage> &auxiliaryImage);

    void SetColorSpaceInfo(HeifFrameInfo* info, const std::shared_ptr<HeifImage>& image);

    void GetGainmapColorSpace(ColorManager::ColorSpaceName &gainmapColor);

    void SetHardwareDecodeErrMsg(const uint32_t width, const uint32_t height);

    std::shared_ptr<HeifParser> parser_;
    std::shared_ptr<HeifImage> primaryImage_;
    Media::PixelFormat outPixelFormat_;
    Media::PixelFormat gainmapOutPixelFormat_ = Media::PixelFormat::RGBA_8888;
    HeifFrameInfo imageInfo_{};

    GridInfo gridInfo_ = {0, 0, false, 0, 0, 0, 0, 1};
    uint8_t *srcMemory_ = nullptr;
    uint8_t *dstMemory_;
    size_t dstRowStride_;
    SurfaceBuffer *dstHwBuffer_;

    std::shared_ptr<HeifImage> gainmapImage_ = nullptr;
    HeifFrameInfo gainmapImageInfo_{};
    uint8_t* gainmapDstMemory_;
    size_t gainmapDstRowStride_;

    std::shared_ptr<HeifImage> auxiliaryImage_ = nullptr;
    HeifFrameInfo auxiliaryImageInfo_{};
    GridInfo auxiliaryGridInfo_ = {0, 0, false, 0, 0, 0, 0, 1};
    uint8_t* auxiliaryDstMemory_;
    size_t auxiliaryDstRowStride_;
    size_t auxiliaryDstMemorySize_;
    bool isAuxiliaryDecode_ = false;
    bool isGainmapDecode_ = false;
    SurfaceBuffer *auxiliaryDstHwBuffer_;
    SurfaceBuffer *gainMapDstHwBuffer_;
    uint32_t sampleSize_ = 1;
    OHOS::ColorManager::ColorSpaceName colorSpaceName_ = ColorManager::ColorSpaceName::NONE;

    HeifFrameInfo tmapInfo_{};
    std::string errMsg_;

    GridInfo gainmapGridInfo_ = {0, 0, false, 0, 0, 0, 0, 1};
};
} // namespace ImagePlugin
} // namespace OHOS
#endif

#ifdef __cplusplus
extern "C" {
#endif

HeifDecoder* CreateHeifDecoderImpl(void);

#ifdef __cplusplus
}
#endif

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_IMPL_H
