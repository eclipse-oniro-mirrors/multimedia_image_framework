/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_AVIF_DECODER_IMPL_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_AVIF_DECODER_IMPL_H

#include <array>
#include <memory>
#include <numeric>
#include <limits>
#include <unordered_set>
#include <map>
#include <unordered_map>

#include "HeifDecoder.h"
#include "heif_parser.h"
#include "heif_parser/box/item_property_av1c_box.h"
#include "image_type.h"
#include "pixel_convert_adapter.h"
#include "surface_buffer.h"

#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif

#ifdef AVIF_DECODE_ENABLE
#include "dav1d.h"
#include "data.h"
#endif

namespace OHOS {
    struct BufferRequestConfig;
}

namespace OHOS {
namespace ImagePlugin {
using Media::AllocatorType;
using Media::PixelFormat;

struct ConvertInfo {
    uint8_t *dstBuffer = nullptr;
    size_t dstBufferSize = 0;
    PixelFormat desiredPixelFormat = PixelFormat::UNKNOWN;
    size_t rowStride = 0;
};

#ifdef AVIF_DECODE_ENABLE
class Dav1dDecoder {
public:
    Dav1dDecoder() = default;
    ~Dav1dDecoder()
    {
        ClearPicMap();
        DeleteDecoder();
    }
    bool CreateDecoder();
    void DeleteDecoder();
    bool DecodeFrame(uint32_t index, const std::vector<uint8_t> &frameData);
    void ClearPicMap();
    std::shared_ptr<Dav1dPicture> GetOccurDecodeFrame(uint32_t index);
    bool ConvertWithFFmpeg(uint32_t index, ConvertInfo &info);
private:
    bool ConvertToRGB(SwsContext *ctx, Dav1dPicture &pic, ConvertInfo &info);

    std::unordered_map<uint32_t, std::shared_ptr<Dav1dPicture>> picMap_;
    Dav1dContext *ctx_ = nullptr;
    Dav1dSettings settings_;
};
#endif

class AvifDecoderImpl : public HeifDecoder {
public:
    AvifDecoderImpl() = default;
    ~AvifDecoderImpl() override = default;

    bool init(HeifStream *stream, HeifFrameInfo *frameInfo) override;
    bool getSequenceInfo(HeifFrameInfo *frameInfo, size_t *frameCount) override;
    bool setOutputColor(SkHeifColorFormat heifColor) override;
    bool decode(HeifFrameInfo *frameInfo = nullptr) override;
    bool decodeSequence(int frameIndex, HeifFrameInfo *frameInfo = nullptr) override;
    void setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context) override;
    bool getScanline(uint8_t *dst) override;
    size_t skipScanlines(int count) override;
    bool getImageInfo(HeifFrameInfo *frameInfo) override;
    bool decodeGainmap() override;
    void setGainmapDstBuffer(uint8_t *dstBuffer, size_t rowStride) override;
    bool getGainmapInfo(HeifFrameInfo *frameInfo) override;
    bool getTmapInfo(HeifFrameInfo *frameInfo) override;
    HeifImageHdrType getHdrType() override;
    void getVividMetadata(std::vector<uint8_t> &uwaInfo, std::vector<uint8_t> &displayInfo,
        std::vector<uint8_t> &lightInfo) override;
    void getISOMetadata(std::vector<uint8_t> &isoMetadata) override;
    void getErrMsg(std::string &errMsg) override;
    uint32_t getColorDepth() override;
    bool IsAvisImage();
    void SetAllocatorType(AllocatorType type)
    {
        allocatorType_ = type;
    }
    void SetDesiredPixelFormat(PixelFormat format)
    {
        desiredPixelFormat_ = format;
    }
    bool IsSupportedPixelFormat(bool isAnimation, PixelFormat format);
    AvifBitDepth GetAvifBitDepth(bool isAnimation);
    HeifPixelFormat GetAvifPixelFormat(bool isAnimation);
    void SetBufferSize(size_t dstBufferSize)
    {
        dstMemorySize_ = dstBufferSize;
    }
    uint32_t GetAvisDelayTime(uint32_t index, int32_t &value);
private:
    bool CopySrcMemory(HeifStream *stream, size_t &len);
    void InitFrameInfo(HeifFrameInfo *info, const std::shared_ptr<HeifImage> &image);
    void SetColorSpaceInfo(HeifFrameInfo *info, const std::shared_ptr<HeifImage> &image);
    uint32_t GetPixelBytes(HeifPixelFormat format);
#ifdef AVIF_DECODE_ENABLE
    bool DecodeFrame();
    bool DecodeMovieFrame(uint32_t index);
    std::vector<std::vector<uint32_t>> CalculateMiniGroup(uint32_t index, HeifsFrameGroup groupInfo);
    bool IsMemoryExceed(uint32_t groupNum);
    bool InitDecoder();
#endif

    std::unique_ptr<uint8_t[]> srcMemory_;
    std::shared_ptr<HeifParser> parser_;
    std::shared_ptr<HeifImage> primaryImage_;
    HeifFrameInfo primaryImageInfo_{};
    std::shared_ptr<HeifImage> animationImage_;
    HeifFrameInfo animationImageInfo_{};
    AllocatorType allocatorType_ = AllocatorType::DEFAULT;
    PixelFormat desiredPixelFormat_ = PixelFormat::UNKNOWN;
    size_t rowStride_ = 0;
    uint8_t *dstMemory_ = nullptr;
    size_t dstMemorySize_ = 0;

#ifdef AVIF_DECODE_ENABLE
    std::unique_ptr<Dav1dDecoder> decoder_;
#endif
};
} // namespace ImagePlugin
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

HeifDecoder* CreateAvifDecoderImpl(void);

#ifdef __cplusplus
}
#endif

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_AVIF_DECODER_IMPL_H
