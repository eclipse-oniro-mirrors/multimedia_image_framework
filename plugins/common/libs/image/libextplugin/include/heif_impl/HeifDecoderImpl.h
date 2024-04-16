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
#include "heif_parser.h"
#include "image_type.h"
#include "surface_buffer.h"

#ifdef HEIF_HW_DECODE_ENABLE
#include "hardware/heif_hw_decoder.h"
#endif

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

private:
    bool Reinit(HeifFrameInfo *frameInfo);

    void InitFrameInfo(HeifFrameInfo *frameInfo, const std::shared_ptr<HeifImage> &image);

    void GetTileSize(const std::shared_ptr<HeifImage> &image, uint32_t &tileWidth, uint32_t &tileHeight);

    void SetRowColNum();

    bool ProcessChunkHead(uint8_t *data, size_t len);

    bool DecodeGrids(sptr<SurfaceBuffer> &hwBuffer);

    bool DecodeSingleImage(std::shared_ptr<HeifImage> &image, sptr<SurfaceBuffer> &hwBuffer);

    bool ConvertHwBufferPixelFormat(sptr<SurfaceBuffer> &hwBuffer);

    bool IsDirectYUVDecode();

    std::shared_ptr<HeifParser> parser_;
    std::shared_ptr<HeifImage> primaryImage_;
    GraphicPixelFormat inPixelFormat_;
    Media::PixelFormat outPixelFormat_;
    HeifFrameInfo imageInfo_;

    uint32_t tileWidth_;
    uint32_t tileHeight_;
    uint32_t colNum_;
    uint32_t rowNum_;
    uint8_t *srcMemory_ = nullptr;
    uint8_t *dstMemory_;
    size_t dstRowStride_;
    SurfaceBuffer *dstHwBuffer_;

#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<HeifHardwareDecoder> hwDecoder_;
#endif
};
} // namespace ImagePlugin
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

HeifDecoder* CreateHeifDecoderImpl();

#ifdef __cplusplus
}
#endif

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_IMPL_H
