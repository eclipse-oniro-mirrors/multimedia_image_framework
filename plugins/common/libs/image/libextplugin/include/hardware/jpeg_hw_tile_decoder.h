/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef JPEG_HARDWARE_TILE_DECODER_H
#define JPEG_HARDWARE_TILE_DECODER_H

#include <memory>
#include <vector>

#include "ext_decoder.h"

namespace OHOS {
namespace ImagePlugin {
#define JPEGHWTILE_SCOPE_EXECUTE(code) \
    do {                               \
        code                           \
    } while (0)

struct HuffTables;

namespace JpegHwTile {
using std::vector;
using std::unique_ptr;
using BLOB = unique_ptr<uint8_t[]>;

struct JPG_DATA {
    BLOB                        streamData       {nullptr};
    size_t                      streamSize       {0};

    DecodeContext*              ctx              {nullptr};
    SkImageInfo                 ctxSizeInfo      {};

    uint32_t                    imageWidthPad16  {0};
    uint32_t                    imageHeightPad16 {0};
    size_t                      YPos             {0};
    size_t                      RiPos            {0};
    size_t                      ECSStartPos      {0};
    vector<size_t>              rstPositions     {};
    jpeg_decompress_struct*     dinfo            {nullptr};
    const ExtDecoder*           extDecoder       {nullptr};
    std::shared_ptr<HuffTables> tables           {nullptr};
};

struct RegionDecInfo {
    size_t maxOffset {0};  // used in non-aligned RST
    struct MCULineInfo {
        size_t startRstIdx {0};  // used in both aligned and non-aligned RST
        uint32_t mcuOffset {0};  // used in non-aligned RST
    };
    vector<MCULineInfo> entries {};
};

struct FullDecInfo {
    struct MCULineInfo {
        size_t   startRSTIdx {0};
        size_t   endRSTIdx   {0};
        uint32_t cropOffsetX {0};

        MCULineInfo() {}
        MCULineInfo(size_t startRSTIdx_, size_t endRSTIdx_, uint32_t cropOffsetX_)
            : startRSTIdx(startRSTIdx_), endRSTIdx(endRSTIdx_), cropOffsetX(cropOffsetX_) {}
    };
    vector<MCULineInfo> entries {};
};

struct SUBJPEG_DATA {
    RegionDecInfo     regionDecInfo {};
    FullDecInfo       fullDecInfo   {};
    uint8_t*          streamData    {nullptr};
    size_t            streamSize    {0};

    uint32_t          sampleSize    {1};

    DecodeContext     ctx           {};
    SkImageInfo       ctxSizeInfo   {};

    SkISize           origSize      {};
    SkIPoint          origLT        {};  // left top, only used in region decoding

    const ExtDecoder* extDecoder    {nullptr};

    ~SUBJPEG_DATA();
};

struct StreamBuffer {
    const uint8_t* dataHead {nullptr};
    uint32_t dataSize {0};
};

class UserBufferSourceStream {
public:
    static std::unique_ptr<UserBufferSourceStream>
    Create(uint8_t* data, uint32_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            IMAGE_LOGD("[BufferSourceStream]input the parameter exception.");
            return nullptr;
        }
        return std::make_unique<UserBufferSourceStream>(data, size, 0);
    }

    UserBufferSourceStream(uint8_t* data, uint32_t size, uint32_t offset)
        : dataHead(data), dataSize(size), dataOffset(offset) {}

    bool Read(uint32_t desiredSize, StreamBuffer& outData)
    {
        if (!Peek(desiredSize, outData)) {
            return false;
        }
        dataOffset += desiredSize;
        return true;
    }

    bool Peek(uint32_t desiredSize, StreamBuffer& outData)
    {
        if (dataOffset + desiredSize > dataSize) {
            IMAGE_LOGD("[UserBufferSourceStream] Peek out of bounds");
            return false;
        }
        outData.dataSize = desiredSize;
        outData.dataHead = dataHead + dataOffset;
        return true;
    }

    uint32_t Tell() { return dataOffset; }

    bool Seek(uint32_t position)
    {
        if (position > dataSize) {
            IMAGE_LOGE("[UserBufferSourceStream]Seek the position greater than the Data Size,position:%{public}u.",
                position);
            return false;
        }
        dataOffset = position;
        return true;
    }

    size_t GetStreamSize()
    {
        return dataSize;
    }

private:
    uint8_t* dataHead;
    size_t dataSize;
    size_t dataOffset;
};
} // namespace JpegHwTile

class RSTBasedDecoder {
public:
    RSTBasedDecoder() {}
    virtual bool IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder);
    virtual bool DoTileDecode() = 0;
protected:
    virtual bool Init();
    bool CheckResolution(uint32_t image_width, uint32_t image_height);
    bool IsBaselineDCT();
    bool ParseRSTs();
    bool ParseDHTs();
    bool DoHardWareDecode();
    uint32_t GetScaledValue(uint32_t val, Media::PixelFormat fmt);
    SkIPoint MapToScaledPoint(int32_t x, int32_t y, Media::PixelFormat fmt);
    SkISize  MapToScaledSize(int32_t origWidth, int32_t origHeight, Media::PixelFormat fmt);

    bool                                        isAligned {true};
    JpegHwTile::JPG_DATA                        jpg {};
    JpegHwTile::SUBJPEG_DATA                    subJpg {};
    JpegHwTile::unique_ptr<JpegHardwareDecoder> hwDecoder {nullptr};
};

class JpegHwRegionDecoder : public RSTBasedDecoder {
public:
    JpegHwRegionDecoder() {}
    bool IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder) override;
    bool DoTileDecode() override;
private:
    bool SplitRegion();
    bool CombineIntoJpeg();
    bool DecodeSubJpg();
    bool CropTarget();
    bool CombineIntoJpegAligned();
    bool CombineIntoJpegNonAligned();
};

class JpegHwFullDecoder : public RSTBasedDecoder {
public:
    JpegHwFullDecoder() {}
    bool IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder) override;
    bool DoTileDecode() override;
private:
    bool IsSupport16k();
    bool Init() override;
    bool ProcessLastECS();
    bool DecodeFull();
    bool AllocDMACtx();
    bool CreateSub(const SkIRect& subRegion);
    bool MergeRegion(const SkIRect& subregion);
    bool MergeRegionNV21(uint8_t* src, uint64_t srcStride, uint8_t* dst, uint64_t dstStride,
                         const SkIRect& subRegion);
    bool MergeRegionRGBA(uint8_t* src, uint64_t srcStride, uint8_t* dst, uint64_t dstStride,
                         const SkIRect& subRegion);
    uint32_t GetSampleSize(int32_t dwidth, int32_t dheight, int32_t origWidth, int32_t origHeight);

    JpegHwTile::BLOB subStreamForFull {nullptr};
};

} // namespace ImagePlugin
} // namespace OHOS

#endif // JPEG_HARDWARE_TILE_DECODER_H