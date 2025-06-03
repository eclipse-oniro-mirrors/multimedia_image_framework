/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JPEG_HARDWARE_DECODER_H
#define JPEG_HARDWARE_DECODER_H

#include <cinttypes>
#include <chrono>
#include "v2_1/icodec_image.h"
#include "v1_0/include/idisplay_buffer.h"
#include "image/image_plugin_type.h"
#include "image/input_data_stream.h"
#include "include/codec/SkCodec.h"
#include "image_log.h"
#include "jpeglib.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "JPEGHWDECODER"

#ifdef __FILE_NAME__
#define FILENAME __FILE_NAME__
#else
#define FILENAME __FILE__
#endif

#define LOG_FMT "[%{public}s][%{public}s %{public}d] "
#define JPEG_HW_LOGE(x, ...) \
    IMAGE_LOGE(LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define JPEG_HW_LOGW(x, ...) \
    IMAGE_LOGW(LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define JPEG_HW_LOGI(x, ...) \
    IMAGE_LOGI(LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define JPEG_HW_LOGD(x, ...) \
    IMAGE_LOGD(LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define KILO_BYTE 1024
#define MAX_SIZE_USE_DMA_POOL 256     /* max size of jpeg bitstream to use DMA Pool */
#define BUFFER_UNIT_SIZE 32           /* Input buffer alignment size */
#define DMA_POOL_SIZE 1024            /* the size of DMA Pool is 1M */
#define DMA_POOL_WAIT_SECONDS 10      /* Destroy the DMA pool if it is not used for more than 10s */
#define DMA_POOL_QUERY_INTERVAL 5     /* Query the active time of the DMA pool every 5 seconds */

namespace OHOS {
namespace ImagePlugin {

class DmaPool {
public:
    DmaPool();
    ~DmaPool();
public:
    OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer buffer;
    BufferHandle *bufferHandle;
    std::pair<uint32_t, uint32_t> remainSpace; /* <remainSpace, start> */
    std::unordered_map<uint32_t, uint32_t> usedSpace; /* <end, size> */
    std::unordered_map<uint32_t, uint32_t> releaseSpace; /* <end, size> */
};
class JpegHardwareDecoder {
public:
    JpegHardwareDecoder();
    ~JpegHardwareDecoder();
    bool InitDecoder();
    bool IsHardwareDecodeSupported(const std::string& srcImgFormat, OHOS::Media::Size srcImgSize);
    uint32_t Decode(SkCodec *codec, ImagePlugin::InputDataStream *srcStream, OHOS::Media::Size srcImgSize,
                    uint32_t sampleSize, OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer& outputBuffer);
private:
    class LifeSpanTimer {
    public:
        explicit LifeSpanTimer(std::string desc);
        ~LifeSpanTimer();
    private:
        int64_t GetCurrentTimeInUs();
    private:
        int64_t startTimeInUs_;
        std::string desc_;
    };
private:
    bool AssembleComponentInfo(jpeg_decompress_struct* jpegCompressInfo);
    bool HuffmanTblTransform(JHUFF_TBL* huffTbl, OHOS::HDI::Codec::Image::V2_1::CodecJpegHuffTable& tbl);
    void AssembleHuffmanTable(jpeg_decompress_struct* jpegCompressInfo);
    void AssembleQuantizationTable(jpeg_decompress_struct* jpegCompressInfo);
    bool AssembleJpegImgHeader(jpeg_decompress_struct* jpegCompressInfo);
    bool CopySrcImgToDecodeInputBuffer(ImagePlugin::InputDataStream *srcStream);
    bool IsStandAloneJpegMarker(uint16_t marker);
    bool JumpOverCurrentJpegMarker(ImagePlugin::InputDataStream* srcStream,
                                   unsigned int& curPos, unsigned int totalLen, uint16_t marker);
    bool PrepareInputData(SkCodec *codec, ImagePlugin::InputDataStream *srcStream);
    bool DoDecode(OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer& outputBufferHandle);
    void RecycleAllocatedResource();
    static OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* GetBufferMgr();
    bool CheckInputColorFmt(SkCodec *codec);
    bool GetCompressedDataStart(ImagePlugin::InputDataStream* srcStream);
    bool CopySrcToInputBuff(ImagePlugin::InputDataStream* srcStream, BufferHandle* inputBufferHandle);
    bool TryDmaPoolInBuff(ImagePlugin::InputDataStream* srcStream);
    bool AllocDmaPool();
    bool AllocSpace();
    void UpdateSpaceInfo();
    bool PackingInputBufferHandle(BufferHandle* inputBufferHandle);
    bool TryNormalInBuff(ImagePlugin::InputDataStream* srcStream);
    bool RecycleSpace();
    void ReleaseSpace(uint32_t& offset, uint32_t& usedSize);
    uint16_t ReadTwoBytes(ImagePlugin::InputDataStream* srcStream, unsigned int pos, bool& flag)
    static void RunDmaPoolRecycle();
private:
    static constexpr char JPEG_FORMAT_DESC[] = "image/jpeg";
    static std::vector<OHOS::HDI::Codec::Image::V2_1::CodecImageCapability> capList_;
    static std::mutex capListMtx_;
    static std::pair<DmaPool*, std::chrono::steady_clock::time_point> dmaPool_;
    static std::mutex dmaPoolMtx_;
    OHOS::sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> hwDecoder_;
    OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* bufferMgr_;
    OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer inputBuffer_;
    OHOS::HDI::Codec::Image::V2_1::CodecJpegDecInfo decodeInfo_;
    uint32_t compressDataPos_;
    uint32_t compressDataSize_;
    bool useDmaPool_;
    uint32_t usedSizeInPool_;
    uint32_t usedOffsetInPool_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // JPEG_HARDWARE_DECODER_H