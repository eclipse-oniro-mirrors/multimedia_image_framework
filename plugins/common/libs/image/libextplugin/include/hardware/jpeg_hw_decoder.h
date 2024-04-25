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
#include "v1_0/icodec_image.h"
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

namespace OHOS {
namespace ImagePlugin {
class JpegHardwareDecoder {
public:
    JpegHardwareDecoder();
    ~JpegHardwareDecoder();

    bool IsHardwareDecodeSupported(const std::string& srcImgFormat, PlSize srcImgSize);
    uint32_t Decode(SkCodec *codec, ImagePlugin::InputDataStream *srcStream, PlSize srcImgSize, uint32_t sampleSize,
                    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer& outputBuffer);
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
    inline uint16_t CombineTwoBytes(const uint8_t* data, unsigned int pos)
    {
        static constexpr int BITS_OFFSET = 8;
        static constexpr unsigned int BYTE_OFFSET = 1;
        return static_cast<uint16_t>((data[pos] << BITS_OFFSET) + data[pos + BYTE_OFFSET]);
    }
    bool InitDecoder();
    bool AssembleComponentInfo(jpeg_decompress_struct* jpegCompressInfo);
    bool HuffmanTblTransform(JHUFF_TBL* huffTbl, OHOS::HDI::Codec::Image::V1_0::CodecJpegHuffTable& tbl);
    void AssembleHuffmanTable(jpeg_decompress_struct* jpegCompressInfo);
    void AssembleQuantizationTable(jpeg_decompress_struct* jpegCompressInfo);
    bool AssembleJpegImgHeader(jpeg_decompress_struct* jpegCompressInfo);
    bool CopySrcImgToDecodeInputBuffer(ImagePlugin::InputDataStream *srcStream);
    bool IsStandAloneJpegMarker(uint16_t marker);
    bool JumpOverCurrentJpegMarker(const uint8_t* data, unsigned int& curPos, unsigned int totalLen, uint16_t marker);
    bool GetCompressedDataStart();
    bool PrepareInputData(SkCodec *codec, ImagePlugin::InputDataStream *srcStream);
    bool DoDecode(OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer& outputBufferHandle);
    void RecycleAllocatedResource();
    static OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* GetBufferMgr();
private:
    static constexpr char JPEG_FORMAT_DESC[] = "image/jpeg";
    OHOS::sptr<OHOS::HDI::Codec::Image::V1_0::ICodecImage> hwDecoder_;
    OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* bufferMgr_;
    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer inputBuffer_;
    OHOS::HDI::Codec::Image::V1_0::CodecJpegDecInfo decodeInfo_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // JPEG_HARDWARE_DECODER_H