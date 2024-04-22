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

#include "hardware/jpeg_hw_decoder.h"

#include <vector>
#include <algorithm>
#include <chrono>
#include <securec.h>

#include "hardware/jpeg_marker_define.h"
#include "hdf_base.h"
#include "iservmgr_hdi.h"
#include "media_errors.h"
#include "src/codec/SkJpegUtility.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "src/codec/SkJpegCodec.h"

namespace OHOS::ImagePlugin {
using namespace OHOS::HDI::Codec::Image::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::ServiceManager::V1_0;

static std::mutex g_codecMtx;
static sptr<ICodecImage> g_codecMgr;

class Listener : public ServStatListenerStub {
public:
    void OnReceive(const ServiceStatus &status) override
    {
        if (status.serviceName == "codec_image_service" && status.status == SERVIE_STATUS_STOP) {
            JPEG_HW_LOGW("codec_image_service died");
            std::lock_guard<std::mutex> lk(g_codecMtx);
            g_codecMgr = nullptr;
        }
    }
};

static sptr<ICodecImage> GetCodecManager()
{
    std::lock_guard<std::mutex> lk(g_codecMtx);
    if (g_codecMgr) {
        return g_codecMgr;
    }
    JPEG_HW_LOGI("need to get ICodecImage");
    sptr<IServiceManager> serviceMng = IServiceManager::Get();
    if (serviceMng) {
        serviceMng->RegisterServiceStatusListener(new Listener(), DEVICE_CLASS_DEFAULT);
    }
    g_codecMgr = ICodecImage::Get();
    return g_codecMgr;
}

JpegHardwareDecoder::LifeSpanTimer::LifeSpanTimer(std::string desc) : desc_(desc)
{
    startTimeInUs_ = GetCurrentTimeInUs();
}

JpegHardwareDecoder::LifeSpanTimer::~LifeSpanTimer()
{
    static constexpr float MILLISEC_TO_MICROSEC = 1000.0f;
    int64_t timeSpanInUs = GetCurrentTimeInUs() - startTimeInUs_;
    JPEG_HW_LOGI("%{public}s cost: %{public}.2f ms",
                 desc_.c_str(), static_cast<float>(timeSpanInUs / MILLISEC_TO_MICROSEC));
}

int64_t JpegHardwareDecoder::LifeSpanTimer::GetCurrentTimeInUs()
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

JpegHardwareDecoder::JpegHardwareDecoder()
{
    inputBuffer_.fenceFd = -1;
    hwDecoder_ = GetCodecManager();
    bufferMgr_ = GetBufferMgr();
}

JpegHardwareDecoder::~JpegHardwareDecoder()
{
    hwDecoder_ = nullptr;
    bufferMgr_ = nullptr;
}

bool JpegHardwareDecoder::IsHardwareDecodeSupported(const std::string& srcImgFormat, PlSize srcImgSize)
{
    if (hwDecoder_ == nullptr) {
        JPEG_HW_LOGE("failed to get hardware decoder!");
        return false;
    }
    if (srcImgFormat != JPEG_FORMAT_DESC) {
        JPEG_HW_LOGE("invalid image format: %{public}s", srcImgFormat.c_str());
        return false;
    }
    std::vector<CodecImageCapability> capList;
    auto ret = hwDecoder_->GetImageCapability(capList);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to get image capability, err=%{public}d!", ret);
        return false;
    }

    for (const CodecImageCapability& cap : capList) {
        JPEG_HW_LOGD("cap info: isSoftwareCodec=%{public}d, role=%{public}d, type=%{public}d, " \
                     "maxSize=[%{public}u*%{public}u], minSize=[%{public}u*%{public}u]",
                     cap.isSoftwareCodec, cap.role, cap.type, cap.maxWidth, cap.maxHeight,
                     cap.minWidth, cap.minHeight);
        if (!cap.isSoftwareCodec && cap.role == CODEC_IMAGE_JPEG && cap.type == CODEC_IMAGE_TYPE_DECODER &&
            srcImgSize.width >= cap.minWidth && srcImgSize.width <= cap.maxWidth &&
            srcImgSize.height >= cap.minHeight && srcImgSize.height <= cap.maxHeight) {
            JPEG_HW_LOGD("decoder(%{public}s) selected", cap.name.c_str());
            return true;
        }
    }
    JPEG_HW_LOGE("no available hardware decoder, img=[%{public}ux%{public}u]", srcImgSize.width, srcImgSize.height);
    return false;
}

uint32_t JpegHardwareDecoder::Decode(SkCodec *codec, ImagePlugin::InputDataStream *srcStream,
                                     PlSize srcImgSize, uint32_t sampleSize, CodecImageBuffer& outputBuffer)
{
    LifeSpanTimer decodeTimer("jpeg hardware decode");
    JPEG_HW_LOGD("jpeg hardware decode start: img=[%{public}ux%{public}u], sampleSize=%{public}u",
                 srcImgSize.width, srcImgSize.height, sampleSize);
    if (hwDecoder_ == nullptr || bufferMgr_ == nullptr) {
        JPEG_HW_LOGE("failed to get hardware decoder or failed to get buffer manager!");
        return Media::ERR_IMAGE_DECODE_ABNORMAL;
    }
    if (!IsHardwareDecodeSupported(JPEG_FORMAT_DESC, srcImgSize)) {
        return Media::ERR_IMAGE_DATA_UNSUPPORT;
    }
    decodeInfo_.sampleSize = sampleSize;
    bool ret = InitDecoder();
    ret = ret && PrepareInputData(codec, srcStream);
    ret = ret && DoDecode(outputBuffer);
    RecycleAllocatedResource();
    if (ret) {
        JPEG_HW_LOGI("jpeg hardware decode succeed");
        return Media::SUCCESS;
    }
    return Media::ERR_IMAGE_DECODE_FAILED;
}

bool JpegHardwareDecoder::AssembleComponentInfo(jpeg_decompress_struct* jpegCompressInfo)
{
    static constexpr int ONE_COMPONENT = 1;
    static constexpr int THREE_COMPONENTS = 3;
    if (jpegCompressInfo->num_components != ONE_COMPONENT &&
        jpegCompressInfo->num_components != THREE_COMPONENTS) {
        JPEG_HW_LOGE("unsupported component number: %{public}d!", jpegCompressInfo->num_components);
        return false;
    }
    decodeInfo_.numComponents = jpegCompressInfo->num_components;
    for (int i = 0; i < jpegCompressInfo->num_components; ++i) {
        decodeInfo_.compInfo.emplace_back(CodecJpegCompInfo {
            .componentId = jpegCompressInfo->comp_info[i].component_id,
            .componentIndex = jpegCompressInfo->comp_info[i].component_index,
            .hSampFactor = jpegCompressInfo->comp_info[i].h_samp_factor,
            .vSampFactor = jpegCompressInfo->comp_info[i].v_samp_factor,
            .quantTableNo = jpegCompressInfo->comp_info[i].quant_tbl_no,
            .dcTableNo = jpegCompressInfo->comp_info[i].dc_tbl_no,
            .acTableNo = jpegCompressInfo->comp_info[i].ac_tbl_no,
            .infoFlag = true
        });
    }
    return true;
}

bool JpegHardwareDecoder::HuffmanTblTransform(JHUFF_TBL* huffTbl, CodecJpegHuffTable& tbl)
{
    if (huffTbl == nullptr) {
        return false;
    }
    // length of bits is defined as 16 in jpeg specification
    // bits defined in struct JHUFF_TBL has length of 17, bits[0] is unused
    static constexpr int LIST_BITS_OFFSET = 1;
    static constexpr int LIST_BITS_LEN = 16;
    static constexpr int MAX_LIST_HUFFVAL_LEN = 256;
    int actualHuffValLen = 0;
    for (int i = LIST_BITS_OFFSET; i <= LIST_BITS_LEN; ++i) {
        actualHuffValLen += huffTbl->bits[i];
    }
    JPEG_HW_LOGD("actualHuffValLen=%{public}d", actualHuffValLen);
    if (actualHuffValLen > MAX_LIST_HUFFVAL_LEN) {
        JPEG_HW_LOGE("invalid huffVal len: %{public}d", actualHuffValLen);
        return false;
    }
    tbl.tableFlag = true;
    tbl.bits = std::vector<uint8_t>(&huffTbl->bits[LIST_BITS_OFFSET],
                                    &huffTbl->bits[LIST_BITS_OFFSET] + LIST_BITS_LEN);
    tbl.huffVal = std::vector<uint8_t>(huffTbl->huffval, &huffTbl->huffval[actualHuffValLen]);
    return true;
}

void JpegHardwareDecoder::AssembleHuffmanTable(jpeg_decompress_struct* jpegCompressInfo)
{
    static constexpr int HUFFMAN_TBL_CNT = 4;
    for (int i = 0; i < HUFFMAN_TBL_CNT; ++i) {
        CodecJpegHuffTable dcTbl;
        if (HuffmanTblTransform(jpegCompressInfo->dc_huff_tbl_ptrs[i], dcTbl)) {
            decodeInfo_.dcHuffTbl.emplace_back(dcTbl);
        }

        CodecJpegHuffTable acTbl;
        if (HuffmanTblTransform(jpegCompressInfo->ac_huff_tbl_ptrs[i], acTbl)) {
            decodeInfo_.acHuffTbl.emplace_back(acTbl);
        }
    }
}

void JpegHardwareDecoder::AssembleQuantizationTable(jpeg_decompress_struct* jpegCompressInfo)
{
    for (int i = 0; i < NUM_QUANT_TBLS; ++i) {
        if (jpegCompressInfo->quant_tbl_ptrs[i]) {
            uint16_t* quantStart = jpegCompressInfo->quant_tbl_ptrs[i]->quantval;
            decodeInfo_.quantTbl.emplace_back(CodecJpegQuantTable {
                .quantVal = std::vector<uint16_t>(quantStart, quantStart + DCTSIZE2),
                .tableFlag = true
            });
        } else {
            decodeInfo_.quantTbl.emplace_back(CodecJpegQuantTable {
                .quantVal = {},
                .tableFlag = false
            });
        }
    }
}

jpeg_decompress_struct* GetJpegCompressInfo(SkCodec *codec)
{
    if (codec == nullptr) {
        JPEG_HW_LOGE("invalid input codec!");
        return nullptr;
    }
    SkJpegCodec* jpegCodec = static_cast<SkJpegCodec*>(codec);
    if (jpegCodec == nullptr) {
        JPEG_HW_LOGE("invalid input jpeg codec!");
        return nullptr;
    }
    if (jpegCodec->decoderMgr() == nullptr) {
        JPEG_HW_LOGE("invalid input jpeg codec mgr!");
        return nullptr;
    }
    return jpegCodec->decoderMgr()->dinfo();
}

bool JpegHardwareDecoder::AssembleJpegImgHeader(jpeg_decompress_struct* jpegCompressInfo)
{
    decodeInfo_.imageWidth = jpegCompressInfo->image_width;
    decodeInfo_.imageHeight = jpegCompressInfo->image_height;
    decodeInfo_.dataPrecision = jpegCompressInfo->data_precision;
    decodeInfo_.restartInterval = jpegCompressInfo->restart_interval;
    decodeInfo_.arithCode = jpegCompressInfo->arith_code;
    decodeInfo_.progressiveMode = jpegCompressInfo->progressive_mode;
    // no crop as default
    decodeInfo_.region.flag = 0;
    if (!AssembleComponentInfo(jpegCompressInfo)) {
        return false;
    }
    AssembleHuffmanTable(jpegCompressInfo);
    AssembleQuantizationTable(jpegCompressInfo);
    return true;
}

bool JpegHardwareDecoder::CopySrcImgToDecodeInputBuffer(ImagePlugin::InputDataStream *srcStream)
{
    size_t fileSize = srcStream->GetStreamSize();
    uint32_t positionRecord = srcStream->Tell();
    JPEG_HW_LOGI("input stream, size=%{public}zu, curPos=%{public}u", fileSize, positionRecord);
    int32_t ret = hwDecoder_->AllocateInBuffer(inputBuffer_, static_cast<uint32_t>(fileSize), CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to allocate input buffer, err=%{public}d", ret);
        return false;
    }
    BufferHandle *inputBufferHandle = inputBuffer_.buffer->GetBufferHandle();
    if (inputBufferHandle == nullptr) {
        JPEG_HW_LOGE("inputBufferHandle is nullptr");
        return false;
    }
    bufferMgr_->Mmap(*inputBufferHandle);
    (void)bufferMgr_->InvalidateCache(*inputBufferHandle);
    srcStream->Seek(0);
    uint32_t readSize = 0;
    bool flag = srcStream->Read(static_cast<uint32_t>(fileSize), static_cast<uint8_t*>(inputBufferHandle->virAddr),
                                static_cast<uint32_t>(inputBufferHandle->size), readSize);
    (void)bufferMgr_->FlushCache(*inputBufferHandle);
    ret = bufferMgr_->Unmap(*inputBufferHandle);
    if (ret != 0) {
        JPEG_HW_LOGE("failed to unmap input buffer, err=%{public}d", ret);
    }
    srcStream->Seek(positionRecord);
    if (!flag || readSize != static_cast<uint32_t>(fileSize)) {
        JPEG_HW_LOGE("failed to read input data, readSize=%{public}u", readSize);
        return false;
    }
    return true;
}

bool JpegHardwareDecoder::IsStandAloneJpegMarker(uint16_t marker)
{
    auto iter = std::find(JpegMarker::STAND_ALONE_MARKER.begin(), JpegMarker::STAND_ALONE_MARKER.end(), marker);
    return (iter != JpegMarker::STAND_ALONE_MARKER.end());
}

bool JpegHardwareDecoder::JumpOverCurrentJpegMarker(const uint8_t* data, unsigned int& curPos,
                                                    unsigned int totalLen, uint16_t marker)
{
    curPos += JpegMarker::MARKER_LEN;
    if (curPos + JpegMarker::MARKER_LEN > totalLen) {
        JPEG_HW_LOGE("invalid pos(cur=%{public}u, total=%{public}u) after jump over marker(%{public}u)",
                     curPos, totalLen, marker);
        return false;
    }
    if (IsStandAloneJpegMarker(marker)) {
        return true;
    }
    // jump over related parameters for those who are not stand alone markers
    curPos += static_cast<unsigned int>(CombineTwoBytes(data, curPos));
    if (curPos > totalLen) {
        JPEG_HW_LOGE("invalid pos(cur=%{public}u, total=%{public}u) after jump over related parameters " \
                     "for marker(%{public}u)", curPos, totalLen, marker);
        return false;
    }
    return true;
}

bool JpegHardwareDecoder::GetCompressedDataStart()
{
    BufferHandle *inputBufferHandle = inputBuffer_.buffer->GetBufferHandle();
    bufferMgr_->Mmap(*inputBufferHandle);
    (void)bufferMgr_->InvalidateCache(*inputBufferHandle);
    const uint8_t* data = static_cast<const uint8_t*>(inputBufferHandle->virAddr);
    if (data == nullptr) {
        JPEG_HW_LOGE("map inputBufferHandle failed");
        return false;
    }
    unsigned int totalLen = static_cast<unsigned int>(inputBufferHandle->size);
    unsigned int curPos = 0;
    bool findFlag = false;
    while (curPos + JpegMarker::MARKER_LEN <= totalLen) {
        uint16_t potentialMarker = CombineTwoBytes(data, curPos);
        if (potentialMarker < JpegMarker::MIN_MARKER || potentialMarker > JpegMarker::MAX_MARKER) {
            ++curPos;
            continue;
        }
        if (!JumpOverCurrentJpegMarker(data, curPos, totalLen, potentialMarker)) {
            break;
        }
        if (potentialMarker == JpegMarker::SOS) {
            findFlag = true;
            decodeInfo_.compressPos = curPos;
            break;
        }
    }
    (void)bufferMgr_->FlushCache(*inputBufferHandle);
    int32_t ret = bufferMgr_->Unmap(*inputBufferHandle);
    if (ret != 0) {
        JPEG_HW_LOGE("failed to unmap input buffer, err=%{public}d", ret);
    }
    return findFlag;
}

bool JpegHardwareDecoder::PrepareInputData(SkCodec *codec, ImagePlugin::InputDataStream *srcStream)
{
    LifeSpanTimer decodeTimer("prepare input data");
    jpeg_decompress_struct* jpegCompressInfo = GetJpegCompressInfo(codec);
    if (jpegCompressInfo == nullptr || srcStream == nullptr) {
        JPEG_HW_LOGE("failed to get jpeg compress info or invalid input stream");
        return false;
    }
    bool ret = AssembleJpegImgHeader(jpegCompressInfo);
    ret = ret && CopySrcImgToDecodeInputBuffer(srcStream);
    ret = ret && GetCompressedDataStart();
    return ret;
}

bool JpegHardwareDecoder::InitDecoder()
{
    LifeSpanTimer decodeTimer("init decoder");
    int32_t ret = hwDecoder_->Init(CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to init decoder, err=%{public}d", ret);
        return false;
    }
    return true;
}

bool JpegHardwareDecoder::DoDecode(CodecImageBuffer& outputBuffer)
{
    LifeSpanTimer decodeTimer("do decode");
    int32_t ret = hwDecoder_->DoJpegDecode(inputBuffer_, outputBuffer, decodeInfo_);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to do decode, err=%{public}d", ret);
        return false;
    }
    return true;
}

void JpegHardwareDecoder::RecycleAllocatedResource()
{
    LifeSpanTimer decodeTimer("recycle resource");
    int32_t ret = hwDecoder_->FreeInBuffer(inputBuffer_);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to free input buffer, err=%{public}d", ret);
    }

    ret = hwDecoder_->DeInit(CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to deinit decoder, err=%{public}d", ret);
    }
}

OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* JpegHardwareDecoder::GetBufferMgr()
{
    static OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* staticBufferMgr = IDisplayBuffer::Get();
    return staticBufferMgr;
}
} // namespace OHOS::ImagePlugin
