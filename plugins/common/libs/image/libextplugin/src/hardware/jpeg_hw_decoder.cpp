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
#include <sys/mman.h>

#include "hardware/jpeg_marker_define.h"
#include "hardware/jpeg_dma_pool.h"
#include "hdf_base.h"
#include "iremote_object.h"
#include "iproxy_broker.h"
#include "media_errors.h"
#include "image_trace.h"
#include "src/codec/SkJpegUtility.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "src/codec/SkJpegCodec.h"

namespace OHOS::ImagePlugin {
using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace Media;

static std::mutex g_codecMtx;
static sptr<ICodecImage> g_codecMgr;
std::vector<CodecImageCapability> JpegHardwareDecoder::capList_ = {};
std::mutex JpegHardwareDecoder::capListMtx_;

class CodecJpegDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        JPEG_HW_LOGW("codec_image_service died");
        std::lock_guard<std::mutex> lk(g_codecMtx);
        g_codecMgr = nullptr;
    }
};

static sptr<ICodecImage> GetCodecManager()
{
    std::lock_guard<std::mutex> lk(g_codecMtx);
    if (g_codecMgr) {
        return g_codecMgr;
    }
    JPEG_HW_LOGI("need to get ICodecImage");
    g_codecMgr = ICodecImage::Get();
    if (g_codecMgr == nullptr) {
        return nullptr;
    }
    bool isDeathRecipientAdded = false;
    const sptr<OHOS::IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ICodecImage>(g_codecMgr);
    if (remote) {
        sptr<CodecJpegDeathRecipient> deathCallBack(new CodecJpegDeathRecipient());
        isDeathRecipientAdded = remote->AddDeathRecipient(deathCallBack);
    }
    if (!isDeathRecipientAdded) {
        JPEG_HW_LOGE("failed to add deathRecipient for ICodecImage!");
    }
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
    JPEG_HW_LOGD("%{public}s cost: %{public}.2f ms",
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
}

JpegHardwareDecoder::~JpegHardwareDecoder()
{
    hwDecoder_ = nullptr;
}

bool JpegHardwareDecoder::IsHardwareDecodeSupported(const std::string& srcImgFormat, OHOS::Media::Size srcImgSize)
{
    if (hwDecoder_ == nullptr) {
        JPEG_HW_LOGE("failed to get hardware decoder!");
        return false;
    }
    if (srcImgFormat != JPEG_FORMAT_DESC) {
        JPEG_HW_LOGE("invalid image format: %{public}s", srcImgFormat.c_str());
        return false;
    }
    std::lock_guard<std::mutex> lock(capListMtx_);
    if (capList_.size() == 0) {
        auto ret = hwDecoder_->GetImageCapability(capList_);
        if (ret != HDF_SUCCESS) {
            JPEG_HW_LOGE("failed to get image capability, err=%{public}d!", ret);
            return false;
        }
    }

    for (const CodecImageCapability& cap : capList_) {
        JPEG_HW_LOGD("cap info: isSoftwareCodec=%{public}d, role=%{public}d, type=%{public}d, " \
                     "maxSize=[%{public}u*%{public}u], minSize=[%{public}u*%{public}u]",
                     cap.isSoftwareCodec, cap.role, cap.type, cap.maxWidth, cap.maxHeight,
                     cap.minWidth, cap.minHeight);
        if (!cap.isSoftwareCodec && cap.role == CODEC_IMAGE_JPEG &&
            cap.type == CODEC_IMAGE_TYPE_DECODER &&
            srcImgSize.width >= static_cast<int32_t>(cap.minWidth) &&
            srcImgSize.width <= static_cast<int32_t>(cap.maxWidth) &&
            srcImgSize.height >= static_cast<int32_t>(cap.minHeight) &&
            srcImgSize.height <= static_cast<int32_t>(cap.maxHeight)) {
            JPEG_HW_LOGD("decoder(%{public}s) selected", cap.name.c_str());
            return true;
        }
    }
    JPEG_HW_LOGE("no available hardware decoder, img=[%{public}ux%{public}u]", srcImgSize.width, srcImgSize.height);
    return false;
}

static jpeg_decompress_struct* GetJpegCompressInfo(SkCodec *codec)
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

bool JpegHardwareDecoder::CheckInputColorFmt(SkCodec *codec)
{
    jpeg_decompress_struct* jpegCompressInfo = GetJpegCompressInfo(codec);
    if (jpegCompressInfo == nullptr) {
        JPEG_HW_LOGE("failed to get jpeg info");
        return false;
    }
    if (jpegCompressInfo->jpeg_color_space != JCS_YCbCr) {
        JPEG_HW_LOGI("unsupported in color: %{public}d", jpegCompressInfo->jpeg_color_space);
        return false;
    }
    return true;
}

uint32_t JpegHardwareDecoder::Decode(SkCodec *codec, ImagePlugin::InputDataStream *srcStream,
                                     OHOS::Media::Size srcImgSize, uint32_t sampleSize, CodecImageBuffer& outputBuffer)
{
    Media::ImageTrace imageTrace("JpegHardwareDecoder::Decode");
    LifeSpanTimer decodeTimer("jpeg hardware decode");
    JPEG_HW_LOGD("img=[%{public}ux%{public}u], sampleSize=%{public}u",
                 srcImgSize.width, srcImgSize.height, sampleSize);
    if (hwDecoder_ == nullptr) {
        JPEG_HW_LOGE("failed to get hardware decoder!");
        return Media::ERR_IMAGE_DECODE_ABNORMAL;
    }
    if (!IsHardwareDecodeSupported(JPEG_FORMAT_DESC, srcImgSize) || !CheckInputColorFmt(codec)) {
        return Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    decodeInfo_.sampleSize = sampleSize;
    bool ret = true;
    ret = ret && PrepareInputData(codec, srcStream);
    ret = ret && DoDecode(outputBuffer);
    RecycleAllocatedResource();
    if (ret) {
        JPEG_HW_LOGD("jpeg hardware decode succeed");
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
    decodeInfo_.numComponents = static_cast<uint32_t>(jpegCompressInfo->num_components);
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
    if (actualHuffValLen >= MAX_LIST_HUFFVAL_LEN) {
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
            uint16_t* quantStart = reinterpret_cast<uint16_t *>(jpegCompressInfo->quant_tbl_ptrs[i]->quantval);
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

bool JpegHardwareDecoder::AssembleJpegImgHeader(jpeg_decompress_struct* jpegCompressInfo)
{
    decodeInfo_.imageWidth = jpegCompressInfo->image_width;
    decodeInfo_.imageHeight = jpegCompressInfo->image_height;
    decodeInfo_.dataPrecision = static_cast<uint32_t>(jpegCompressInfo->data_precision);
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

bool JpegHardwareDecoder::CopySrcToInputBuff(ImagePlugin::InputDataStream* srcStream, BufferHandle* inputBufferHandle)
{
    uint32_t positionRecord = srcStream->Tell();
    srcStream->Seek(compressDataPos_);
    uint32_t readSize = 0;
    bool flag = srcStream->Read(compressDataSize_,
                                static_cast<uint8_t *>(inputBufferHandle->virAddr),
                                static_cast<uint32_t>(inputBufferHandle->size),
                                readSize);
    srcStream->Seek(positionRecord);
    if (!flag || readSize != compressDataSize_) {
        JPEG_HW_LOGE("failed to read input data, readSize=%{public}u", readSize);
        return false;
    }
    return true;
}

uint16_t JpegHardwareDecoder::ReadTwoBytes(ImagePlugin::InputDataStream* srcStream, unsigned int pos, bool& flag)
{
    static constexpr int ZERO = 0;
    static constexpr int ONE = 1;
    static constexpr int TWO = 2;
    static constexpr int BITS_OFFSET = 8;
    uint8_t* readBuffer = new (std::nothrow) uint8_t[TWO];
    uint16_t result = 0xFFFF;
    if (readBuffer == nullptr) {
        JPEG_HW_LOGE("new readbuffer failed");
        flag = false;
    } else {
        uint32_t readSize = 0;
        srcStream->Seek(pos);
        bool ret = srcStream->Read(TWO, readBuffer, TWO, readSize);
        if (!ret) {
            JPEG_HW_LOGE("read input stream failed.");
            flag = false;
        }
        result = static_cast<uint16_t>((readBuffer[ZERO] << BITS_OFFSET) + readBuffer[ONE]);
        delete[] readBuffer;
    }
    return result;
}

bool JpegHardwareDecoder::GetCompressedDataStart(ImagePlugin::InputDataStream* srcStream)
{
    unsigned int fileSize = static_cast<unsigned int>(srcStream->GetStreamSize());
    if (fileSize == 0) {
        JPEG_HW_LOGE("input stream is null ");
        return false;
    }
    uint32_t positionRecord = srcStream->Tell();
    srcStream->Seek(0);
    unsigned int curPos = 0;
    bool findFlag = false;
    while (curPos + JpegMarker::MARKER_LEN <= fileSize) {
        bool readSuccess = true;
        uint16_t potentialMarker = ReadTwoBytes(srcStream, curPos, readSuccess);
        if (!readSuccess) {
            findFlag = false;
            break;
        }
        if (potentialMarker < JpegMarker::MIN_MARKER || potentialMarker > JpegMarker::MAX_MARKER) {
            ++curPos;
            continue;
        }
        if (!JumpOverCurrentJpegMarker(srcStream, curPos, fileSize, potentialMarker)) {
            break;
        }
        if (potentialMarker == JpegMarker::SOS) {
            findFlag = true;
            compressDataPos_ = curPos;
            compressDataSize_ = fileSize - curPos;
            break;
        }
    }
    JPEG_HW_LOGI("input stream size:%{public}u compress data size:%{public}u", fileSize, compressDataSize_);
    srcStream->Seek(positionRecord);
    return findFlag;
}

bool JpegHardwareDecoder::TryDmaPoolInBuff(ImagePlugin::InputDataStream* srcStream)
{
    ImageTrace imageTrace("JpegHardwareDecoder::TryDmaPoolInBuff");
    PureStreamInfo curStreamInfo {compressDataPos_, compressDataSize_};
    DmaBufferInfo allocBufferInfo {0, 0};
    if (!DmaPool::GetInstance().AllocBufferInDmaPool(hwDecoder_, srcStream, inputBuffer_,
        curStreamInfo, allocBufferInfo)) {
        return false;
    }
    usedOffsetInPool_ = allocBufferInfo.allocatedBufferOffsetOfPool;
    usedSizeInPool_ = allocBufferInfo.allocatedBufferSize;
    return true;
}

bool JpegHardwareDecoder::TryNormalInBuff(ImagePlugin::InputDataStream* srcStream)
{
    ImageTrace imageTrace("JpegHardwareDecoder::TryNormalInBuff");
    // step1. alloc Buffer
    int32_t ret = hwDecoder_->AllocateInBuffer(inputBuffer_, compressDataSize_, CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to allocate input buffer, err=%{public}d", ret);
        return false;
    }
    usedOffsetInPool_ = 0;
    // step2. copysrc to buffer
    BufferHandle *inputBufferHandle = inputBuffer_.buffer->GetBufferHandle();
    if (inputBufferHandle == nullptr) {
        JPEG_HW_LOGE("inputBufferHandle is nullptr");
        return false;
    }
    inputBufferHandle->virAddr = mmap(nullptr, inputBufferHandle->size,
                                      PROT_READ | PROT_WRITE, MAP_SHARED, inputBufferHandle->fd, 0);
    if (inputBufferHandle->virAddr == MAP_FAILED) {
        JPEG_HW_LOGE("failed to map input buffer");
        return false;
    }
    if (!CopySrcToInputBuff(srcStream, inputBufferHandle)) {
        munmap(inputBufferHandle->virAddr, inputBufferHandle->size);
        JPEG_HW_LOGE("copy bitstream to input buffer failed");
        return false;
    }
    ret = munmap(inputBufferHandle->virAddr, inputBufferHandle->size);
    if (ret != 0) {
        JPEG_HW_LOGE("failed to unmap input buffer, err=%{public}d", ret);
    }

    return true;
}

bool JpegHardwareDecoder::CopySrcImgToDecodeInputBuffer(ImagePlugin::InputDataStream* srcStream)
{
    // max size of pure jpeg bitstream to use DMA Pool is 256KB
    constexpr uint32_t MAX_SIZE_USE_DMA_POOL = 256 * 1024;
    if (!GetCompressedDataStart(srcStream)) {
        JPEG_HW_LOGE("get compressed data start failed");
        return false;
    }
    if (compressDataSize_ <= MAX_SIZE_USE_DMA_POOL) {
        if (TryDmaPoolInBuff(srcStream)) {
            useDmaPool_ = true;
        }
    }
    if ((compressDataSize_ > MAX_SIZE_USE_DMA_POOL) || (!useDmaPool_)) {
        if (!TryNormalInBuff(srcStream)) {
            return false;
        }
    }
    decodeInfo_.compressPos = usedOffsetInPool_;
    return true;
}

bool JpegHardwareDecoder::IsStandAloneJpegMarker(uint16_t marker)
{
    auto iter = std::find(JpegMarker::STAND_ALONE_MARKER.begin(), JpegMarker::STAND_ALONE_MARKER.end(), marker);
    return (iter != JpegMarker::STAND_ALONE_MARKER.end());
}

bool JpegHardwareDecoder::JumpOverCurrentJpegMarker(ImagePlugin::InputDataStream* srcStream, unsigned int& curPos,
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
    bool readSuccess = true;
    unsigned int skipBytes = static_cast<unsigned int>(ReadTwoBytes(srcStream, curPos, readSuccess));
    if (!readSuccess) {
        return false;
    }
    curPos += skipBytes;
    if (curPos > totalLen) {
        JPEG_HW_LOGE("invalid pos(cur=%{public}u, total=%{public}u) after jump over related parameters " \
                     "for marker(%{public}u)", curPos, totalLen, marker);
        return false;
    }
    return true;
}

bool JpegHardwareDecoder::PrepareInputData(SkCodec *codec, ImagePlugin::InputDataStream *srcStream)
{
    Media::ImageTrace imageTrace("PrepareInputData");
    LifeSpanTimer decodeTimer("prepare input data");
    jpeg_decompress_struct* jpegCompressInfo = GetJpegCompressInfo(codec);
    if (jpegCompressInfo == nullptr || srcStream == nullptr) {
        JPEG_HW_LOGE("failed to get jpeg compress info or invalid input stream");
        return false;
    }
    bool ret = AssembleJpegImgHeader(jpegCompressInfo);
    ret = ret && CopySrcImgToDecodeInputBuffer(srcStream);
    return ret;
}

bool JpegHardwareDecoder::InitDecoder()
{
    LifeSpanTimer decodeTimer("init decoder");
    if (hwDecoder_ == nullptr) {
        JPEG_HW_LOGE("failed to get ICodecImage!");
        return false;
    }
    int32_t ret = hwDecoder_->Init(CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to init decoder, err=%{public}d", ret);
        return false;
    }
    hwDecoder_->NotifyPowerOn(CODEC_IMAGE_JPEG);
    return true;
}

bool JpegHardwareDecoder::DoDecode(CodecImageBuffer& outputBuffer)
{
    Media::ImageTrace imageTrace("DoDecode");
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
    ImageTrace imageTrace("JpegHardwareDecoder::RecycleAllocatedResource");
    if (useDmaPool_) {
        DmaBufferInfo bufferInfo {usedSizeInPool_, usedOffsetInPool_};
        DmaPool::GetInstance().RecycleBufferInDmaPool(bufferInfo);
    }
}
} // namespace OHOS::ImagePlugin
