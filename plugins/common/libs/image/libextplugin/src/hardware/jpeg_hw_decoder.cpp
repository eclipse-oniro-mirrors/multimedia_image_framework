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
#include<thread>
#include <securec.h>
#include <sys/mman.h> 

#include "hardware/jpeg_marker_define.h"
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
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace Media;

static std::mutex g_codecMtx;
static sptr<ICodecImage> g_codecMgr;
static constexpr std::chrono::duration<int> THRESHIOLD_DURATION(DMA_POOL_WAIT_SECONDS);
std::vector<CodecImageCapability> JpegHardwareDecoder::capList_ = {};
std::pair<DmaPool*, std::chrono::steady_clock::time_point> JpegHardwareDecoder::dmaPool_ =
    std::make_pair(nullptr, std::chrono::steady_clock::now());
std::mutex JpegHardwareDecoder::dmaPoolMtx_;
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

DmaPool::DmaPool()
{
    buffer = {0};
    remainSpace = {};
    usedSpace = {};
    releaseSpace = {};
    bufferHandle = nullptr;
}

DmaPool::~DmaPool()
{
    buffer = {0};
    remainSpace = {};
    usedSpace = {};
    releaseSpace = {};
    bufferHandle = nullptr;
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
    bufferMgr_ = GetBufferMgr();
}

JpegHardwareDecoder::~JpegHardwareDecoder()
{
    hwDecoder_ = nullptr;
    bufferMgr_ = nullptr;
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
    if (hwDecoder_ == nullptr || bufferMgr_ == nullptr) {
        JPEG_HW_LOGE("failed to get hardware decoder or failed to get buffer manager!");
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

bool JpegHardwareDecoder::AllocDmaPool()
{
    dmaPool_.first = new DmaPool();
    int32_t ret = hwDecoder_->AllocateInBuffer(dmaPool_.first->buffer, (DMA_POOL_SIZE * KILO_BYTE),
                                               CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to allocate DMA pool, err=%{public}d", ret);
        delete dmaPool_.first;
        dmaPool_.first = nullptr;
        return false;
    }
    dmaPool_.first->remainSpace = std::make_pair(DMA_POOL_SIZE * KILO_BYTE, 0);
    dmaPool_.first->bufferHandle = (dmaPool_.first->buffer).buffer->GetBufferHandle();
    if (dmaPool_.first->bufferHandle == nullptr) {
        JPEG_HW_LOGE("inputBufferHandle is nullptr");
        delete dmaPool_.first;
        dmaPool_.first = nullptr;
        return false;
    }
    dmaPool_.first->bufferHandle->virAddr = mmap(nullptr, (DMA_POOL_SIZE * KILO_BYTE), PROT_READ | PROT_WRITE,
                                                 MAP_SHARED, dmaPool_.first->bufferHandle->fd, 0);
    if (dmaPool_.first->bufferHandle->virAddr == MAP_FAILED) {
        JPEG_HW_LOGE("failed to map input buffer");
        delete dmaPool_.first;
        dmaPool_.first = nullptr;
        return false;
    }
    JPEG_HW_LOGI("alloc DMA pool success!");
    return true;
}

void JpegHardwareDecoder::UpdateSpaceInfo()
{
    usedOffsetInPool_ = (dmaPool_.first->remainSpace).second;
    uint32_t newSize = (dmaPool_.first->remainSpace).first - usedSizeInPool_;
    uint32_t newStart = (dmaPool_.first->remainSpace).second + usedSizeInPool_;
    dmaPool_.first->remainSpace = std::make_pair(newSize, newStart);
    (dmaPool_.first->usedSpace)[newStart] = usedSizeInPool_;
    JPEG_HW_LOGI("upadteSpaceInfo:  aligend size:%{public}u buffer offset:%{public}u",
                 usedSizeInPool_, usedOffsetInPool_);
}

bool JpegHardwareDecoder::CopySrcToInputBuff(ImagePlugin::InputDataStream* srcStream, BufferHandle* inputBufferHandle)
{
    uint32_t positionRecord = srcStream->Tell();
    srcStream->Seek(compressDataPos_);
    uint32_t readSize = 0;
    bool flag = srcStream->Read(compressDataSize_,
                                static_cast<uint8_t *>(inputBufferHandle->virAddr) + usedOffsetInPool_,
                                static_cast<uint32_t>(inputBufferHandle->size) - usedOffsetInPool_,
                                readSize
                                );
    srcStream->Seek(positionRecord);
    if (!flag || readSize != compressDataSize_) {
        JPEG_HW_LOGE("failed to read input data, readSize=%{public}u", readSize);
        return false;
    }
    return true;
}
void JpegHardwareDecoder::RunDmaPoolRecycle()
{
    dmaPoolMtx_.lock();
    while (true) {
        std::chrono::steady_clock::time_point curTime = std::chrono::steady_clock::now();
        std::chrono::duration<int> diffDuration = 
            std::chrono::duration_cast<std::chrono::duration<int>>(curTime - dmaPool_.second);
        if (diffDuration >= THRESHIOLD_DURATION) {
            break;
        } else {
            dmaPoolMtx_.unlock();
            JPEG_HW_LOGI("wait to recycle DMA pool");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            dmaPoolMtx_.lock();
        }
    }
    if (munmap(dmaPool_.first->bufferHandle->virAddr, (DMA_POOL_SIZE * KILO_BYTE)) != 0) {
        JPEG_HW_LOGE("failed to unmap input buffer");
    }
    delete dmaPool_.first;
    dmaPool_.first = nullptr;
    JPEG_HW_LOGI("DMA pool has been destroyed.");
    dmaPoolMtx_.unlock();
}

bool JpegHardwareDecoder::AllocSpace()
{
    // step1. decide whether to alloc buffer
    if (dmaPool_.first == nullptr) {
        if (!AllocDmaPool()) {
            return false;
        }
        std::thread dmaPoolRecycleThread(RunDmaPoolRecycle);
        dmaPoolRecycleThread.detach();
    }
    dmaPool_.second = std::chrono::steady_clock::now();
    // step2. try to alloc space
    uint32_t uintNum = (compressDataSize_ + BUFFER_UNIT_SIZE * KILO_BYTE - 1) / (BUFFER_UNIT_SIZE * KILO_BYTE);
    usedSizeInPool_ = uintNum * (BUFFER_UNIT_SIZE * KILO_BYTE);
    if(usedSizeInPool_ <= (dmaPool_.first->remainSpace).first) {
        UpdateSpaceInfo();
    } else {
        JPEG_HW_LOGI("The space left in DMA pool isn't enough");
        return false;
    }
    return true;
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

bool JpegHardwareDecoder::PackingInputBufferHandle(BufferHandle* inputBufferHandle)
{
    BufferHandle* curHandle = new (std::nothrow) BufferHandle;
    if (curHandle == nullptr) {
        JPEG_HW_LOGE("failed to new bufferHandle!");
        return false;
    }
    curHandle->fd = inputBufferHandle->fd;
    curHandle->size = usedSizeInPool_;
    curHandle->width = usedSizeInPool_;
    curHandle->stride = usedSizeInPool_;
    curHandle->height = 1;
    curHandle->reserveFds = 0;
    curHandle->reserveInts = 0;
    inputBuffer_.buffer = new NativeBuffer();
    inputBuffer_.buffer->SetBufferHandle(curHandle, true, [this](BufferHandle* freeBuffer) {
        delete freeBuffer;
    });
    inputBuffer_.bufferRole = CODEC_IMAGE_JPEG;
    JPEG_HW_LOGI("inputBuffer size:%{public}d  DMA pool size:%{public}d",
                inputBuffer_.buffer->GetBufferHandle()->size, dmaPool_.first->bufferHandle->size);
    return true;
}

bool JpegHardwareDecoder::TryDmaPoolInBuff(ImagePlugin::InputDataStream* srcStream)
{
    ImageTrace imageTrace("JpegHardwareDecoder::TryDmaPoolInBuff");
    // step1. alloc Buffer
    std::lock_guard<std::mutex> lock(dmaPoolMtx_);
    if (!AllocSpace()) {
        return false;
    }
    // step2. copysrc to buffer
    BufferHandle *inputBufferHandle = dmaPool_.first->bufferHandle;
    if (!CopySrcToInputBuff(srcStream, inputBufferHandle)) {
        return false;
    }
    // step3. packing a inputBuffer_
    if (!PackingInputBufferHandle(inputBufferHandle)) {
        return false;
    }
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
    useDmaPool_ = false;
    if (!GetCompressedDataStart(srcStream)) {
        JPEG_HW_LOGE("get compressed data start failed");
        return false;
    }
    if (compressDataSize_ <= (MAX_SIZE_USE_DMA_POOL * KILO_BYTE)) {
        if (TryDmaPoolInBuff(srcStream)) {
            useDmaPool_ = true;
        }
    }
    if (compressDataSize_ > (MAX_SIZE_USE_DMA_POOL * KILO_BYTE) || !useDmaPool_) {
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

void JpegHardwareDecoder::ReleaseSpace(uint32_t& offset, uint32_t& usedSize)
{
    std::lock_guard<std::mutex> lock(dmaPoolMtx_);
    dmaPool_.second = std::chrono::steady_clock::now();
    auto it = (dmaPool_.first->usedSpace).find(offset);
    if (it != (dmaPool_.first->usedSpace).end()) {
        (dmaPool_.first->releaseSpace)[offset] = usedSize;
        (dmaPool_.first->usedSpace).erase(it);
    }
}

bool JpegHardwareDecoder::RecycleSpace()
{
    std::lock_guard<std::mutex> lock(dmaPoolMtx_);
    auto it = (dmaPool_.first->releaseSpace).find((dmaPool_.first->remainSpace).second);
    if (it != (dmaPool_.first->releaseSpace).end()) {
        uint32_t newStart = (dmaPool_.first->remainSpace).second - it->second; 
        uint32_t newSize = it->second + (dmaPool_.first->remainSpace).first;
        dmaPool_.first->remainSpace = std::make_pair(newSize, newStart);
        (dmaPool_.first->releaseSpace).erase(it);
        return true;
    }
    return false;
}

void JpegHardwareDecoder::RecycleAllocatedResource()
{
    ImageTrace imageTrace("JpegHardwareDecoder::RecycleAllocatedResource");
    if (useDmaPool_) {
        // merge continuous remain space in DMA pool
        uint32_t newEnd = usedOffsetInPool_ + usedSizeInPool_;
        uint32_t newSize = usedSizeInPool_;
        ReleaseSpace(newEnd, newSize);
        bool findEnd = true;
        while (findEnd) {
            findEnd = RecycleSpace();
        }
        JPEG_HW_LOGI("remianSpace info: size=%{public}u start=%{public}u", (dmaPool_.first->remainSpace).first,
                     (dmaPool_.first->remainSpace).second);
    }
}

OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* JpegHardwareDecoder::GetBufferMgr()
{
    static OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* staticBufferMgr = IDisplayBuffer::Get();
    return staticBufferMgr;
}
} // namespace OHOS::ImagePlugin
