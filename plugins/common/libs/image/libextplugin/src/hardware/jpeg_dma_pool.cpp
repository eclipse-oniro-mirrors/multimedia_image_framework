/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hardware/jpeg_dma_pool.h"
#include <chrono>
#include <sys/mman.h>
namespace OHOS::ImagePlugin {
using namespace OHOS::HDI::Codec::Image::V2_1;

constexpr uint32_t DMA_POOL_SIZE = 1024 * 1024;     /* the size of DMA Pool is 1M */
constexpr uint32_t DMA_POOL_ALIGN_SIZE = 32 * 1024; /* Input buffer alignment size is 32K */

DmaPool& DmaPool::GetInstance()
{
    static DmaPool singleton;
    return singleton;
}

bool DmaPool::AllocBufferInDmaPool(sptr<ICodecImage> hwDecoder_, ImagePlugin::InputDataStream* srcStream,
                                   CodecImageBuffer& inBuffer, PureStreamInfo streamInfo, DmaBufferInfo& bufferInfo)
{
    std::lock_guard<std::mutex> lock(dmaPoolMtx_);
    // step1. decide whether to alloc dma pool
    if (!Init(hwDecoder_)) {
        JPEG_HW_LOGE("failed to init dma pool");
        return false;
    }
    // step2. determine whether remainCapacity_ is sufficient
    bufferInfo.allocatedBufferSize = ((streamInfo.dataSize + DMA_POOL_ALIGN_SIZE - 1) / DMA_POOL_ALIGN_SIZE)
                                     * DMA_POOL_ALIGN_SIZE;
    bufferInfo.allocatedBufferOffsetOfPool = remainOffset_;
    if (bufferInfo.allocatedBufferSize > remainCapacity_) {
        JPEG_HW_LOGI("The space left in dma pool isn't enough");
        return false;
    }
    // step3. try to copy src data to alloc buffer in dma pool
    if (!CopySrcToDmaPool(srcStream, streamInfo, bufferInfo)) {
        return false;
    }
    // step4. try to packing bufferhandle to inbuffer
    if (!PackingBufferHandle(bufferInfo, inBuffer)) {
        return false;
    }
    // step5. try to alloc buffer in dmapool
    UpdateDmaPoolInfo(streamInfo, bufferInfo);
    return true;
}

bool DmaPool::Init(sptr<ICodecImage> hwDecoder_)
{
    if (inited_) {
        return true;
    }
    CodecImageBuffer tempPool{};
    int32_t ret = hwDecoder_->AllocateInBuffer(tempPool, DMA_POOL_SIZE, CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS || tempPool.buffer == nullptr) {
        JPEG_HW_LOGE("failed to allocate dma pool, err=%{public}d", ret);
        return false;
    }
    bufferHandle_ = tempPool.buffer->GetBufferHandle();
    if (bufferHandle_ == nullptr) {
        JPEG_HW_LOGE("dma pool bufferHandle is null");
        return false;
    }
    bufferHandle_->virAddr = mmap(nullptr, DMA_POOL_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, bufferHandle_->fd, 0);
    if (bufferHandle_->virAddr == MAP_FAILED) {
        JPEG_HW_LOGE("failed to map dma pool");
        return false;
    }
    std::thread lifeManageThread([this] {this->RunDmaPoolDestroy();});
    if (!lifeManageThread.joinable()) {
        if (munmap(bufferHandle_->virAddr, DMA_POOL_SIZE) != 0) {
            JPEG_HW_LOGE("failed to unmap dma pool");
        }
        JPEG_HW_LOGE("failed to create lifeManageThread_");
        bufferHandle_ = nullptr;
        return false;
    }
    lifeManageThread.detach();
    inited_ = true;
    remainCapacity_ = DMA_POOL_SIZE;
    nativeBuf_ = tempPool.buffer;
    JPEG_HW_LOGI("creta dma pool success!");
    return true;
}

bool DmaPool::CopySrcToDmaPool(ImagePlugin::InputDataStream* srcStream, PureStreamInfo streamInfo,
                               DmaBufferInfo bufferInfo)
{
    uint32_t positionRecord = srcStream->Tell();
    srcStream->Seek(streamInfo.dataPos);
    uint32_t readSize = 0;
    bool flag = srcStream->Read(streamInfo.dataSize,
                                static_cast<uint8_t*>(bufferHandle_->virAddr) + bufferInfo.allocatedBufferOffsetOfPool,
                                static_cast<uint32_t>(bufferHandle_->size) - bufferInfo.allocatedBufferOffsetOfPool,
                                readSize);
    srcStream->Seek(positionRecord);
    if (!flag || readSize != streamInfo.dataSize) {
        JPEG_HW_LOGE("failed to read input data, readSize=%{public}u", readSize);
        return false;
    }
    return true;
}

bool DmaPool::PackingBufferHandle(DmaBufferInfo bufferInfo, CodecImageBuffer& inBuffer)
{
    BufferHandle* curHandle = new (std::nothrow) BufferHandle;
    if (curHandle == nullptr) {
        JPEG_HW_LOGE("failed to new bufferHandle!");
        return false;
    }
    curHandle->fd = bufferHandle_->fd;
    curHandle->size = static_cast<int32_t>(bufferInfo.allocatedBufferSize);
    curHandle->width = static_cast<int32_t>(bufferInfo.allocatedBufferSize);
    curHandle->stride = static_cast<int32_t>(bufferInfo.allocatedBufferSize);
    curHandle->height = 1;
    curHandle->reserveFds = 0;
    curHandle->reserveInts = 0;
    inBuffer.buffer = new NativeBuffer();
    inBuffer.buffer->SetBufferHandle(curHandle, true, [this](BufferHandle* freeBuffer) {
        delete freeBuffer;
    });
    inBuffer.bufferRole = CODEC_IMAGE_JPEG;
    return true;
}

void DmaPool::UpdateDmaPoolInfo(PureStreamInfo streamInfo, DmaBufferInfo bufferInfo)
{
    remainCapacity_ -= bufferInfo.allocatedBufferSize;
    remainOffset_ += bufferInfo.allocatedBufferSize;
    usedSpace_[remainOffset_] = bufferInfo.allocatedBufferSize;
    activeTime_ = std::chrono::steady_clock::now();
    JPEG_HW_LOGI("upadteSpaceInfo: aligend size:%{public}u buffer usedOffset:%{public}u usedNum:%{public}u",
                 bufferInfo.allocatedBufferSize, bufferInfo.allocatedBufferOffsetOfPool, usedSpace_.size());
}

void DmaPool::RunDmaPoolDestroy()
{
    using namespace std::literals;
    std::unique_lock<std::mutex> lck(dmaPoolMtx_);
    /* Destroy the DMA pool if it is not used for more than 10s */
    while (true) {
        bool ret = dmaPoolCond_.wait_for(lck, 5s, [this]() {
            auto curTime = std::chrono::steady_clock::now();
            auto diffDuration = std::chrono::duration_cast<std::chrono::seconds>(curTime - activeTime_);
            return usedSpace_.empty() && diffDuration >= 10s;
        });
        if (ret) {
            break;
        }
        JPEG_HW_LOGI("wait to destroy dma pool");
    }
    if (bufferHandle_ != nullptr && bufferHandle_->virAddr != nullptr) {
        if (munmap(bufferHandle_->virAddr, DMA_POOL_SIZE) != 0) {
            JPEG_HW_LOGE("failed to unmap dma pool");
        }
    } else {
        JPEG_HW_LOGE("dma pool bufferhandle or viraddr is nullptr!");
    }
    inited_ = false;
    remainCapacity_ = 0;
    remainOffset_ = 0;
    nativeBuf_ = nullptr;
    bufferHandle_ = nullptr;
    JPEG_HW_LOGI("dma pool destroyed!");
    return;
}

void DmaPool::RecycleBufferInDmaPool(DmaBufferInfo bufferInfo)
{
    std::lock_guard<std::mutex> lock(dmaPoolMtx_);
    activeTime_ = std::chrono::steady_clock::now();
    uint32_t endOffset = bufferInfo.allocatedBufferOffsetOfPool + bufferInfo.allocatedBufferSize;
    // 1.push used space to release space
    auto it = usedSpace_.find(endOffset);
    if (it != usedSpace_.end()) {
        releaseSpace_[endOffset] = bufferInfo.allocatedBufferSize;
        usedSpace_.erase(it);
    }

    // 2.recycle continuous release space adjacent to remainOffset_
    while (true) {
        auto it = releaseSpace_.find(remainOffset_);
        if (it != releaseSpace_.end()) {
            remainOffset_ -= it->second;
            remainCapacity_ += it->second;
            releaseSpace_.erase(it);
            continue;
        }
        break;
    }
    JPEG_HW_LOGI("remainCapacity_: size:%{public}u remainOffset_:%{public}u unRecycleNum:%{public}lu + %{public}lu",
                 remainCapacity_, remainOffset_, usedSpace_.size(), releaseSpace_.size());
}
}