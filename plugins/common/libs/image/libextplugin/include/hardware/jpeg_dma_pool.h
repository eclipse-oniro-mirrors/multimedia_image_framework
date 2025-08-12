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

#ifndef JPEG_DMA_POOL_H
#define JPEG_DMA_POOL_H
#include "jpeg_hw_decoder.h"
#include <thread>

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HDI::Codec::Image::V2_1;

struct DmaBufferInfo {
    uint32_t allocatedBufferSize;
    uint32_t allocatedBufferOffsetOfPool;
};

struct PureStreamInfo {
    uint32_t dataPos;
    uint32_t dataSize;
};

class DmaPool {
public:
    ~DmaPool() = default;
    static DmaPool& GetInstance();
    bool AllocBufferInDmaPool(sptr<ICodecImage> hwDecoder_, ImagePlugin::InputDataStream* srcStream,
                              CodecImageBuffer& inBuffer, PureStreamInfo streamInfo, DmaBufferInfo& bufferInfo);
    void RecycleBufferInDmaPool(DmaBufferInfo bufferInfo);
private:
    DmaPool() = default;
    bool Init(sptr<ICodecImage> hwDecoder_);
    bool CopySrcToDmaPool(ImagePlugin::InputDataStream* srcStream, PureStreamInfo streamInfo, 
                          DmaBufferInfo bufferInfo);
    bool PackingBufferHandle(DmaBufferInfo bufferInfo, CodecImageBuffer& inBuffer);
    void UpdateDmaPoolInfo(PureStreamInfo streamInfo, DmaBufferInfo bufferInfo);
    void RunDmaPoolDestroy();
private:
    std::mutex dmaPoolMtx_;
    bool inited_ {false};
    std::condition_variable dmaPoolCond_;
    uint32_t remainCapacity_ {0};
    uint32_t remainOffset_ {0};
    sptr<NativeBuffer> nativeBuf_ {nullptr};
    BufferHandle *bufferHandle_ {nullptr};
    std::unordered_map<uint32_t, uint32_t> usedSpace_; /* <end, size> */
    std::unordered_map<uint32_t, uint32_t> releaseSpace_; /* <end, size> */
    std::chrono::steady_clock::time_point activeTime_ {std::chrono::steady_clock::now()}; /* active time */
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // JPEG_DMA_POOL_H
