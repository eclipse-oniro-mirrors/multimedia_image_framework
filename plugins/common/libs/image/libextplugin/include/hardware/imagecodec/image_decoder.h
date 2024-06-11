/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMAGE_DECODER_H
#define IMAGE_DECODER_H

 #include "hardware/imagecodec/image_codec.h"

namespace OHOS::ImagePlugin {
class ImageDecoder : public ImageCodec {
public:
    ImageDecoder();
private:
    // configure
    int32_t OnConfigure(const Format &format) override;
    int32_t SetupPort(const Format &format);
    int32_t UpdateInPortFormat() override;
    int32_t UpdateOutPortFormat() override;
    bool UpdateConfiguredFmt(OMX_COLOR_FORMATTYPE portFmt);
    void UpdateColorAspects() override;
    void UpdateDisplaySizeByCrop();
    int32_t ReConfigureOutputBufferCnt() override;
    uint64_t OnGetOutputBufferUsage() override;
    int32_t OnSetOutputBuffer(sptr<SurfaceBuffer> output) override;

    // start
    int32_t AllocateBuffersOnPort(OMX_DIRTYPE portIndex) override;
    void UpdateFormatFromSurfaceBuffer() override;
    int32_t SubmitAllBuffersOwnedByUs() override;
    int32_t SubmitOutputBuffersToOmxNode() override;
    bool ReadyToStart() override;

    // input buffer circulation
    void OnOMXEmptyBufferDone(uint32_t bufferId, BufferOperationMode mode) override;

    // output buffer circulation
    uint64_t GetProducerUsage();

    // stop/release
    void EraseBufferFromPool(OMX_DIRTYPE portIndex, size_t i) override;
private:
    static constexpr uint64_t BUFFER_MODE_REQUEST_USAGE =
        BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_VIDEO_DECODER | BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE;
    bool enableHeifGrid_ = false;
    sptr<SurfaceBuffer> outputBuffer_;
};
} // namespace OHOS::ImagePlugin

#endif // IMAGE_DECODER_H