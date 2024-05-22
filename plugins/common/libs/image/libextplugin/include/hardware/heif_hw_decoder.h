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

#ifndef HEIF_HW_DECODER_H
#define HEIF_HW_DECODER_H

#include <cinttypes>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <list>
 #include "imagecodec/image_codec.h"

namespace OHOS {
namespace ImagePlugin {
struct GridInfo {
    uint32_t displayWidth = 0;
    uint32_t displayHeight = 0;
    bool enableGrid = false;
    uint32_t cols = 0;
    uint32_t rows = 0;
    uint32_t tileWidth = 0;
    uint32_t tileHeight = 0;

    bool IsValid() const;
};

class HeifHardwareDecoder {
public:
    HeifHardwareDecoder();
    ~HeifHardwareDecoder();
    sptr<SurfaceBuffer> AllocateOutputBuffer(uint32_t width, uint32_t height, int32_t pixelFmt);
    uint32_t DoDecode(const GridInfo& gridInfo, std::vector<std::vector<uint8_t>>& inputs, sptr<SurfaceBuffer>& output);
private:
    class HeifDecoderCallback : public ImageCodecCallback {
    public:
        HeifDecoderCallback(HeifHardwareDecoder* heifDecoder);
        void OnError(ImageCodecError err) override;
        void OnOutputFormatChanged(const Format &format) override;
        void OnInputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) override;
        void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) override;
        HeifHardwareDecoder* heifDecoder_;
    };
private:
    struct RawYuvCopyInfo {
        uint8_t* yStart = 0;
        uint8_t* uvStart = 0;
        uint32_t stride = 0;
        uint32_t yStride = 0;
        uint32_t yOffset = 0;
        uint32_t uvOffset = 0;
    };
private:
    static bool GetUvPlaneOffsetFromSurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer, uint64_t& offset);
    bool IsHardwareDecodeSupported(const GridInfo& gridInfo);
    bool SetCallbackForDecoder();
    bool ConfigureDecoder(const GridInfo& gridInfo, sptr<SurfaceBuffer>& output);
    bool SetOutputBuffer(const GridInfo& gridInfo, sptr<SurfaceBuffer> output);
    bool WaitForOmxToReturnInputBuffer(uint32_t& bufferId, std::shared_ptr<ImageCodecBuffer>& buffer);
    int32_t PrepareInputCodecBuffer(const std::vector<std::vector<uint8_t>>& inputs, size_t inputIndex,
                                    std::shared_ptr<ImageCodecBuffer>& buffer);
    void SendInputBufferLoop(const std::vector<std::vector<uint8_t>>& inputs);
    bool WaitForOmxToReturnOutputBuffer(uint32_t& bufferId, std::shared_ptr<ImageCodecBuffer>& buffer);
    void AssembleOutput(uint32_t outputIndex, std::shared_ptr<ImageCodecBuffer>& buffer);
    static uint32_t CalculateDirtyLen(uint32_t displayLen, uint32_t gridLen, uint32_t totalGrid, uint32_t curGrid);
    static bool CopyRawYuvData(const RawYuvCopyInfo& src, const RawYuvCopyInfo& dst,
                               uint32_t dirtyWidth, uint32_t dirtyHeight);
    void ReceiveOutputBufferLoop();
    static int64_t GetTimestampInUs();
    void ReleaseDecoder();

    void SignalError();
    bool HasError();
    void Reset();

    void FlushOutput();
    std::string GetOutputPixelFmtDesc();
    void DumpOutput();
private:
    static constexpr int32_t BUFFER_CIRCULATE_TIMEOUT_IN_MS = 1000;
    static constexpr uint32_t SAMPLE_RATIO_FOR_YUV420_SP = 2;
    static constexpr size_t MIN_SIZE_OF_INPUT = 2;

    std::shared_ptr<ImageCodec> heifDecoderImpl_;

    sptr<SurfaceBuffer> output_;
    uint64_t uvOffsetForOutput_;
    GridInfo gridInfo_;

    std::mutex errMtx_;
    bool hasErr_ = false;

    std::mutex inputMtx_;
    std::condition_variable inputCond_;
    std::list<std::pair<uint32_t, std::shared_ptr<ImageCodecBuffer>>> inputList_;

    std::mutex outputMtx_;
    std::condition_variable outputCond_;
    std::list<std::pair<uint32_t, std::shared_ptr<ImageCodecBuffer>>> outputList_;

    std::thread releaseThread_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // HEIF_HW_DECODER_H