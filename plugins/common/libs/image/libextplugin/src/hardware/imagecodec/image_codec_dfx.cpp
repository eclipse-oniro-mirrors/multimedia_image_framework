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

#include <fstream>
#include "hardware/imagecodec/image_codec.h"
#include "hardware/imagecodec/image_codec_log.h"

namespace OHOS::ImagePlugin {
using namespace std;

void ImageCodec::PrintAllBufferInfo()
{
    HLOGI("------------INPUT-----------");
    for (const BufferInfo& info : inputBufferPool_) {
        HLOGI("inBufId = %{public}u, owner = %{public}s", info.bufferId, ToString(info.owner));
    }
    HLOGI("----------------------------");
    HLOGI("------------OUTPUT----------");
    for (const BufferInfo& info : outputBufferPool_) {
        HLOGI("outBufId = %{public}u, owner = %{public}s", info.bufferId, ToString(info.owner));
    }
    HLOGI("----------------------------");
}

std::array<uint32_t, ImageCodec::OWNER_CNT> ImageCodec::CountOwner(bool isInput)
{
    std::array<uint32_t, OWNER_CNT> arr;
    arr.fill(0);
    const vector<BufferInfo>& pool = isInput ? inputBufferPool_ : outputBufferPool_;
    for (const BufferInfo &info : pool) {
        arr[info.owner]++;
    }
    return arr;
}

void ImageCodec::ChangeOwner(BufferInfo& info, BufferOwner newOwner)
{
    if (!debugMode_) {
        info.owner = newOwner;
        return;
    }
    BufferOwner oldOwner = info.owner;
    const char* oldOwnerStr = ToString(oldOwner);
    const char* newOwnerStr = ToString(newOwner);
    const char* idStr = info.isInput ? "inBufId" : "outBufId";

    // calculate hold time
    auto now = chrono::steady_clock::now();
    uint64_t holdUs = static_cast<uint64_t>(
        chrono::duration_cast<chrono::microseconds>(now - info.lastOwnerChangeTime).count());
    double holdMs = holdUs / US_TO_MS;
    TotalCntAndCost& holdRecord = info.isInput ? inputHoldTimeRecord_[oldOwner][newOwner] :
                                                outputHoldTimeRecord_[oldOwner][newOwner];
    holdRecord.totalCnt++;
    holdRecord.totalCostUs += holdUs;
    double aveHoldMs = holdRecord.totalCostUs / US_TO_MS / holdRecord.totalCnt;

    // now change owner
    info.lastOwnerChangeTime = now;
    info.owner = newOwner;
    std::array<uint32_t, OWNER_CNT> arr = CountOwner(info.isInput);
    HLOGI("%{public}s = %{public}u, after hold %{public}.1f ms (%{public}.1f ms), %{public}s -> %{public}s, "
          "%{public}u/%{public}u/%{public}u",
          idStr, info.bufferId, holdMs, aveHoldMs, oldOwnerStr, newOwnerStr,
          arr[OWNED_BY_US], arr[OWNED_BY_USER], arr[OWNED_BY_OMX]);

    if (info.isInput && oldOwner == OWNED_BY_US && newOwner == OWNED_BY_OMX) {
        UpdateInputRecord(info, now);
    }
    if (!info.isInput && oldOwner == OWNED_BY_OMX && newOwner == OWNED_BY_US) {
        UpdateOutputRecord(info, now);
    }
}

void ImageCodec::UpdateInputRecord(const BufferInfo& info, std::chrono::time_point<std::chrono::steady_clock> now)
{
    if (!info.IsValidFrame()) {
        return;
    }
    inTimeMap_[info.omxBuffer->pts] = now;
    if (inTotalCnt_ == 0) {
        firstInTime_ = now;
    }
    inTotalCnt_++;

    uint64_t fromFirstInToNow = chrono::duration_cast<chrono::microseconds>(now - firstInTime_).count();
    if (fromFirstInToNow == 0) {
        HLOGI("pts = %{public}" PRId64 ", len = %{public}u, flags = 0x%{public}x",
              info.omxBuffer->pts, info.omxBuffer->filledLen, info.omxBuffer->flag);
    } else {
        double inFps = inTotalCnt_ * US_TO_S / fromFirstInToNow;
        HLOGI("pts = %{public}" PRId64 ", len = %{public}u, flags = 0x%{public}x, in fps %{public}.2f",
              info.omxBuffer->pts, info.omxBuffer->filledLen, info.omxBuffer->flag, inFps);
    }
}

void ImageCodec::UpdateOutputRecord(const BufferInfo& info, std::chrono::time_point<std::chrono::steady_clock> now)
{
    if (!info.IsValidFrame()) {
        return;
    }
    auto it = inTimeMap_.find(info.omxBuffer->pts);
    if (it == inTimeMap_.end()) {
        return;
    }
    if (outRecord_.totalCnt == 0) {
        firstOutTime_ = now;
    }
    outRecord_.totalCnt++;

    uint64_t fromInToOut = chrono::duration_cast<chrono::microseconds>(now - it->second).count();
    inTimeMap_.erase(it);
    outRecord_.totalCostUs += fromInToOut;
    double oneFrameCostMs = fromInToOut / US_TO_MS;
    double averageCostMs = outRecord_.totalCostUs / US_TO_MS / outRecord_.totalCnt;

    uint64_t fromFirstOutToNow = chrono::duration_cast<chrono::microseconds>(now - firstOutTime_).count();
    if (fromFirstOutToNow == 0) {
        HLOGI("pts = %{public}" PRId64 ", len = %{public}u, flags = 0x%{public}x, "
              "cost %{public}.2f ms (%{public}.2f ms)",
              info.omxBuffer->pts, info.omxBuffer->filledLen, info.omxBuffer->flag,
              oneFrameCostMs, averageCostMs);
    } else {
        double outFps = outRecord_.totalCnt * US_TO_S / fromFirstOutToNow;
        HLOGI("pts = %{public}" PRId64 ", len = %{public}u, flags = 0x%{public}x, "
              "cost %{public}.2f ms (%{public}.2f ms), out fps %{public}.2f",
              info.omxBuffer->pts, info.omxBuffer->filledLen, info.omxBuffer->flag,
              oneFrameCostMs, averageCostMs, outFps);
    }
}

bool ImageCodec::BufferInfo::IsValidFrame() const
{
    if (omxBuffer->flag & OMX_BUFFERFLAG_EOS) {
        return false;
    }
    if (omxBuffer->flag & OMX_BUFFERFLAG_CODECCONFIG) {
        return false;
    }
    if (omxBuffer->filledLen == 0) {
        return false;
    }
    return true;
}

void ImageCodec::BufferInfo::Dump(const string& prefix, bool dumpMode) const
{
    if (!dumpMode) {
        return;
    }
    if (isInput) {
        Dump(prefix + "_Input");
    } else {
        Dump(prefix + "_Output");
    }
}

void ImageCodec::BufferInfo::Dump(const string& prefix) const
{
    if (surfaceBuffer) {
        DumpSurfaceBuffer(prefix);
    } else {
        DumpLinearBuffer(prefix);
    }
}

void ImageCodec::BufferInfo::DumpSurfaceBuffer(const std::string& prefix) const
{
    const char* va = reinterpret_cast<const char*>(surfaceBuffer->GetVirAddr());
    if (va == nullptr) {
        LOGW("surface buffer has null va");
        return;
    }
    bool eos = (omxBuffer->flag & OMX_BUFFERFLAG_EOS);
    if (eos || omxBuffer->filledLen == 0) {
        return;
    }
    int w = surfaceBuffer->GetWidth();
    int h = surfaceBuffer->GetHeight();
    int alignedW = surfaceBuffer->GetStride();
    uint32_t totalSize = surfaceBuffer->GetSize();
    if (w <= 0 || h <= 0 || alignedW <= 0 || w > alignedW) {
        LOGW("invalid buffer dimension");
        return;
    }
    std::optional<PixelFmt> fmt = TypeConverter::GraphicFmtToFmt(
        static_cast<GraphicPixelFormat>(surfaceBuffer->GetFormat()));
    if (fmt == nullopt) {
        LOGW("invalid fmt=%{public}d", surfaceBuffer->GetFormat());
        return;
    }

    char name[128];
    int ret = sprintf_s(name, sizeof(name), "%s/%s_%dx%d(%d)_fmt%s_pts%" PRId64 ".yuv",
                        DUMP_PATH, prefix.c_str(), w, h, alignedW, fmt->strFmt.c_str(), omxBuffer->pts);
    if (ret > 0) {
        ofstream ofs(name, ios::binary);
        if (ofs.is_open()) {
            ofs.write(va, totalSize);
        } else {
            LOGW("cannot open %{public}s", name);
        }
    }
    // if we unmap here, flush cache will fail
}

void ImageCodec::BufferInfo::DumpLinearBuffer(const string& prefix) const
{
    if (imgCodecBuffer == nullptr) {
        LOGW("invalid imgCodecBuffer");
        return;
    }
    const char* va = reinterpret_cast<const char*>(imgCodecBuffer->GetAddr());
    if (va == nullptr) {
        LOGW("null va");
        return;
    }
    bool eos = (omxBuffer->flag & OMX_BUFFERFLAG_EOS);
    if (eos || omxBuffer->filledLen == 0) {
        return;
    }

    char name[128];
    int ret = 0;
    if (isInput) {
        ret = sprintf_s(name, sizeof(name), "%s/%s.bin", DUMP_PATH, prefix.c_str());
    } else {
        ret = sprintf_s(name, sizeof(name), "%s/%s_(%d)_pts%" PRId64 ".yuv",
                        DUMP_PATH, prefix.c_str(), imgCodecBuffer->GetStride(), omxBuffer->pts);
    }
    if (ret <= 0) {
        LOGW("sprintf_s failed");
        return;
    }
    std::ios_base::openmode mode = isInput ? (ios::binary | ios::app) : ios::binary;
    ofstream ofs(name, mode);
    if (ofs.is_open()) {
        ofs.write(va, omxBuffer->filledLen);
    } else {
        LOGW("cannot open %{public}s", name);
    }
}
} // namespace OHOS::ImagePlugin