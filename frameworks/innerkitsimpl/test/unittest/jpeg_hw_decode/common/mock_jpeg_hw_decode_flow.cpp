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

#include <fstream>
#include <map>
#include <securec.h>
#include "ext_stream.h"
#include "file_source_stream.h"
#include "v1_0/display_buffer_type.h"
#include "mock_jpeg_hw_decode_flow.h"

namespace OHOS::ImagePlugin {
using namespace OHOS::HDI::Codec::Image::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;

JpegHwDecoderFlow::JpegHwDecoderFlow() : sampleSize_(1), outputColorFmt_(PIXEL_FMT_YCRCB_420_SP)
{
    bufferMgr_ = IDisplayBuffer::Get();
    outputBuffer_.id = 0;
    outputBuffer_.size = 0;
    outputBuffer_.buffer = nullptr;
    outputBuffer_.fenceFd = -1;
    outputBuffer_.bufferRole = CODEC_IMAGE_JPEG;
}

JpegHwDecoderFlow::~JpegHwDecoderFlow()
{
    bufferMgr_ = nullptr;
}

bool JpegHwDecoderFlow::AllocOutputBuffer()
{
    AllocInfo alloc = {
        .width = scaledImgSize_.width,
        .height = scaledImgSize_.height,
        .usage =  HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
        .format = outputColorFmt_
    };
    BufferHandle *handle = nullptr;
    int32_t ret = bufferMgr_->AllocMem(alloc, handle);
    if (ret != HDF_SUCCESS) {
        JPEG_HW_LOGE("failed to alloc output buffer, err=%{public}d", ret);
        return false;
    }
    if (outputColorFmt_ == PIXEL_FMT_RGBA_8888) {
        static constexpr uint32_t bitDepthForRgba = 4;
        outputBufferSize_.width = static_cast<uint32_t>(handle->stride) / bitDepthForRgba;
    } else { // PIXEL_FMT_YCRCB_420_SP
        outputBufferSize_.width = static_cast<uint32_t>(handle->stride);
    }
    outputBufferSize_.height = static_cast<uint32_t>(handle->height);
    outputBuffer_.buffer = new NativeBuffer(handle);
    return true;
}

bool JpegHwDecoderFlow::DoDecode()
{
    std::unique_ptr<Media::SourceStream> stream = Media::FileSourceStream::CreateSourceStream(inputFile_);
    ImagePlugin::InputDataStream* inputStream = stream.get();
    std::unique_ptr<SkCodec> demoCodec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(inputStream));
    JpegHardwareDecoder hwDecoder;
    auto ret = hwDecoder.Decode(demoCodec.get(), inputStream, orgImgSize_, sampleSize_, outputBuffer_);
    if (ret != 0) {
        JPEG_HW_LOGE("failed to do jpeg hardware decode, err=%{public}u", ret);
        return false;
    }
    return true;
}

bool JpegHwDecoderFlow::DumpDecodeResult()
{
    JPEG_HW_LOGI("dump decode result");
    auto getColorDesc = [this]()->std::string {
        if (outputColorFmt_ == PIXEL_FMT_YCRCB_420_SP) {
            return "YUV";
        } else if (outputColorFmt_ == PIXEL_FMT_RGBA_8888) {
            return "RGB";
        }
        return "UnknownColorFormat";
    };

    constexpr int maxPathLen = 256;
    char outputFilePath[maxPathLen] = {0};
    std::string colorDesc = getColorDesc();
    int ret = sprintf_s(outputFilePath, sizeof(outputFilePath), "%s/out_%u(%u)x%u_org_%ux%u_%s.bin",
                        outputPath_.c_str(), scaledImgSize_.width, outputBufferSize_.width, scaledImgSize_.height,
                        orgImgSize_.width, orgImgSize_.height, colorDesc.c_str());
    if (ret == -1) {
        JPEG_HW_LOGE("failed to create dump file");
        return false;
    }

    std::ofstream dumpOutFile;
    dumpOutFile.open(std::string(outputFilePath), std::ios_base::binary | std::ios_base::trunc);
    if (!dumpOutFile.is_open()) {
        JPEG_HW_LOGE("failed to dump decode result");
        return false;
    }

    BufferHandle *outputHandle = outputBuffer_.buffer->GetBufferHandle();
    bufferMgr_->Mmap(*outputHandle);
    (void)bufferMgr_->InvalidateCache(*outputHandle);
    dumpOutFile.write(reinterpret_cast<char*>(outputHandle->virAddr), outputHandle->size);
    dumpOutFile.flush();
    (void)bufferMgr_->FlushCache(*outputHandle);
    (void)bufferMgr_->Unmap(*outputHandle);
    dumpOutFile.close();
    return true;
}

std::optional<PixelFormat> JpegHwDecoderFlow::UserColorFmtToPixelFmt(UserColorFormat usrColorFmt)
{
    static const std::map<UserColorFormat, PixelFormat> colorMap = {
        { UserColorFormat::YUV, PIXEL_FMT_YCRCB_420_SP },
        { UserColorFormat::RGB, PIXEL_FMT_RGBA_8888 }
    };
    auto iter = colorMap.find(usrColorFmt);
    if (iter == colorMap.end()) {
        JPEG_HW_LOGE("unsupported color format(%{public}d)", static_cast<int>(usrColorFmt));
        return std::nullopt;
    }
    return iter->second;
}

bool JpegHwDecoderFlow::Run(const CommandOpt& opt, bool needDumpOutput)
{
    JPEG_HW_LOGI("jpeg hardware decode demo start");
    std::optional<PixelFormat> colorFmt = UserColorFmtToPixelFmt(opt.colorFmt);
    if (!colorFmt.has_value()) {
        JPEG_HW_LOGE("jpeg hardware decode demo failed");
        return false;
    }
    inputFile_ = opt.inputFile;
    outputPath_ = opt.outputPath;
    outputColorFmt_ = colorFmt.value();
    orgImgSize_.width = opt.width;
    orgImgSize_.height = opt.height;
    sampleSize_ = opt.sampleSize;
    scaledImgSize_.width = AlignUp(opt.width / opt.sampleSize, ALIGN_8);
    scaledImgSize_.height = AlignUp(opt.height / opt.sampleSize, ALIGN_8);
    JPEG_HW_LOGD("orgImgSize=[%{public}ux%{public}u], scaledImgSize=[%{public}ux%{public}u], sampleSize=%{public}u",
                 orgImgSize_.width, orgImgSize_.height, scaledImgSize_.width, scaledImgSize_.height, sampleSize_);

    bool ret = AllocOutputBuffer();
    ret = ret && DoDecode();
    if (needDumpOutput) {
        ret = ret && DumpDecodeResult();
    }
    if (ret) {
        JPEG_HW_LOGI("jpeg hardware decode demo succeed");
    } else {
        JPEG_HW_LOGE("jpeg hardware decode demo failed");
    }
    return ret;
}
} // namespace OHOS::ImagePlugin