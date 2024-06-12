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

#include "hardware/imagecodec/image_decoder.h"
#include "hardware/imagecodec/image_codec_log.h"
#include <cassert>
#include "codec_omx_ext.h" // drivers/peripheral/codec/interfaces/include/codec_omx_ext.h
#include "OMX_VideoExt.h" // third_party/openmax/api/1.1.2/OMX_VideoExt.h
#include "surface_buffer.h" // foundation/graphic/graphic_surface/interfaces/inner_api/surface/surface_buffer.h

namespace OHOS::ImagePlugin {
using namespace std;

ImageDecoder::ImageDecoder()
    : ImageCodec(static_cast<OMX_VIDEO_CODINGTYPE>(CODEC_OMX_VIDEO_CodingHEVC), false)
{}

int32_t ImageDecoder::OnConfigure(const Format &format)
{
    configFormat_ = make_shared<Format>(format);

    (void)format.GetValue(ImageCodecDescriptionKey::ENABLE_HEIF_GRID, enableHeifGrid_);

    UseBufferType useBufferTypes;
    InitOMXParamExt(useBufferTypes);
    useBufferTypes.portIndex = OMX_DirOutput;
    useBufferTypes.bufferType = CODEC_BUFFER_TYPE_HANDLE;
    if (!SetParameter(OMX_IndexParamUseBufferType, useBufferTypes)) {
        HLOGE("component don't support CODEC_BUFFER_TYPE_HANDLE");
        return IC_ERR_INVALID_VAL;
    }

    (void)SetProcessName(format);
    (void)SetFrameRateAdaptiveMode(format);
    return SetupPort(format);
}

int32_t ImageDecoder::SetupPort(const Format &format)
{
    uint32_t width;
    if (!format.GetValue(ImageCodecDescriptionKey::WIDTH, width) || width <= 0) {
        HLOGE("format should contain width");
        return IC_ERR_INVALID_VAL;
    }
    uint32_t height;
    if (!format.GetValue(ImageCodecDescriptionKey::HEIGHT, height) || height <= 0) {
        HLOGE("format should contain height");
        return IC_ERR_INVALID_VAL;
    }
    HLOGI("user set width %{public}u, height %{public}u", width, height);
    if (!GetPixelFmtFromUser(format)) {
        return IC_ERR_INVALID_VAL;
    }
    uint32_t inputBufferCnt = 0;
    (void)format.GetValue(ImageCodecDescriptionKey::INPUT_BUFFER_COUNT, inputBufferCnt);
    uint32_t outputBufferCnt = 0;
    (void)format.GetValue(ImageCodecDescriptionKey::OUTPUT_BUFFER_COUNT, outputBufferCnt);

    optional<double> frameRate = GetFrameRateFromUser(format);
    if (!frameRate.has_value()) {
        HLOGI("user don't set valid frame rate, use default 30.0");
        frameRate = 30.0;  // default frame rate 30.0
    }

    PortInfo inputPortInfo {width, height, codingType_, std::nullopt, frameRate.value()};
    int32_t maxInputSize = 0;
    (void)format.GetValue(ImageCodecDescriptionKey::MAX_INPUT_SIZE, maxInputSize);
    if (maxInputSize > 0) {
        inputPortInfo.inputBufSize = static_cast<uint32_t>(maxInputSize);
    }
    if (inputBufferCnt > 0) {
        inputPortInfo.bufferCnt = inputBufferCnt;
    }
    int32_t ret = SetVideoPortInfo(OMX_DirInput, inputPortInfo);
    if (ret != IC_ERR_OK) {
        return ret;
    }

    PortInfo outputPortInfo = {width, height, OMX_VIDEO_CodingUnused, configuredFmt_, frameRate.value()};
    if (outputBufferCnt > 0) {
        outputPortInfo.bufferCnt = outputBufferCnt;
    }
    ret = SetVideoPortInfo(OMX_DirOutput, outputPortInfo);
    if (ret != IC_ERR_OK) {
        return ret;
    }

    return IC_ERR_OK;
}

bool ImageDecoder::UpdateConfiguredFmt(OMX_COLOR_FORMATTYPE portFmt)
{
    auto graphicFmt = static_cast<GraphicPixelFormat>(portFmt);
    if (graphicFmt != configuredFmt_.graphicFmt) {
        optional<PixelFmt> fmt = TypeConverter::GraphicFmtToFmt(graphicFmt);
        if (!fmt.has_value()) {
            return false;
        }
        HLOGI("GraphicPixelFormat need update: configured(%{public}s) -> portdefinition(%{public}s)",
            configuredFmt_.strFmt.c_str(), fmt->strFmt.c_str());
        configuredFmt_ = fmt.value();
    }
    return true;
}

int32_t ImageDecoder::UpdateInPortFormat()
{
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParam(def);
    def.nPortIndex = OMX_DirInput;
    if (!GetParameter(OMX_IndexParamPortDefinition, def)) {
        HLOGE("get input port definition failed");
        return IC_ERR_UNKNOWN;
    }
    PrintPortDefinition(def);
    if (inputFormat_ == nullptr) {
        inputFormat_ = make_shared<Format>();
    }
    inputFormat_->SetValue(ImageCodecDescriptionKey::WIDTH, def.format.video.nFrameWidth);
    inputFormat_->SetValue(ImageCodecDescriptionKey::HEIGHT, def.format.video.nFrameHeight);
    return IC_ERR_OK;
}

int32_t ImageDecoder::UpdateOutPortFormat()
{
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParam(def);
    def.nPortIndex = OMX_DirOutput;
    if (!GetParameter(OMX_IndexParamPortDefinition, def)) {
        HLOGE("get output port definition failed");
        return IC_ERR_UNKNOWN;
    }
    PrintPortDefinition(def);
    if (def.nBufferCountActual == 0) {
        HLOGE("invalid bufferCount");
        return IC_ERR_UNKNOWN;
    }
    (void)UpdateConfiguredFmt(def.format.video.eColorFormat);

    uint32_t w = def.format.video.nFrameWidth;
    uint32_t h = def.format.video.nFrameHeight;

    // save into member variable
    requestCfg_.timeout = 0;
    requestCfg_.width = static_cast<int32_t>(w);
    requestCfg_.height = static_cast<int32_t>(h);
    requestCfg_.strideAlignment = STRIDE_ALIGNMENT;
    requestCfg_.format = configuredFmt_.graphicFmt;
    requestCfg_.usage = GetProducerUsage();
    UpdateDisplaySizeByCrop();

    // save into format
    if (outputFormat_ == nullptr) {
        outputFormat_ = make_shared<Format>();
    }
    if (!outputFormat_->ContainKey(ImageCodecDescriptionKey::WIDTH)) {
        outputFormat_->SetValue(ImageCodecDescriptionKey::WIDTH, w);
    }
    if (!outputFormat_->ContainKey(ImageCodecDescriptionKey::HEIGHT)) {
        outputFormat_->SetValue(ImageCodecDescriptionKey::HEIGHT, h);
    }
    outputFormat_->SetValue(ImageCodecDescriptionKey::VIDEO_DISPLAY_WIDTH, requestCfg_.width);
    outputFormat_->SetValue(ImageCodecDescriptionKey::VIDEO_DISPLAY_HEIGHT, requestCfg_.height);
    outputFormat_->SetValue(ImageCodecDescriptionKey::PIXEL_FORMAT,
        static_cast<int32_t>(configuredFmt_.graphicFmt));
    return IC_ERR_OK;
}

void ImageDecoder::UpdateColorAspects()
{
    CodecVideoColorspace param;
    InitOMXParamExt(param);
    param.portIndex = OMX_DirOutput;
    if (!GetParameter(OMX_IndexColorAspects, param, true)) {
        return;
    }
    HLOGI("range:%{public}d, primary:%{public}d, transfer:%{public}d, matrix:%{public}d)",
        param.aspects.range, param.aspects.primaries, param.aspects.transfer, param.aspects.matrixCoeffs);
    if (outputFormat_) {
        outputFormat_->SetValue(ImageCodecDescriptionKey::RANGE_FLAG, param.aspects.range);
        outputFormat_->SetValue(ImageCodecDescriptionKey::COLOR_PRIMARIES, param.aspects.primaries);
        outputFormat_->SetValue(ImageCodecDescriptionKey::TRANSFER_CHARACTERISTICS, param.aspects.transfer);
        outputFormat_->SetValue(ImageCodecDescriptionKey::MATRIX_COEFFICIENTS, param.aspects.matrixCoeffs);
        callback_->OnOutputFormatChanged(*(outputFormat_.get()));
    }
}

void ImageDecoder::UpdateDisplaySizeByCrop()
{
    OMX_CONFIG_RECTTYPE rect;
    InitOMXParam(rect);
    rect.nPortIndex = OMX_DirOutput;
    if (!GetParameter(OMX_IndexConfigCommonOutputCrop, rect, true)) {
        HLOGW("get crop failed, use default");
        return;
    }
    if (rect.nLeft < 0 || rect.nTop < 0 || rect.nWidth == 0 || rect.nHeight == 0 ||
        static_cast<int32_t>(rect.nLeft) + static_cast<int32_t>(rect.nWidth) > requestCfg_.width ||
        static_cast<int32_t>(rect.nTop) + static_cast<int32_t>(rect.nHeight) > requestCfg_.height) {
        HLOGW("wrong crop rect (%{public}d, %{public}d, %{public}u, %{public}u), use default",
              rect.nLeft, rect.nTop, rect.nWidth, rect.nHeight);
        return;
    }
    HLOGI("crop rect (%{public}d, %{public}d, %{public}u, %{public}u)",
          rect.nLeft, rect.nTop, rect.nWidth, rect.nHeight);
    requestCfg_.width = static_cast<int32_t>(rect.nWidth);
    requestCfg_.height = static_cast<int32_t>(rect.nHeight);
}

int32_t ImageDecoder::ReConfigureOutputBufferCnt()
{
    IF_TRUE_RETURN_VAL(enableHeifGrid_, IC_ERR_OK);
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParam(def);
    def.nPortIndex = OMX_DirOutput;
    IF_TRUE_RETURN_VAL_WITH_MSG(!GetParameter(OMX_IndexParamPortDefinition, def), IC_ERR_UNKNOWN,
                                "failed to get output port def");
    uint32_t outputBufferCnt = 0;
    (void)configFormat_->GetValue(ImageCodecDescriptionKey::OUTPUT_BUFFER_COUNT, outputBufferCnt);
    IF_TRUE_RETURN_VAL_WITH_MSG(outputBufferCnt == 0, IC_ERR_UNKNOWN, "failed to get output buffer cnt");
    def.nBufferCountActual = outputBufferCnt;
    IF_TRUE_RETURN_VAL_WITH_MSG(!SetParameter(OMX_IndexParamPortDefinition, def), IC_ERR_UNKNOWN,
                                "failed to set output port def");
    return IC_ERR_OK;
}

uint64_t ImageDecoder::GetProducerUsage()
{
    uint64_t producerUsage = BUFFER_MODE_REQUEST_USAGE;

    GetBufferHandleUsageParams vendorUsage;
    InitOMXParamExt(vendorUsage);
    vendorUsage.portIndex = static_cast<uint32_t>(OMX_DirOutput);
    if (GetParameter(OMX_IndexParamGetBufferHandleUsage, vendorUsage)) {
        HLOGI("vendor producer usage = 0x%" PRIx64 "", vendorUsage.usage);
        producerUsage |= vendorUsage.usage;
    }
    HLOGI("decoder producer usage = 0x%" PRIx64 "", producerUsage);
    return producerUsage;
}

uint64_t ImageDecoder::OnGetOutputBufferUsage()
{
    uint64_t usage = GetProducerUsage();
    usage |= BUFFER_USAGE_CPU_WRITE;
    return usage;
}

int32_t ImageDecoder::OnSetOutputBuffer(sptr<SurfaceBuffer> output)
{
    if (output == nullptr) {
        HLOGE("invalid output buffer");
        return IC_ERR_INVALID_VAL;
    }
    outputBuffer_ = output;
    return IC_ERR_OK;
}

bool ImageDecoder::ReadyToStart()
{
    if (callback_ == nullptr || outputFormat_ == nullptr || inputFormat_ == nullptr) {
        HLOGE("callback not set or format is not configured, can't start");
        return false;
    }
    if (enableHeifGrid_ && outputBuffer_ != nullptr) {
        HLOGE("can not set output buffer when heif grid is enabled");
        return false;
    }
    if (!enableHeifGrid_ && outputBuffer_ == nullptr) {
        HLOGE("must set output buffer when heif grid is not enabled");
        return false;
    }
    return true;
}

int32_t ImageDecoder::AllocateBuffersOnPort(OMX_DIRTYPE portIndex, bool isOutputPortSettingChanged)
{
    if (portIndex == OMX_DirInput) {
        return AllocateHardwareBuffers(portIndex);
    }
    int32_t ret = AllocateSurfaceBuffers(portIndex, isOutputPortSettingChanged, outputBuffer_);
    if (ret == IC_ERR_OK) {
        UpdateFormatFromSurfaceBuffer();
    }
    return ret;
}

void ImageDecoder::UpdateFormatFromSurfaceBuffer()
{
    if (outputBufferPool_.empty()) {
        return;
    }
    sptr<SurfaceBuffer> surfaceBuffer = outputBufferPool_.front().surfaceBuffer;
    if (surfaceBuffer == nullptr) {
        return;
    }
    outputFormat_->SetValue(ImageCodecDescriptionKey::VIDEO_DISPLAY_WIDTH, surfaceBuffer->GetWidth());
    outputFormat_->SetValue(ImageCodecDescriptionKey::VIDEO_DISPLAY_HEIGHT, surfaceBuffer->GetHeight());
    outputFormat_->SetValue(ImageCodecDescriptionKey::WIDTH, surfaceBuffer->GetStride());

    OMX_PARAM_PORTDEFINITIONTYPE def;
    int32_t ret = GetPortDefinition(OMX_DirOutput, def);
    int32_t sliceHeight = static_cast<int32_t>(def.format.video.nSliceHeight);
    if (ret == IC_ERR_OK && sliceHeight >= surfaceBuffer->GetHeight()) {
        outputFormat_->SetValue(ImageCodecDescriptionKey::HEIGHT, sliceHeight);
    }
}

int32_t ImageDecoder::SubmitAllBuffersOwnedByUs()
{
    HLOGI(">>");
    if (isBufferCirculating_) {
        HLOGI("buffer is already circulating, no need to do again");
        return IC_ERR_OK;
    }
    int32_t ret = SubmitOutputBuffersToOmxNode();
    if (ret != IC_ERR_OK) {
        return ret;
    }
    for (BufferInfo& info : inputBufferPool_) {
        if (info.owner == BufferOwner::OWNED_BY_US) {
            NotifyUserToFillThisInBuffer(info);
        }
    }
    isBufferCirculating_ = true;
    return IC_ERR_OK;
}

int32_t ImageDecoder::SubmitOutputBuffersToOmxNode()
{
    for (BufferInfo& info : outputBufferPool_) {
        switch (info.owner) {
            case BufferOwner::OWNED_BY_US: {
                int32_t ret = NotifyOmxToFillThisOutBuffer(info);
                if (ret != IC_ERR_OK) {
                    return ret;
                }
                continue;
            }
            case BufferOwner::OWNED_BY_OMX: {
                continue;
            }
            default: {
                HLOGE("buffer id %{public}u has invalid owner %{public}d", info.bufferId, info.owner);
                return IC_ERR_UNKNOWN;
            }
        }
    }
    return IC_ERR_OK;
}

void ImageDecoder::OnOMXEmptyBufferDone(uint32_t bufferId, BufferOperationMode mode)
{
    BufferInfo *info = FindBufferInfoByID(OMX_DirInput, bufferId);
    if (info == nullptr) {
        HLOGE("unknown buffer id %{public}u", bufferId);
        return;
    }
    if (info->owner != BufferOwner::OWNED_BY_OMX) {
        HLOGE("wrong ownership: buffer id=%{public}d, owner=%{public}s", bufferId, ToString(info->owner));
        return;
    }
    ChangeOwner(*info, BufferOwner::OWNED_BY_US);

    switch (mode) {
        case KEEP_BUFFER:
            return;
        case RESUBMIT_BUFFER: {
            if (!inputPortEos_) {
                NotifyUserToFillThisInBuffer(*info);
            }
            return;
        }
        default: {
            HLOGE("SHOULD NEVER BE HERE");
            return;
        }
    }
}

void ImageDecoder::EraseBufferFromPool(OMX_DIRTYPE portIndex, size_t i)
{
    vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    if (i >= pool.size()) {
        return;
    }
    BufferInfo& info = pool[i];
    FreeOmxBuffer(portIndex, info);
    pool.erase(pool.begin() + i);
}


} // namespace OHOS::ImagePlugin