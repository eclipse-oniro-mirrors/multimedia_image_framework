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
 
#include "hardware/heif_hw_decoder.h"
#include "hardware/imagecodec/image_codec_list.h"
#include "hardware/imagecodec/image_codec_log.h"
#include "hardware/imagecodec/type_converter.h"
#include "media_errors.h" // foundation/multimedia/image_framework/interfaces/innerkits/include/
#include "syspara/parameters.h" // base/startup/init/interfaces/innerkits/include/
#include <fstream>
#include <algorithm>
#include <climits>

namespace OHOS::ImagePlugin {
using namespace std;
using namespace HdiCodecNamespace;

bool GridInfo::IsValid() const
{
    IF_TRUE_RETURN_VAL_WITH_MSG((displayWidth == 0 || displayHeight == 0), false,
                                "invalid displaySize: [%{public}ux%{public}u]", displayWidth, displayHeight);
    IF_TRUE_RETURN_VAL(!enableGrid, true);
    IF_TRUE_RETURN_VAL_WITH_MSG((cols == 0 || rows == 0), false,
                                "invalid gridSize: [%{public}ux%{public}u]", cols, rows);
    IF_TRUE_RETURN_VAL_WITH_MSG((tileWidth == 0 || tileHeight == 0), false,
                                "invalid tileSize: [%{public}ux%{public}u]", tileWidth, tileHeight);
    uint32_t expCols = static_cast<uint32_t>(ceil(static_cast<float>(displayWidth) / static_cast<float>(tileWidth)));
    IF_TRUE_RETURN_VAL_WITH_MSG(expCols != cols, false,
                                "invalid cols, expect %{public}u, get %{public}u", expCols, cols);
    uint32_t expRows = static_cast<uint32_t>(ceil(static_cast<float>(displayHeight) / static_cast<float>(tileHeight)));
    IF_TRUE_RETURN_VAL_WITH_MSG(expRows != rows, false,
                                "invalid rows, expect %{public}u, get %{public}u", expRows, rows);
    return true;
}

HeifHardwareDecoder::HeifDecoderCallback::HeifDecoderCallback(HeifHardwareDecoder* heifDecoder)
    : heifDecoder_(heifDecoder)
{}

void HeifHardwareDecoder::HeifDecoderCallback::OnError(ImageCodecError err)
{
    heifDecoder_->SignalError();
}

void HeifHardwareDecoder::HeifDecoderCallback::OnOutputFormatChanged(const Format &format)
{}

void HeifHardwareDecoder::HeifDecoderCallback::OnInputBufferAvailable(uint32_t index,
                                                                      std::shared_ptr<ImageCodecBuffer> buffer)
{
    lock_guard<mutex> lk(heifDecoder_->inputMtx_);
    heifDecoder_->inputList_.emplace_back(index, buffer);
    heifDecoder_->inputCond_.notify_all();
}

void HeifHardwareDecoder::HeifDecoderCallback::OnOutputBufferAvailable(uint32_t index,
                                                                       std::shared_ptr<ImageCodecBuffer> buffer)
{
    lock_guard<mutex> lk(heifDecoder_->outputMtx_);
    heifDecoder_->outputList_.emplace_back(index, buffer);
    heifDecoder_->outputCond_.notify_all();
}

HeifHardwareDecoder::HeifHardwareDecoder() : uvOffsetForOutput_(0)
{
    heifDecoderImpl_ = ImageCodec::Create();
}

HeifHardwareDecoder::~HeifHardwareDecoder()
{
    if (releaseThread_.joinable()) {
        releaseThread_.join();
    }
    Reset();
}

sptr<SurfaceBuffer> HeifHardwareDecoder::AllocateOutputBuffer(uint32_t width, uint32_t height, int32_t pixelFmt)
{
    HeifPerfTracker tracker(__FUNCTION__);
    LOGI("BufferInfo: width=%{public}u, height=%{public}u, pixelFmt=%{public}d", width, height, pixelFmt);
    IF_TRUE_RETURN_VAL_WITH_MSG(heifDecoderImpl_ == nullptr, nullptr, "failed to create heif decoder");
    IF_TRUE_RETURN_VAL_WITH_MSG((width == 0 || height == 0), nullptr,
                                "invalid size=[%{public}ux%{public}u]", width, height);
    optional<PixelFmt> fmt = TypeConverter::GraphicFmtToFmt(static_cast<GraphicPixelFormat>(pixelFmt));
    IF_TRUE_RETURN_VAL(!fmt.has_value(), nullptr);

    uint64_t usage;
    int32_t err = heifDecoderImpl_->GetOutputBufferUsage(usage);
    IF_TRUE_RETURN_VAL_WITH_MSG(err != IC_ERR_OK, nullptr, "failed to get output buffer usage, err=%{public}d", err);
    sptr<SurfaceBuffer> output = SurfaceBuffer::Create();
    IF_TRUE_RETURN_VAL_WITH_MSG(output == nullptr, nullptr, "failed to create output");
    BufferRequestConfig config = {
        .width = width,
        .height = height,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = pixelFmt,
        .usage = usage,
        .timeout = 0
    };
    GSError ret = output->Alloc(config);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != GSERROR_OK, nullptr, "failed to alloc output, ret=%{public}d", ret);
    return output;
}

static bool IsValueInRange(uint32_t value, HdiCodecNamespace::RangeValue range)
{
    return (value >= static_cast<uint32_t>(range.min)) && (value <= static_cast<uint32_t>(range.max));
}

bool HeifHardwareDecoder::IsHardwareDecodeSupported(const GridInfo& gridInfo)
{
    string decoderName = heifDecoderImpl_->GetComponentName();
    vector<CodecCompCapability> capList = GetCapList();
    auto it = find_if(capList.begin(), capList.end(), [decoderName](const CodecCompCapability& cap) {
        return (cap.compName == decoderName);
    });
    if (it == capList.end()) {
        LOGE("can not find heif hw decoder");
        return false;
    }
    uint32_t widthToCheck = gridInfo.enableGrid ? gridInfo.tileWidth : gridInfo.displayWidth;
    uint32_t heightToCheck = gridInfo.enableGrid ? gridInfo.tileHeight : gridInfo.displayHeight;
    HdiCodecNamespace::RangeValue widthRange = {
        .min = it->port.video.minSize.width,
        .max = it->port.video.maxSize.width
    };
    HdiCodecNamespace::RangeValue heightRange = {
        .min = it->port.video.minSize.height,
        .max = it->port.video.maxSize.height
    };
    bool isValidSize = false;
    if (it->canSwapWidthHeight) {
        LOGI("decoder support swap width and height");
        isValidSize = (IsValueInRange(widthToCheck, widthRange) && IsValueInRange(heightToCheck, heightRange)) ||
                      (IsValueInRange(heightToCheck, widthRange) && IsValueInRange(widthToCheck, heightRange));
    } else {
        isValidSize = IsValueInRange(widthToCheck, widthRange) && IsValueInRange(heightToCheck, heightRange);
    }
    if (!isValidSize) {
        LOGE("unsupported size: [%{public}ux%{public}u]", widthToCheck, heightToCheck);
        return false;
    }
    return true;
}

bool HeifHardwareDecoder::SetCallbackForDecoder()
{
    HeifPerfTracker tracker(__FUNCTION__);
    shared_ptr<HeifDecoderCallback> cb = make_shared<HeifDecoderCallback>(this);
    int32_t ret = heifDecoderImpl_->SetCallback(cb);
    if (ret != IC_ERR_OK) {
        LOGE("failed to set callback for decoder, err=%{public}d", ret);
        return false;
    }
    return true;
}

bool HeifHardwareDecoder::ConfigureDecoder(const GridInfo& gridInfo, sptr<SurfaceBuffer>& output)
{
    HeifPerfTracker tracker(__FUNCTION__);
    Format format;
    if (gridInfo.enableGrid) {
        format.SetValue(ImageCodecDescriptionKey::WIDTH, gridInfo.tileWidth);
        format.SetValue(ImageCodecDescriptionKey::HEIGHT, gridInfo.tileHeight);
    } else {
        format.SetValue(ImageCodecDescriptionKey::WIDTH, gridInfo.displayWidth);
        format.SetValue(ImageCodecDescriptionKey::HEIGHT, gridInfo.displayHeight);
    }
    static constexpr double OUTPUT_FRAME_RATE = 120.0;
    format.SetValue(ImageCodecDescriptionKey::FRAME_RATE, OUTPUT_FRAME_RATE);
    format.SetValue(ImageCodecDescriptionKey::VIDEO_FRAME_RATE_ADAPTIVE_MODE, true);
    format.SetValue(ImageCodecDescriptionKey::PIXEL_FORMAT, output->GetFormat());
    format.SetValue(ImageCodecDescriptionKey::ENABLE_HEIF_GRID, gridInfo.enableGrid);
    if (!gridInfo.enableGrid) {
        static constexpr uint32_t INPUT_BUFFER_CNT_WHEN_NO_GRID = 3;
        format.SetValue(ImageCodecDescriptionKey::INPUT_BUFFER_COUNT, INPUT_BUFFER_CNT_WHEN_NO_GRID);
    }
    static constexpr uint32_t OUTPUT_BUFFER_CNT = 1;
    format.SetValue(ImageCodecDescriptionKey::OUTPUT_BUFFER_COUNT, OUTPUT_BUFFER_CNT);
    int32_t ret = heifDecoderImpl_->Configure(format);
    if (ret != IC_ERR_OK) {
        LOGE("failed to configure decoder, err=%{public}d", ret);
        return false;
    }
    return true;
}

bool HeifHardwareDecoder::SetOutputBuffer(const GridInfo& gridInfo, sptr<SurfaceBuffer> output)
{
    HeifPerfTracker tracker(__FUNCTION__);
    if (gridInfo.enableGrid) {
        return true;
    }
    int32_t ret = heifDecoderImpl_->SetOutputBuffer(output);
    if (ret != IC_ERR_OK) {
        LOGE("failed to set output buffer, err=%{public}d", ret);
        return false;
    }
    return true;
}

bool HeifHardwareDecoder::GetUvPlaneOffsetFromSurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer, uint64_t& offset)
{
    IF_TRUE_RETURN_VAL_WITH_MSG(surfaceBuffer == nullptr, false, "invalid surface buffer");
    OH_NativeBuffer_Planes* outputPlanes = nullptr;
    GSError ret = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&outputPlanes));
    IF_TRUE_RETURN_VAL_WITH_MSG((ret != GSERROR_OK || outputPlanes == nullptr), false,
                                "GetPlanesInfo failed, GSError=%{public}d", ret);
    IF_TRUE_RETURN_VAL_WITH_MSG(outputPlanes->planeCount < PLANE_BUTT, false,
                                "invalid yuv buffer, %{public}u", outputPlanes->planeCount);
    int32_t pixelFmt = surfaceBuffer->GetFormat();
    if (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_420_SP || pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
        offset = outputPlanes->planes[PLANE_U].offset;
    } else {
        offset = outputPlanes->planes[PLANE_V].offset;
    }
    return true;
}

void HeifHardwareDecoder::DumpSingleInput(const std::string& type, const GridInfo& gridInfo,
                                          const std::vector<std::vector<uint8_t>>& inputs)
{
    char inFilePath[MAX_PATH_LEN] = {0};
    int ret = -1;
    if (gridInfo.enableGrid) {
        ret = sprintf_s(inFilePath, sizeof(inFilePath), "%s/in_%s_%ux%u_grid_%ux%u_%ux%u.bin",
                        DUMP_PATH, type.c_str(), gridInfo.displayWidth, gridInfo.displayHeight,
                        gridInfo.tileWidth, gridInfo.tileHeight, gridInfo.cols, gridInfo.rows);
    } else {
        ret = sprintf_s(inFilePath, sizeof(inFilePath), "%s/in_%s_%ux%u_nogrid.bin",
                        DUMP_PATH, type.c_str(), gridInfo.displayWidth, gridInfo.displayHeight);
    }
    if (ret == -1) {
        LOGE("failed to dump input %{public}s", type.c_str());
        return;
    }
    char realpathRes[PATH_MAX] = {0};
    realpath(inFilePath, realpathRes);
    if (realpathRes == nullptr || !verify_file(realpathRes)) {
        LOGE("%{public}s is invalid", realpathRes);
        return;
    }
    std::ofstream dumpInFile;
    dumpInFile.open(std::string(realpathRes), std::ios_base::binary | std::ios_base::trunc);
    if (!dumpInFile.is_open()) {
        LOGE("failed to open %{public}s", realpathRes);
        return;
    }
    for (size_t i = 0; i < inputs.size(); ++i) {
        if ((i == 0) && (type == "data")) {
            continue;
        }
        const vector<uint8_t>& one = inputs[i];
        dumpInFile.write(reinterpret_cast<char*>(const_cast<uint8_t*>(one.data())), one.size());
        if ((i == 0) && (type == "xps")) {
            break;
        }
    }
    dumpInFile.close();
}

void HeifHardwareDecoder::DumpInput(const GridInfo& gridInfo, const std::vector<std::vector<uint8_t>>& inputs)
{
    DumpSingleInput("all", gridInfo, inputs);
    DumpSingleInput("xps", gridInfo, inputs);
    DumpSingleInput("data", gridInfo, inputs);
}

uint32_t HeifHardwareDecoder::DoDecode(const GridInfo& gridInfo, std::vector<std::vector<uint8_t>>& inputs,
                                       sptr<SurfaceBuffer>& output)
{
    LOGI("GridInfo: displayWidth=%{public}u, displayHeight=%{public}u, enableGrid=%{public}d, " \
         "cols=%{public}u, rows=%{public}u, tileWidth=%{public}u, tileHeight=%{public}u",
         gridInfo.displayWidth, gridInfo.displayHeight, gridInfo.enableGrid, gridInfo.cols, gridInfo.rows,
         gridInfo.tileWidth, gridInfo.tileHeight);
    HeifPerfTracker tracker(__FUNCTION__);
    IF_TRUE_RETURN_VAL(!gridInfo.IsValid(), Media::ERR_IMAGE_INVALID_PARAMETER);
    IF_TRUE_RETURN_VAL_WITH_MSG(output == nullptr, Media::ERR_IMAGE_INVALID_PARAMETER, "null output");
    IF_TRUE_RETURN_VAL_WITH_MSG(inputs.size() < MIN_SIZE_OF_INPUT, Media::ERR_IMAGE_INVALID_PARAMETER,
                                "input size < %{public}zu", MIN_SIZE_OF_INPUT);
    IF_TRUE_RETURN_VAL_WITH_MSG(heifDecoderImpl_ == nullptr, Media::ERR_IMAGE_DECODE_FAILED,
                                "failed to create heif decoder");
    if (OHOS::system::GetBoolParameter("image.codec.dump", false)) {
        DumpInput(gridInfo, inputs);
    }
    IF_TRUE_RETURN_VAL(!IsHardwareDecodeSupported(gridInfo), Media::ERR_IMAGE_HW_DECODE_UNSUPPORT);
    IF_TRUE_RETURN_VAL(!SetCallbackForDecoder(), Media::ERR_IMAGE_DECODE_FAILED);
    IF_TRUE_RETURN_VAL(!ConfigureDecoder(gridInfo, output), Media::ERR_IMAGE_DECODE_FAILED);
    IF_TRUE_RETURN_VAL(!SetOutputBuffer(gridInfo, output), Media::ERR_IMAGE_DECODE_FAILED);
    Reset();
    output_ = output;
    IF_TRUE_RETURN_VAL(!GetUvPlaneOffsetFromSurfaceBuffer(output_, uvOffsetForOutput_),
                       Media::ERR_IMAGE_DECODE_FAILED);
    gridInfo_ = gridInfo;
    thread inputThread(&HeifHardwareDecoder::SendInputBufferLoop, this, inputs);
    thread outputThread(&HeifHardwareDecoder::ReceiveOutputBufferLoop, this);
    int32_t ret = heifDecoderImpl_->Start();
    if (ret != IC_ERR_OK) {
        LOGE("failed to start decoder, err=%{public}d", ret);
        SignalError();
    }
    if (inputThread.joinable()) {
        inputThread.join();
    }
    if (outputThread.joinable()) {
        outputThread.join();
    }
    releaseThread_ = thread([this] {
        this->ReleaseDecoder();
    });
    IF_TRUE_RETURN_VAL_WITH_MSG(hasErr_, Media::ERR_IMAGE_DECODE_FAILED, "err occured during decode");
    FlushOutput();
    if (OHOS::system::GetBoolParameter("image.codec.dump", false)) {
        DumpOutput();
    }
    return Media::SUCCESS;
}

void HeifHardwareDecoder::ReleaseDecoder()
{
    HeifPerfTracker tracker(__FUNCTION__);
    int32_t ret = heifDecoderImpl_->Release();
    if (ret != IC_ERR_OK) {
        LOGE("failed to release decoder, err=%{public}d", ret);
    }
}

void HeifHardwareDecoder::Reset()
{
    hasErr_ = false;
    output_ = nullptr;
    inputList_.clear();
    outputList_.clear();
}

void HeifHardwareDecoder::FlushOutput()
{
    if (output_->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE) {
        GSError err = output_->Map();
        if (err != GSERROR_OK) {
            LOGW("Map failed, GSError=%{public}d", err);
            return;
        }
        err = output_->FlushCache();
        if (err != GSERROR_OK) {
            LOGW("FlushCache failed, GSError=%{public}d", err);
        }
    }
}

string HeifHardwareDecoder::GetOutputPixelFmtDesc()
{
    optional<PixelFmt> fmt = TypeConverter::GraphicFmtToFmt(static_cast<GraphicPixelFormat>(output_->GetFormat()));
    if (fmt.has_value()) {
        return fmt->strFmt;
    }
    return "unknown";
}

void HeifHardwareDecoder::DumpOutput()
{
    string pixelFmtDesc = GetOutputPixelFmtDesc();
    char outputFilePath[MAX_PATH_LEN] = {0};
    int ret = 0;
    if (gridInfo_.enableGrid) {
        ret = sprintf_s(outputFilePath, sizeof(outputFilePath), "%s/out_%s_%ux%u_grid_%ux%u_%ux%u.bin",
                        DUMP_PATH, pixelFmtDesc.c_str(), gridInfo_.displayWidth, gridInfo_.displayHeight,
                        gridInfo_.tileWidth, gridInfo_.tileHeight, gridInfo_.cols, gridInfo_.rows);
    } else {
        ret = sprintf_s(outputFilePath, sizeof(outputFilePath), "%s/out_%s_%ux%u_nogrid.bin",
                        DUMP_PATH, pixelFmtDesc.c_str(), gridInfo_.displayWidth, gridInfo_.displayHeight);
    }
    if (ret == -1) {
        LOGE("failed to create dump file");
        return;
    }
    LOGI("dump result to: %{public}s", outputFilePath);

    std::ofstream dumpOutFile;
    dumpOutFile.open(std::string(outputFilePath), std::ios_base::binary | std::ios_base::trunc);
    if (!dumpOutFile.is_open()) {
        LOGE("failed to dump decode result");
        return;
    }

    GSError err = output_->InvalidateCache();
    if (err != GSERROR_OK) {
        LOGW("InvalidateCache failed, GSError=%{public}d", err);
    }
    dumpOutFile.write(reinterpret_cast<char*>(output_->GetVirAddr()), output_->GetSize());
    dumpOutFile.close();
}

int64_t HeifHardwareDecoder::GetTimestampInUs()
{
    auto now = chrono::steady_clock::now();
    return chrono::duration_cast<chrono::microseconds>(now.time_since_epoch()).count();
}

int32_t HeifHardwareDecoder::PrepareInputCodecBuffer(const vector<vector<uint8_t>>& inputs, size_t inputIndex,
                                                     shared_ptr<ImageCodecBuffer>& buffer)
{
    HeifPerfTracker tracker(__FUNCTION__);
    int64_t pts = GetTimestampInUs();
    if (inputIndex >= inputs.size()) {
        buffer->SetBufferCirculateInfo(pts, OMX_BUFFERFLAG_EOS, 0, 0);
        return 0;
    }
    const vector<uint8_t>& one = inputs[inputIndex];
    if (one.empty()) {
        LOGW("inputs[%{public}zu] is empty", inputIndex);
        return -1;
    }
    errno_t ret = memcpy_s(buffer->GetAddr(), static_cast<size_t>(buffer->GetCapacity()), one.data(), one.size());
    if (ret != EOK) {
        LOGE("failed to get input");
        return -1;
    }
    uint32_t flag = inputIndex == 0 ? OMX_BUFFERFLAG_CODECCONFIG : 0;
    int32_t size = static_cast<int32_t>(one.size());
    buffer->SetBufferCirculateInfo(pts, flag, static_cast<uint32_t>(size), 0);
    return size;
}

bool HeifHardwareDecoder::WaitForOmxToReturnInputBuffer(uint32_t& bufferId, shared_ptr<ImageCodecBuffer>& buffer)
{
    unique_lock<mutex> lk(inputMtx_);
    bool ret = inputCond_.wait_for(lk, chrono::milliseconds(BUFFER_CIRCULATE_TIMEOUT_IN_MS), [this] {
        return !inputList_.empty();
    });
    if (!ret) {
        return false;
    }
    std::tie(bufferId, buffer) = inputList_.front();
    inputList_.pop_front();
    return true;
}

void HeifHardwareDecoder::SendInputBufferLoop(const vector<vector<uint8_t>>& inputs)
{
    LOGI("in");
    size_t inputIndex = 0;
    bool eos = false;
    while (!eos && !HasError()) {
        uint32_t bufferId;
        shared_ptr<ImageCodecBuffer> buffer;
        if (!WaitForOmxToReturnInputBuffer(bufferId, buffer)) {
            LOGE("input time out");
            continue;
        }
        if (buffer == nullptr) {
            LOGE("got null input buffer");
            break;
        }
        int32_t size = PrepareInputCodecBuffer(inputs, inputIndex, buffer);
        if (size >= 0) {
            int32_t ret = heifDecoderImpl_->QueueInputBuffer(bufferId);
            if (ret != IC_ERR_OK) {
                LOGE("failed to queue input buffer");
            }
        }
        ++inputIndex;
        eos = (size == 0);
    }
    LOGI("out");
}

bool HeifHardwareDecoder::WaitForOmxToReturnOutputBuffer(uint32_t& bufferId, shared_ptr<ImageCodecBuffer>& buffer)
{
    unique_lock<mutex> lk(outputMtx_);
    bool ret = outputCond_.wait_for(lk, chrono::milliseconds(BUFFER_CIRCULATE_TIMEOUT_IN_MS), [this] {
        return !outputList_.empty();
    });
    if (!ret) {
        return false;
    }
    std::tie(bufferId, buffer) = outputList_.front();
    outputList_.pop_front();
    return true;
}

bool HeifHardwareDecoder::CopyRawYuvData(const RawYuvCopyInfo& src, const RawYuvCopyInfo& dst,
                                         uint32_t dirtyWidth, uint32_t dirtyHeight)
{
    IF_TRUE_RETURN_VAL_WITH_MSG((dst.yStart == nullptr || dst.uvStart == nullptr),
                                false, "can not get addr from dst buffer");
    IF_TRUE_RETURN_VAL_WITH_MSG((src.yStart == nullptr || src.uvStart == nullptr),
                                false, "can not get addr from src buffer");
    errno_t ret = EOK;
    // copy Y plane
    for (uint32_t row = 0; (row < dirtyHeight) && (ret == EOK); ++row) {
        ret = memcpy_s(dst.yStart + dst.yOffset + row * dst.stride, static_cast<size_t>(dirtyWidth),
                       src.yStart + src.yOffset + row * src.stride, static_cast<size_t>(dirtyWidth));
    }
    // copy UV plane
    uint32_t dirtyHeightForUvPlane = (dirtyHeight + SAMPLE_RATIO_FOR_YUV420_SP - 1) / SAMPLE_RATIO_FOR_YUV420_SP;
    for (uint32_t row = 0; (row < dirtyHeightForUvPlane) && (ret == EOK); ++row) {
        ret = memcpy_s(dst.uvStart + dst.uvOffset + row * dst.stride, static_cast<size_t>(dirtyWidth),
                       src.uvStart + src.uvOffset + row * src.stride, static_cast<size_t>(dirtyWidth));
    }
    if (ret != EOK) {
        LOGE("failed to copy grid data, err=%{public}d", ret);
        return false;
    }
    return true;
}

uint32_t HeifHardwareDecoder::CalculateDirtyLen(uint32_t displayLen, uint32_t gridLen,
                                                uint32_t totalGrid, uint32_t curGrid)
{
    uint32_t dirtyLen = 0;
    if (gridLen >= displayLen) {
        dirtyLen = displayLen;
    } else {
        dirtyLen = gridLen;
        if (curGrid + 1 == totalGrid) {
            dirtyLen = displayLen - curGrid * gridLen;
        }
    }
    return dirtyLen;
}

void HeifHardwareDecoder::AssembleOutput(uint32_t outputIndex, shared_ptr<ImageCodecBuffer>& buffer)
{
    HeifPerfTracker tracker(__FUNCTION__);

    uint64_t srcUvOffset = 0;
    sptr<SurfaceBuffer> srcSurfaceBuffer = buffer->GetSurfaceBuffer();
    if (!GetUvPlaneOffsetFromSurfaceBuffer(srcSurfaceBuffer, srcUvOffset)) {
        SignalError();
        return;
    }

    RawYuvCopyInfo dst;
    dst.yStart = static_cast<uint8_t*>(output_->GetVirAddr());
    dst.stride = static_cast<uint32_t>(output_->GetStride());
    dst.uvStart = dst.yStart + uvOffsetForOutput_;
    dst.yStride = static_cast<uint32_t>(uvOffsetForOutput_ / static_cast<uint64_t>(dst.stride));
    RawYuvCopyInfo src;
    src.yStart = buffer->GetAddr();
    src.stride = static_cast<uint32_t>(buffer->GetStride());
    src.uvStart = src.yStart + srcUvOffset;
    src.yStride = static_cast<uint32_t>(srcUvOffset / static_cast<uint64_t>(src.stride));
    src.yOffset = 0;
    src.uvOffset = 0;

    uint32_t decodedRows = outputIndex / gridInfo_.cols;
    uint32_t decodedCols = outputIndex % gridInfo_.cols;
    uint32_t dirtyWidth = CalculateDirtyLen(dst.stride, src.stride, gridInfo_.cols, decodedCols);
    uint32_t dirtyHeight = CalculateDirtyLen(dst.yStride, src.yStride, gridInfo_.rows, decodedRows);
    dst.yOffset = decodedRows * dst.stride * gridInfo_.tileHeight + decodedCols * src.stride;
    dst.uvOffset = decodedRows * dst.stride * gridInfo_.tileHeight / SAMPLE_RATIO_FOR_YUV420_SP +
                   decodedCols * src.stride;

    if (!CopyRawYuvData(src, dst, dirtyWidth, dirtyHeight)) {
        LOGE("failed to assemble output(grid=%{public}d))", outputIndex);
        SignalError();
    }
}

void HeifHardwareDecoder::ReceiveOutputBufferLoop()
{
    LOGI("in");
    uint32_t outputIndex = 0;
    while (!HasError()) {
        uint32_t bufferId;
        shared_ptr<ImageCodecBuffer> buffer;
        if (!WaitForOmxToReturnOutputBuffer(bufferId, buffer)) {
            LOGE("output time out");
            continue;
        }
        if (buffer == nullptr) {
            LOGE("null output buffer");
            break;
        }
        uint32_t flag = buffer->GetBufferFlag();
        if (flag & OMX_BUFFERFLAG_EOS) {
            LOGI("output eos, quit loop");
            break;
        }
        if (gridInfo_.enableGrid) {
            AssembleOutput(outputIndex, buffer);
        }
        ++outputIndex;
        int32_t ret = heifDecoderImpl_->ReleaseOutputBuffer(bufferId);
        if (ret != IC_ERR_OK) {
            LOGE("failed to release output buffer");
        }
    }
    LOGI("out");
}

void HeifHardwareDecoder::SignalError()
{
    std::lock_guard<std::mutex> lk(errMtx_);
    hasErr_ = true;
}

bool HeifHardwareDecoder::HasError()
{
    std::lock_guard<std::mutex> lk(errMtx_);
    return hasErr_;
}
} // namespace OHOS::ImagePlugin