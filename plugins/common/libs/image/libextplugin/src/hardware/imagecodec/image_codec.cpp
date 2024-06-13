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

#include "hardware/imagecodec/image_codec.h"
#include "hardware/imagecodec/image_decoder.h"
#include "hardware/imagecodec/image_codec_list.h"
#include "hardware/imagecodec/image_codec_log.h"
#include "syspara/parameters.h" // base/startup/init/interfaces/innerkits/include/
#include "qos.h"

namespace OHOS::ImagePlugin {
using namespace std;
using namespace HdiCodecNamespace;

static bool IsSecureMode(const string &name)
{
    string prefix = ".secure";
    if (name.length() <= prefix.length()) {
        return false;
    }
    return (name.rfind(prefix) == (name.length() - prefix.length()));
}

shared_ptr<ImageCodec> ImageCodec::Create()
{
    vector<CodecCompCapability> capList = GetCapList();
    shared_ptr<ImageCodec> codec;
    string name;
    for (const auto& cap : capList) {
        if (cap.role == MEDIA_ROLETYPE_VIDEO_HEVC && cap.type == VIDEO_DECODER && !IsSecureMode(cap.compName)) {
            name = cap.compName;
            codec = make_shared<ImageDecoder>();
            break;
        }
    }
    if ((codec != nullptr) && (codec->InitWithName(name) == IC_ERR_OK)) {
        return codec;
    }
    return nullptr;
}

int32_t ImageCodec::SetCallback(const shared_ptr<ImageCodecCallback> &callback)
{
    HLOGI(">>");
    function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue("callback", callback);
    };
    return DoSyncCall(MsgWhat::SET_CALLBACK, proc);
}

int32_t ImageCodec::Configure(const Format &format)
{
    function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue("format", format);
    };
    return DoSyncCall(MsgWhat::CONFIGURE, proc);
}

int32_t ImageCodec::QueueInputBuffer(uint32_t index)
{
    function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue(BUFFER_ID, index);
    };
    return DoSyncCall(MsgWhat::QUEUE_INPUT_BUFFER, proc);
}

int32_t ImageCodec::ReleaseOutputBuffer(uint32_t index)
{
    function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue(BUFFER_ID, index);
    };
    return DoSyncCall(MsgWhat::RELEASE_OUTPUT_BUFFER, proc);
}

int32_t ImageCodec::GetInputFormat(Format& format)
{
    HLOGI(">>");
    ParamSP reply;
    int32_t ret = DoSyncCallAndGetReply(MsgWhat::GET_INPUT_FORMAT, nullptr, reply);
    if (ret != IC_ERR_OK) {
        HLOGE("failed to get input format");
        return ret;
    }
    IF_TRUE_RETURN_VAL_WITH_MSG(!reply->GetValue("format", format),
        IC_ERR_UNKNOWN, "input format not replied");
    return IC_ERR_OK;
}

int32_t ImageCodec::GetOutputFormat(Format& format)
{
    ParamSP reply;
    int32_t ret = DoSyncCallAndGetReply(MsgWhat::GET_OUTPUT_FORMAT, nullptr, reply);
    if (ret != IC_ERR_OK) {
        HLOGE("failed to get output format");
        return ret;
    }
    IF_TRUE_RETURN_VAL_WITH_MSG(!reply->GetValue("format", format),
        IC_ERR_UNKNOWN, "output format not replied");
    return IC_ERR_OK;
}

int32_t ImageCodec::Start()
{
    HLOGI(">>");
    return DoSyncCall(MsgWhat::START, nullptr);
}

int32_t ImageCodec::Release()
{
    HLOGI(">>");
    return DoSyncCall(MsgWhat::RELEASE, nullptr);
}

int32_t ImageCodec::GetOutputBufferUsage(uint64_t& usage)
{
    ParamSP reply;
    int32_t ret = DoSyncCallAndGetReply(MsgWhat::GET_OUTPUT_BUFFER_USAGE, nullptr, reply);
    if (ret != IC_ERR_OK) {
        HLOGE("failed to get output buffer usage");
        return ret;
    }
    IF_TRUE_RETURN_VAL_WITH_MSG(!reply->GetValue("usage", usage),
        IC_ERR_UNKNOWN, "output buffer usage not replied");
    return IC_ERR_OK;
}

int32_t ImageCodec::SetOutputBuffer(sptr<SurfaceBuffer> output)
{
    HLOGI(">>");
    std::function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue("output", output);
    };
    return DoSyncCall(MsgWhat::SET_OUTPUT_BUFFER, proc);
}
/**************************** public functions end ****************************/

ImageCodec::ImageCodec(OMX_VIDEO_CODINGTYPE codingType, bool isEncoder)
    : isEncoder_(isEncoder), codingType_(codingType)
{
    debugMode_ = OHOS::system::GetBoolParameter("image.codec.debug", false);
    dumpMode_ = OHOS::system::GetBoolParameter("image.codec.dump", false);
    LOGI(">> debug mode = %{public}d, dump mode = %{public}d", debugMode_, dumpMode_);

    uninitializedState_ = make_shared<UninitializedState>(this);
    initializedState_ = make_shared<InitializedState>(this);
    startingState_ = make_shared<StartingState>(this);
    runningState_ = make_shared<RunningState>(this);
    outputPortChangedState_ = make_shared<OutputPortChangedState>(this);
    stoppingState_ = make_shared<StoppingState>(this);
    StateMachine::ChangeStateTo(uninitializedState_);
}

ImageCodec::~ImageCodec()
{
    HLOGI(">>");
    MsgHandleLoop::Stop();
    ReleaseComponent();
}

int32_t ImageCodec::InitWithName(const string &name)
{
    function<void(ParamSP)> proc = [&](ParamSP msg) {
        msg->SetValue("name", name);
    };
    return DoSyncCall(MsgWhat::INIT, proc);
}

const char* ImageCodec::ToString(BufferOwner owner)
{
    switch (owner) {
        case BufferOwner::OWNED_BY_US:
            return "us";
        case BufferOwner::OWNED_BY_USER:
            return "user";
        case BufferOwner::OWNED_BY_OMX:
            return "omx";
        default:
            return "";
    }
}

const char* ImageCodec::ToString(MsgWhat what)
{
    static const map<MsgWhat, const char*> m = {
        { INIT,                    "INIT"                    },
        { SET_CALLBACK,            "SET_CALLBACK"            },
        { CONFIGURE,               "CONFIGURE"               },
        { START,                   "START"                   },
        { GET_INPUT_FORMAT,        "GET_INPUT_FORMAT"        },
        { GET_OUTPUT_FORMAT,       "GET_OUTPUT_FORMAT"       },
        { QUEUE_INPUT_BUFFER,      "QUEUE_INPUT_BUFFER"      },
        { RELEASE_OUTPUT_BUFFER,   "RELEASE_OUTPUT_BUFFER"   },
        { RELEASE,                 "RELEASE"                 },
        { GET_OUTPUT_BUFFER_USAGE, "GET_OUTPUT_BUFFER_USAGE" },
        { SET_OUTPUT_BUFFER,       "SET_OUTPUT_BUFFER"       },
        { CODEC_EVENT,             "CODEC_EVENT"             },
        { OMX_EMPTY_BUFFER_DONE,   "OMX_EMPTY_BUFFER_DONE"   },
        { OMX_FILL_BUFFER_DONE,    "OMX_FILL_BUFFER_DONE"    },
        { CHECK_IF_STUCK,          "CHECK_IF_STUCK"          },
        { FORCE_SHUTDOWN,          "FORCE_SHUTDOWN"          },
    };
    auto it = m.find(what);
    if (it != m.end()) {
        return it->second;
    }
    return "UNKNOWN";
}

void ImageCodec::ReplyErrorCode(MsgId id, int32_t err)
{
    if (id == ASYNC_MSG_ID) {
        return;
    }
    ParamSP reply = ParamBundle::Create();
    reply->SetValue("err", err);
    PostReply(id, reply);
}

bool ImageCodec::GetPixelFmtFromUser(const Format &format)
{
    is10Bit_ = false;
    optional<PixelFmt> fmt;
    int32_t graphicFmt;
    if (format.GetValue(ImageCodecDescriptionKey::PIXEL_FORMAT, graphicFmt)) {
        if (graphicFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
            is10Bit_ = true;
            graphicFmt = GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
        } else if (graphicFmt == GRAPHIC_PIXEL_FMT_YCRCB_P010) {
            is10Bit_ = true;
            graphicFmt = GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
        }
        fmt = TypeConverter::GraphicFmtToFmt(static_cast<GraphicPixelFormat>(graphicFmt));
    } else {
        HLOGE("pixel format unspecified");
        return false;
    }
    configuredFmt_ = fmt.value();
    HLOGI("configured pixel format is %{public}s", configuredFmt_.strFmt.c_str());
    return true;
}

optional<double> ImageCodec::GetFrameRateFromUser(const Format &format)
{
    double frameRate;
    if (format.GetValue(ImageCodecDescriptionKey::FRAME_RATE, frameRate) && frameRate > 0) {
        LOGI("user set frame rate %{public}.2f", frameRate);
        return frameRate;
    }
    return nullopt;
}

int32_t ImageCodec::SetFrameRateAdaptiveMode(const Format &format)
{
    if (!format.ContainKey(ImageCodecDescriptionKey::VIDEO_FRAME_RATE_ADAPTIVE_MODE)) {
        return IC_ERR_UNKNOWN;
    }

    WorkingFrequencyParam param {};
    InitOMXParamExt(param);
    if (!GetParameter(OMX_IndexParamWorkingFrequency, param)) {
        HLOGW("get working freq param failed");
        return IC_ERR_UNKNOWN;
    }
    HLOGI("level cnt is %{public}d, set level to %{public}d", param.level, param.level - 1);
    param.level = param.level - 1;

    if (!SetParameter(OMX_IndexParamWorkingFrequency, param)) {
        HLOGW("set working freq param failed");
        return IC_ERR_UNKNOWN;
    }
    return IC_ERR_OK;
}

int32_t ImageCodec::SetProcessName(const Format &format)
{
    string processName;
    if (!format.GetValue(ImageCodecDescriptionKey::PROCESS_NAME, processName)) {
        return IC_ERR_UNKNOWN;
    }
    HLOGI("processName name is %{public}s", processName.c_str());

    ProcessNameParam param {};
    InitOMXParamExt(param);
    if (strcpy_s(param.processName, sizeof(param.processName), processName.c_str()) != EOK) {
        HLOGW("strcpy failed");
        return IC_ERR_UNKNOWN;
    }
    if (!SetParameter(OMX_IndexParamProcessName, param)) {
        HLOGW("set process name failed");
        return IC_ERR_UNKNOWN;
    }
    return IC_ERR_OK;
}

int32_t ImageCodec::SetVideoPortInfo(OMX_DIRTYPE portIndex, const PortInfo& info)
{
    if (info.pixelFmt.has_value()) {
        CodecVideoPortFormatParam param;
        InitOMXParamExt(param);
        param.portIndex = portIndex;
        param.codecCompressFormat = info.codingType;
        param.codecColorFormat = info.pixelFmt->graphicFmt;
        param.framerate = info.frameRate * FRAME_RATE_COEFFICIENT;
        if (!SetParameter(OMX_IndexCodecVideoPortFormat, param)) {
            HLOGE("set port format failed");
            return IC_ERR_UNKNOWN;
        }
    }
    {
        OMX_PARAM_PORTDEFINITIONTYPE def;
        InitOMXParam(def);
        def.nPortIndex = portIndex;
        if (!GetParameter(OMX_IndexParamPortDefinition, def)) {
            HLOGE("get port definition failed");
            return IC_ERR_UNKNOWN;
        }
        def.format.video.nFrameWidth = info.width;
        def.format.video.nFrameHeight = info.height;
        def.format.video.eCompressionFormat = info.codingType;
        // we dont set eColorFormat here because it has been set by CodecVideoPortFormatParam
        def.format.video.xFramerate = info.frameRate * FRAME_RATE_COEFFICIENT;
        if (portIndex == OMX_DirInput && info.inputBufSize.has_value()) {
            def.nBufferSize = info.inputBufSize.value();
        }
        if (info.bufferCnt.has_value()) {
            def.nBufferCountActual = info.bufferCnt.value();
        }
        if (!SetParameter(OMX_IndexParamPortDefinition, def)) {
            HLOGE("set port definition failed");
            return IC_ERR_UNKNOWN;
        }
        if (portIndex == OMX_DirOutput) {
            if (outputFormat_ == nullptr) {
                outputFormat_ = make_shared<Format>();
            }
            outputFormat_->SetValue(ImageCodecDescriptionKey::FRAME_RATE, info.frameRate);
        }
    }
    
    return (portIndex == OMX_DirInput) ? UpdateInPortFormat() : UpdateOutPortFormat();
}

void ImageCodec::PrintPortDefinition(const OMX_PARAM_PORTDEFINITIONTYPE& def)
{
    const OMX_VIDEO_PORTDEFINITIONTYPE& video = def.format.video;
    HLOGI("----- %{public}s port definition -----", (def.nPortIndex == OMX_DirInput) ? "INPUT" : "OUTPUT");
    HLOGI("bEnabled %{public}d, bPopulated %{public}d", def.bEnabled, def.bPopulated);
    HLOGI("nBufferCountActual %{public}u, nBufferSize %{public}u", def.nBufferCountActual, def.nBufferSize);
    HLOGI("nFrameWidth x nFrameHeight (%{public}u x %{public}u), framerate %{public}u(%{public}.2f)",
        video.nFrameWidth, video.nFrameHeight, video.xFramerate, video.xFramerate / FRAME_RATE_COEFFICIENT);
    HLOGI("    nStride x nSliceHeight (%{public}u x %{public}u)", video.nStride, video.nSliceHeight);
    HLOGI("eCompressionFormat %{public}d(%{public}#x), eColorFormat %{public}d(%{public}#x)",
        video.eCompressionFormat, video.eCompressionFormat, video.eColorFormat, video.eColorFormat);
    HLOGI("----------------------------------");
}

int32_t ImageCodec::GetPortDefinition(OMX_DIRTYPE portIndex, OMX_PARAM_PORTDEFINITIONTYPE& def)
{
    InitOMXParam(def);
    def.nPortIndex = portIndex;
    if (!GetParameter(OMX_IndexParamPortDefinition, def)) {
        HLOGE("get %{public}s port definition failed", (portIndex == OMX_DirInput ? "input" : "output"));
        return IC_ERR_INVALID_VAL;
    }
    if (def.nBufferSize == 0 || def.nBufferSize > MAX_IMAGE_CODEC_BUFFER_SIZE) {
        HLOGE("invalid nBufferSize %{public}u", def.nBufferSize);
        return IC_ERR_INVALID_VAL;
    }
    PrintPortDefinition(def);
    return IC_ERR_OK;
}

int32_t ImageCodec::AllocateHardwareBuffers(OMX_DIRTYPE portIndex)
{
    HeifPerfTracker tracker(__FUNCTION__);
    OMX_PARAM_PORTDEFINITIONTYPE def;
    int32_t ret = GetPortDefinition(portIndex, def);
    IF_TRUE_RETURN_VAL(ret != IC_ERR_OK, ret);

    vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    pool.clear();
    for (uint32_t i = 0; i < def.nBufferCountActual; ++i) {
        shared_ptr<OmxCodecBuffer> omxBuffer = make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.version.majorVersion = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_DMA_MEM_FD;
        omxBuffer->fd = -1;
        omxBuffer->allocLen = def.nBufferSize;
        omxBuffer->fenceFd = -1;
        shared_ptr<OmxCodecBuffer> outBuffer = make_shared<OmxCodecBuffer>();
        ret = compNode_->AllocateBuffer(portIndex, *omxBuffer, *outBuffer);
        if (ret != HDF_SUCCESS) {
            HLOGE("Failed to AllocateBuffer on %{public}s port", (portIndex == OMX_DirInput ? "input" : "output"));
            return IC_ERR_INVALID_VAL;
        }
        shared_ptr<ImageCodecBuffer> imgCodecBuffer = ImageCodecBuffer::CreateDmaBuffer(outBuffer->fd,
            static_cast<int32_t>(def.nBufferSize), static_cast<int32_t>(def.format.video.nStride));
        if (imgCodecBuffer == nullptr || imgCodecBuffer->GetCapacity() != static_cast<int32_t>(def.nBufferSize)) {
            HLOGE("AllocateHardwareBuffers failed");
            return IC_ERR_NO_MEMORY;
        }
        BufferInfo bufInfo;
        bufInfo.isInput        = (portIndex == OMX_DirInput) ? true : false;
        bufInfo.owner          = BufferOwner::OWNED_BY_US;
        bufInfo.surfaceBuffer  = nullptr;
        bufInfo.imgCodecBuffer = imgCodecBuffer;
        bufInfo.omxBuffer      = outBuffer;
        bufInfo.bufferId       = outBuffer->bufferId;
        bufInfo.CleanUpUnusedInfo();
        pool.push_back(bufInfo);
    }
    return IC_ERR_OK;
}

int32_t ImageCodec::AllocateSurfaceBuffers(OMX_DIRTYPE portIndex, bool isOutputPortSettingChanged,
                                           sptr<SurfaceBuffer> output)
{
    HeifPerfTracker tracker(__FUNCTION__);
    OMX_PARAM_PORTDEFINITIONTYPE def;
    int32_t ret = GetPortDefinition(portIndex, def);
    if (ret != IC_ERR_OK) {
        return ret;
    }
    vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    pool.clear();
    bool canReuseOutputBuffer = (output != nullptr) && (!is10Bit_ || isOutputPortSettingChanged);
    for (uint32_t i = 0; i < def.nBufferCountActual; ++i) {
        shared_ptr<ImageCodecBuffer> imgCodecBuffer = canReuseOutputBuffer ?
            ImageCodecBuffer::CreateSurfaceBuffer(output) : ImageCodecBuffer::CreateSurfaceBuffer(requestCfg_);
        if (imgCodecBuffer == nullptr) {
            HLOGE("AllocateSurfaceBuffers failed");
            return IC_ERR_NO_MEMORY;
        }
        sptr<SurfaceBuffer> surfaceBuffer = imgCodecBuffer->GetSurfaceBuffer();
        IF_TRUE_RETURN_VAL_WITH_MSG(surfaceBuffer == nullptr, IC_ERR_INVALID_VAL, "failed to get surfacebuffer");
        shared_ptr<OmxCodecBuffer> omxBuffer = isEncoder_ ?
            DynamicSurfaceBufferToOmxBuffer() : SurfaceBufferToOmxBuffer(surfaceBuffer);
        IF_TRUE_RETURN_VAL(omxBuffer == nullptr, IC_ERR_INVALID_VAL);
        shared_ptr<OmxCodecBuffer> outBuffer = make_shared<OmxCodecBuffer>();
        int32_t hdiRet = compNode_->UseBuffer(portIndex, *omxBuffer, *outBuffer);
        if (hdiRet != HDF_SUCCESS) {
            HLOGE("Failed to UseBuffer on %{public}s port", (portIndex == OMX_DirInput ? "input" : "output"));
            return IC_ERR_INVALID_VAL;
        }
        BufferInfo bufInfo;
        bufInfo.isInput        = (portIndex == OMX_DirInput) ? true : false;
        bufInfo.owner          = BufferOwner::OWNED_BY_US;
        bufInfo.surfaceBuffer  = surfaceBuffer;
        bufInfo.imgCodecBuffer = imgCodecBuffer;
        bufInfo.omxBuffer      = outBuffer;
        bufInfo.bufferId       = outBuffer->bufferId;
        pool.push_back(bufInfo);
    }

    return IC_ERR_OK;
}

shared_ptr<OmxCodecBuffer> ImageCodec::SurfaceBufferToOmxBuffer(const sptr<SurfaceBuffer>& surfaceBuffer)
{
    BufferHandle* bufferHandle = surfaceBuffer->GetBufferHandle();
    IF_TRUE_RETURN_VAL_WITH_MSG(bufferHandle == nullptr, nullptr, "surfacebuffer has null bufferhandle");
    auto omxBuffer = make_shared<OmxCodecBuffer>();
    omxBuffer->size = sizeof(OmxCodecBuffer);
    omxBuffer->version.version.majorVersion = 1;
    omxBuffer->bufferType = CODEC_BUFFER_TYPE_HANDLE;
    omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    omxBuffer->fd = -1;
    omxBuffer->allocLen = surfaceBuffer->GetSize();
    omxBuffer->fenceFd = -1;
    return omxBuffer;
}

shared_ptr<OmxCodecBuffer> ImageCodec::DynamicSurfaceBufferToOmxBuffer()
{
    auto omxBuffer = make_shared<OmxCodecBuffer>();
    omxBuffer->size = sizeof(OmxCodecBuffer);
    omxBuffer->version.version.majorVersion = 1;
    omxBuffer->bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
    omxBuffer->fd = -1;
    omxBuffer->allocLen = 0;
    omxBuffer->fenceFd = -1;
    return omxBuffer;
}

ImageCodec::BufferInfo* ImageCodec::FindBufferInfoByID(OMX_DIRTYPE portIndex, uint32_t bufferId)
{
    vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    for (BufferInfo &info : pool) {
        if (info.bufferId == bufferId) {
            return &info;
        }
    }
    HLOGE("unknown buffer id %{public}u", bufferId);
    return nullptr;
}

optional<size_t> ImageCodec::FindBufferIndexByID(OMX_DIRTYPE portIndex, uint32_t bufferId)
{
    const vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    for (size_t i = 0; i < pool.size(); i++) {
        if (pool[i].bufferId == bufferId) {
            return i;
        }
    }
    HLOGE("unknown buffer id %{public}u", bufferId);
    return nullopt;
}

void ImageCodec::NotifyUserToFillThisInBuffer(BufferInfo &info)
{
    callback_->OnInputBufferAvailable(info.bufferId, info.imgCodecBuffer);
    ChangeOwner(info, BufferOwner::OWNED_BY_USER);
}

void ImageCodec::OnQueueInputBuffer(const MsgInfo &msg, BufferOperationMode mode)
{
    uint32_t bufferId;
    (void)msg.param->GetValue(BUFFER_ID, bufferId);
    BufferInfo* bufferInfo = FindBufferInfoByID(OMX_DirInput, bufferId);
    if (bufferInfo == nullptr) {
        ReplyErrorCode(msg.id, IC_ERR_INVALID_VAL);
        return;
    }
    if (bufferInfo->owner != BufferOwner::OWNED_BY_USER) {
        HLOGE("wrong ownership: buffer id=%{public}d, owner=%{public}s", bufferId, ToString(bufferInfo->owner));
        ReplyErrorCode(msg.id, IC_ERR_INVALID_VAL);
        return;
    }
    bufferInfo->imgCodecBuffer->GetBufferCirculateInfo(bufferInfo->omxBuffer->pts,
                                                       bufferInfo->omxBuffer->flag,
                                                       bufferInfo->omxBuffer->filledLen,
                                                       bufferInfo->omxBuffer->offset);
    ChangeOwner(*bufferInfo, BufferOwner::OWNED_BY_US);
    ReplyErrorCode(msg.id, IC_ERR_OK);
    OnQueueInputBuffer(mode, bufferInfo);
}

void ImageCodec::OnQueueInputBuffer(BufferOperationMode mode, BufferInfo* info)
{
    switch (mode) {
        case KEEP_BUFFER: {
            return;
        }
        case RESUBMIT_BUFFER: {
            if (inputPortEos_) {
                HLOGI("input already eos, keep this buffer");
                return;
            }
            bool eos = (info->omxBuffer->flag & OMX_BUFFERFLAG_EOS);
            if (!eos && info->omxBuffer->filledLen == 0) {
                HLOGI("this is not a eos buffer but not filled, ask user to re-fill it");
                NotifyUserToFillThisInBuffer(*info);
                return;
            }
            if (eos) {
                inputPortEos_ = true;
            }
            int32_t ret = NotifyOmxToEmptyThisInBuffer(*info);
            if (ret != IC_ERR_OK) {
                SignalError(IC_ERR_UNKNOWN);
            }
            return;
        }
        default: {
            HLOGE("SHOULD NEVER BE HERE");
            return;
        }
    }
}

int32_t ImageCodec::NotifyOmxToEmptyThisInBuffer(BufferInfo& info)
{
    info.Dump(compUniqueStr_, dumpMode_);
    info.EndCpuAccess();
    int32_t ret = compNode_->EmptyThisBuffer(*(info.omxBuffer));
    if (ret != HDF_SUCCESS) {
        HLOGE("EmptyThisBuffer failed");
        return IC_ERR_UNKNOWN;
    }
    ChangeOwner(info, BufferOwner::OWNED_BY_OMX);
    return IC_ERR_OK;
}

int32_t ImageCodec::NotifyOmxToFillThisOutBuffer(BufferInfo& info)
{
    info.omxBuffer->flag = 0;
    int32_t ret = compNode_->FillThisBuffer(*(info.omxBuffer));
    if (ret != HDF_SUCCESS) {
        HLOGE("outBufId = %{public}u failed", info.bufferId);
        return IC_ERR_UNKNOWN;
    }
    ChangeOwner(info, BufferOwner::OWNED_BY_OMX);
    return IC_ERR_OK;
}

void ImageCodec::OnOMXFillBufferDone(const OmxCodecBuffer& omxBuffer, BufferOperationMode mode)
{
    optional<size_t> idx = FindBufferIndexByID(OMX_DirOutput, omxBuffer.bufferId);
    if (!idx.has_value()) {
        return;
    }
    BufferInfo& info = outputBufferPool_[idx.value()];
    if (info.owner != BufferOwner::OWNED_BY_OMX) {
        HLOGE("wrong ownership: buffer id=%{public}d, owner=%{public}s", info.bufferId, ToString(info.owner));
        return;
    }
    info.omxBuffer->offset = omxBuffer.offset;
    info.omxBuffer->filledLen = omxBuffer.filledLen;
    info.omxBuffer->pts = omxBuffer.pts;
    info.omxBuffer->flag = omxBuffer.flag;
    ChangeOwner(info, BufferOwner::OWNED_BY_US);
    OnOMXFillBufferDone(mode, info, idx.value());
}

void ImageCodec::OnOMXFillBufferDone(BufferOperationMode mode, BufferInfo& info, size_t bufferIdx)
{
    switch (mode) {
        case KEEP_BUFFER:
            return;
        case RESUBMIT_BUFFER: {
            if (outputPortEos_) {
                HLOGI("output eos, keep this buffer");
                return;
            }
            bool eos = (info.omxBuffer->flag & OMX_BUFFERFLAG_EOS);
            if (!eos && info.omxBuffer->filledLen == 0) {
                HLOGI("it's not a eos buffer but not filled, ask omx to re-fill it");
                NotifyOmxToFillThisOutBuffer(info);
                return;
            }
            NotifyUserOutBufferAvaliable(info);
            if (eos) {
                outputPortEos_ = true;
            }
            return;
        }
        case FREE_BUFFER:
            EraseBufferFromPool(OMX_DirOutput, bufferIdx);
            return;
        default:
            HLOGE("SHOULD NEVER BE HERE");
            return;
    }
}

void ImageCodec::NotifyUserOutBufferAvaliable(BufferInfo &info)
{
    info.BeginCpuAccess();
    info.Dump(compUniqueStr_, dumpMode_);
    shared_ptr<OmxCodecBuffer> omxBuffer = info.omxBuffer;
    info.imgCodecBuffer->SetBufferCirculateInfo(omxBuffer->pts, omxBuffer->flag,
                                                omxBuffer->filledLen, omxBuffer->offset);
    callback_->OnOutputBufferAvailable(info.bufferId, info.imgCodecBuffer);
    ChangeOwner(info, BufferOwner::OWNED_BY_USER);
}

void ImageCodec::OnReleaseOutputBuffer(const MsgInfo &msg, BufferOperationMode mode)
{
    uint32_t bufferId;
    (void)msg.param->GetValue(BUFFER_ID, bufferId);
    optional<size_t> idx = FindBufferIndexByID(OMX_DirOutput, bufferId);
    if (!idx.has_value()) {
        ReplyErrorCode(msg.id, IC_ERR_INVALID_VAL);
        return;
    }
    BufferInfo& info = outputBufferPool_[idx.value()];
    if (info.owner != BufferOwner::OWNED_BY_USER) {
        HLOGE("wrong ownership: buffer id=%{public}d, owner=%{public}s", bufferId, ToString(info.owner));
        ReplyErrorCode(msg.id, IC_ERR_INVALID_VAL);
        return;
    }
    HLOGD("outBufId = %{public}u", bufferId);
    ChangeOwner(info, BufferOwner::OWNED_BY_US);
    ReplyErrorCode(msg.id, IC_ERR_OK);

    switch (mode) {
        case KEEP_BUFFER: {
            return;
        }
        case RESUBMIT_BUFFER: {
            if (outputPortEos_) {
                HLOGI("output eos, keep this buffer");
                return;
            }
            int32_t ret = NotifyOmxToFillThisOutBuffer(info);
            if (ret != IC_ERR_OK) {
                SignalError(IC_ERR_UNKNOWN);
            }
            return;
        }
        case FREE_BUFFER: {
            EraseBufferFromPool(OMX_DirOutput, idx.value());
            return;
        }
        default: {
            HLOGE("SHOULD NEVER BE HERE");
            return;
        }
    }
}

void ImageCodec::ReclaimBuffer(OMX_DIRTYPE portIndex, BufferOwner owner, bool erase)
{
    vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    for (size_t i = pool.size(); i > 0;) {
        i--;
        BufferInfo& info = pool[i];
        if (info.owner == owner) {
            ChangeOwner(info, BufferOwner::OWNED_BY_US);
            if (erase) {
                EraseBufferFromPool(portIndex, i);
            }
        }
    }
}

bool ImageCodec::IsAllBufferOwnedByUs(OMX_DIRTYPE portIndex)
{
    const vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    for (const BufferInfo& info : pool) {
        if (info.owner != BufferOwner::OWNED_BY_US) {
            return false;
        }
    }
    return true;
}

bool ImageCodec::IsAllBufferOwnedByUs()
{
    return IsAllBufferOwnedByUs(OMX_DirInput) && IsAllBufferOwnedByUs(OMX_DirOutput);
}

void ImageCodec::EraseOutBuffersOwnedByUs()
{
    // traverse index in reverse order because we need to erase index from vector
    for (size_t i = outputBufferPool_.size(); i > 0;) {
        i--;
        const BufferInfo& info = outputBufferPool_[i];
        if (info.owner == BufferOwner::OWNED_BY_US) {
            EraseBufferFromPool(OMX_DirOutput, i);
        }
    }
}

void ImageCodec::ClearBufferPool(OMX_DIRTYPE portIndex)
{
    const vector<BufferInfo>& pool = (portIndex == OMX_DirInput) ? inputBufferPool_ : outputBufferPool_;
    for (size_t i = pool.size(); i > 0;) {
        i--;
        EraseBufferFromPool(portIndex, i);
    }
}

void ImageCodec::FreeOmxBuffer(OMX_DIRTYPE portIndex, const BufferInfo& info)
{
    if (compNode_ && info.omxBuffer) {
        int32_t omxRet = compNode_->FreeBuffer(portIndex, *(info.omxBuffer));
        if (omxRet != HDF_SUCCESS) {
            HLOGW("notify omx to free buffer failed");
        }
    }
}

int32_t ImageCodec::DoSyncCall(MsgWhat msgType, function<void(ParamSP)> oper)
{
    ParamSP reply;
    return DoSyncCallAndGetReply(msgType, oper, reply);
}

int32_t ImageCodec::DoSyncCallAndGetReply(MsgWhat msgType, function<void(ParamSP)> oper, ParamSP &reply)
{
    ParamSP msg = ParamBundle::Create();
    IF_TRUE_RETURN_VAL_WITH_MSG(msg == nullptr, IC_ERR_NO_MEMORY, "out of memory");
    if (oper) {
        oper(msg);
    }
    bool ret = MsgHandleLoop::SendSyncMsg(msgType, msg, reply);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ret, IC_ERR_UNKNOWN, "wait msg %{public}d time out", msgType);
    int32_t err;
    IF_TRUE_RETURN_VAL_WITH_MSG(reply == nullptr || !reply->GetValue("err", err),
        IC_ERR_UNKNOWN, "error code of msg %{public}d not replied", msgType);
    return err;
}

void ImageCodec::ChangeOmxToTargetState(CodecStateType &state, CodecStateType targetState)
{
    int32_t ret = compNode_->SendCommand(CODEC_COMMAND_STATE_SET, targetState, {});
    if (ret != HDF_SUCCESS) {
        HLOGE("failed to change omx state, ret=%{public}d", ret);
        return;
    }

    int tryCnt = 0;
    do {
        if (tryCnt++ > 10) { // try up to 10 times
            HLOGE("failed to change to state(%{public}d), abort", targetState);
            state = CODEC_STATE_INVALID;
            break;
        }
        this_thread::sleep_for(10ms); // wait 10ms
        ret = compNode_->GetState(state);
        if (ret != HDF_SUCCESS) {
            HLOGE("failed to get omx state, ret=%{public}d", ret);
        }
    } while (ret == HDF_SUCCESS && state != targetState && state != CODEC_STATE_INVALID);
}

bool ImageCodec::RollOmxBackToLoaded()
{
    CodecStateType state;
    int32_t ret = compNode_->GetState(state);
    if (ret != HDF_SUCCESS) {
        HLOGE("failed to get omx node status(ret=%{public}d), can not perform state rollback", ret);
        return false;
    }
    HLOGI("current omx state (%{public}d)", state);
    switch (state) {
        case CODEC_STATE_EXECUTING: {
            ChangeOmxToTargetState(state, CODEC_STATE_IDLE);
            [[fallthrough]];
        }
        case CODEC_STATE_IDLE: {
            ChangeOmxToTargetState(state, CODEC_STATE_LOADED);
            [[fallthrough]];
        }
        case CODEC_STATE_LOADED:
        case CODEC_STATE_INVALID: {
            return true;
        }
        default: {
            HLOGE("invalid omx state: %{public}d", state);
            return false;
        }
    }
}

void ImageCodec::CleanUpOmxNode()
{
    if (compNode_ == nullptr) {
        return;
    }

    if (RollOmxBackToLoaded()) {
        for (const BufferInfo& info : inputBufferPool_) {
            FreeOmxBuffer(OMX_DirInput, info);
        }
        for (const BufferInfo& info : outputBufferPool_) {
            FreeOmxBuffer(OMX_DirOutput, info);
        }
    }
}

void ImageCodec::ReleaseComponent()
{
    CleanUpOmxNode();
    if (compMgr_ != nullptr) {
        compMgr_->DestroyComponent(componentId_);
    }
    compNode_ = nullptr;
    compCb_ = nullptr;
    compMgr_ = nullptr;
    componentId_ = 0;
    componentName_.clear();
}

int32_t ImageCodec::ForceShutdown(int32_t generation)
{
    if (generation != stateGeneration_) {
        HLOGE("ignoring stale force shutdown message: #%{public}d (now #%{public}d)",
            generation, stateGeneration_);
        return IC_ERR_OK;
    }
    HLOGI("force to shutdown");
    isShutDownFromRunning_ = true;
    notifyCallerAfterShutdownComplete_ = false;
    auto err = compNode_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
    if (err == HDF_SUCCESS) {
        ChangeStateTo(stoppingState_);
    }
    return IC_ERR_OK;
}

void ImageCodec::SignalError(ImageCodecError err)
{
    HLOGE("fatal error happened: errCode=%{public}d", err);
    hasFatalError_ = true;
    callback_->OnError(err);
}

void ImageCodec::DeferMessage(const MsgInfo &info)
{
    deferredQueue_.push_back(info);
}

void ImageCodec::ProcessDeferredMessages()
{
    for (const MsgInfo &info : deferredQueue_) {
        StateMachine::OnMsgReceived(info);
    }
    deferredQueue_.clear();
}

void ImageCodec::ReplyToSyncMsgLater(const MsgInfo& msg)
{
    syncMsgToReply_[msg.type].push(make_pair(msg.id, msg.param));
}

bool ImageCodec::GetFirstSyncMsgToReply(MsgInfo& msg)
{
    auto iter = syncMsgToReply_.find(msg.type);
    if (iter == syncMsgToReply_.end()) {
        return false;
    }
    tie(msg.id, msg.param) = iter->second.front();
    iter->second.pop();
    return true;
}

/**************************** HdiCallback functions begin ****************************/
int32_t ImageCodec::HdiCallback::EventHandler(CodecEventType event, const EventInfo &info)
{
    LOGI("event = %{public}d, data1 = %{public}u, data2 = %{public}u", event, info.data1, info.data2);
    ParamSP msg = ParamBundle::Create();
    msg->SetValue("event", event);
    msg->SetValue("data1", info.data1);
    msg->SetValue("data2", info.data2);
    codec_->SendAsyncMsg(MsgWhat::CODEC_EVENT, msg);
    return HDF_SUCCESS;
}

int32_t ImageCodec::HdiCallback::EmptyBufferDone(int64_t appData, const OmxCodecBuffer& buffer)
{
    ParamSP msg = ParamBundle::Create();
    msg->SetValue(BUFFER_ID, buffer.bufferId);
    codec_->SendAsyncMsg(MsgWhat::OMX_EMPTY_BUFFER_DONE, msg);
    return HDF_SUCCESS;
}

int32_t ImageCodec::HdiCallback::FillBufferDone(int64_t appData, const OmxCodecBuffer& buffer)
{
    ParamSP msg = ParamBundle::Create();
    msg->SetValue("omxBuffer", buffer);
    codec_->SendAsyncMsg(MsgWhat::OMX_FILL_BUFFER_DONE, msg);
    return HDF_SUCCESS;
}
/**************************** HdiCallback functions begin ****************************/

/**************************** BufferInfo functions begin ****************************/
void ImageCodec::BufferInfo::CleanUpUnusedInfo()
{
    if (omxBuffer == nullptr || omxBuffer->fd < 0) {
        return;
    }
    if (omxBuffer->fd == 0) {
        LOGW("fd of omxbuffer should never be 0");
    }
    close(omxBuffer->fd);
    omxBuffer->fd = -1;
}

void ImageCodec::BufferInfo::BeginCpuAccess()
{
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->InvalidateCache();
        if (err != GSERROR_OK) {
            LOGW("InvalidateCache failed, GSError=%{public}d", err);
        }
    }
}

void ImageCodec::BufferInfo::EndCpuAccess()
{
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->Map();
        if (err != GSERROR_OK) {
            LOGW("Map failed, GSError=%{public}d", err);
            return;
        }
        err = surfaceBuffer->FlushCache();
        if (err != GSERROR_OK) {
            LOGW("FlushCache failed, GSError=%{public}d", err);
        }
    }
}
/**************************** BufferInfo functions end ****************************/
} // namespace OHOS::ImagePlugin