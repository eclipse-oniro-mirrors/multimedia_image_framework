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
#include "hardware/imagecodec/image_codec_list.h"
#include "hardware/imagecodec/image_codec_log.h"

namespace OHOS::ImagePlugin {
using namespace std;
using namespace HdiCodecNamespace;

/**************************** BaseState Start ****************************/
void ImageCodec::BaseState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::CODEC_EVENT: {
            OnCodecEvent(info);
            return;
        }
        case MsgWhat::OMX_EMPTY_BUFFER_DONE: {
            uint32_t bufferId;
            (void)info.param->GetValue(BUFFER_ID, bufferId);
            codec_->OnOMXEmptyBufferDone(bufferId, inputMode_);
            return;
        }
        case MsgWhat::OMX_FILL_BUFFER_DONE: {
            OmxCodecBuffer omxBuffer;
            (void)info.param->GetValue("omxBuffer", omxBuffer);
            codec_->OnOMXFillBufferDone(omxBuffer, outputMode_);
            return;
        }
        case MsgWhat::GET_INPUT_FORMAT:
        case MsgWhat::GET_OUTPUT_FORMAT: {
            OnGetFormat(info);
            return;
        }
        case MsgWhat::RELEASE: {
            OnShutDown(info);
            return;
        }
        default: {
            const char* msgWhat = ImageCodec::ToString(static_cast<MsgWhat>(info.type));
            if (info.id == ASYNC_MSG_ID) {
                SLOGI("ignore msg %{public}s in current state", msgWhat);
            } else { // Make sure that all sync message are replied
                SLOGE("%{public}s cannot be called at this state", msgWhat);
                ReplyErrorCode(info.id, IC_ERR_INVALID_STATE);
            }
            return;
        }
    }
}

void ImageCodec::BaseState::ReplyErrorCode(MsgId id, int32_t err)
{
    if (id == ASYNC_MSG_ID) {
        return;
    }
    ParamSP reply = ParamBundle::Create();
    reply->SetValue("err", err);
    codec_->PostReply(id, reply);
}

void ImageCodec::BaseState::OnCodecEvent(const MsgInfo &info)
{
    CodecEventType event{};
    uint32_t data1;
    uint32_t data2;
    (void)info.param->GetValue("event", event);
    (void)info.param->GetValue("data1", data1);
    (void)info.param->GetValue("data2", data2);
    if (event == CODEC_EVENT_CMD_COMPLETE &&
        data1 == static_cast<uint32_t>(CODEC_COMMAND_FLUSH) &&
        data2 == static_cast<uint32_t>(OMX_ALL)) {
        SLOGD("ignore flush all complete event");
    } else {
        OnCodecEvent(event, data1, data2);
    }
}

void ImageCodec::BaseState::OnCodecEvent(CodecEventType event, uint32_t data1, uint32_t data2)
{
    if (event == CODEC_EVENT_ERROR) {
        SLOGE("omx report error event, data1 = %{public}u, data2 = %{public}u", data1, data2);
        codec_->SignalError(IC_ERR_SERVICE_DIED);
    } else {
        SLOGW("ignore event %{public}d, data1 = %{public}u, data2 = %{public}u", event, data1, data2);
    }
}

void ImageCodec::BaseState::OnGetFormat(const MsgInfo &info)
{
    shared_ptr<Format> fmt = (info.type == MsgWhat::GET_INPUT_FORMAT) ?
        codec_->inputFormat_ : codec_->outputFormat_;
    ParamSP reply = ParamBundle::Create();
    if (fmt) {
        reply->SetValue<int32_t>("err", IC_ERR_OK);
        reply->SetValue("format", *fmt);
        codec_->PostReply(info.id, reply);
    } else {
        ReplyErrorCode(info.id, IC_ERR_UNKNOWN);
    }
}

void ImageCodec::BaseState::OnCheckIfStuck(const MsgInfo &info)
{
    int32_t generation;
    (void)info.param->GetValue("generation", generation);
    if (generation == codec_->stateGeneration_) {
        SLOGE("stucked");
        codec_->PrintAllBufferInfo();
        codec_->SignalError(IC_ERR_UNKNOWN);
    }
}

void ImageCodec::BaseState::OnForceShutDown(const MsgInfo &info)
{
    int32_t generation;
    (void)info.param->GetValue("generation", generation);
    codec_->ForceShutdown(generation);
}
/**************************** BaseState End ******************************/

/**************************** UninitializedState start ****************************/
void ImageCodec::UninitializedState::OnStateEntered()
{
    codec_->ReleaseComponent();
}

void ImageCodec::UninitializedState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::INIT: {
            string name;
            (void)info.param->GetValue("name", name);
            int32_t err = OnAllocateComponent(name);
            ReplyErrorCode(info.id, err);
            if (err == IC_ERR_OK) {
                codec_->ChangeStateTo(codec_->initializedState_);
            }
            break;
        }
        default: {
            BaseState::OnMsgReceived(info);
        }
    }
}

int32_t ImageCodec::UninitializedState::OnAllocateComponent(const std::string &name)
{
    codec_->compMgr_ = GetManager();
    if (codec_->compMgr_ == nullptr) {
        SLOGE("GetCodecComponentManager failed");
        return IC_ERR_UNKNOWN;
    }
    codec_->compCb_ = new HdiCallback(codec_);
    int32_t ret = codec_->compMgr_->CreateComponent(codec_->compNode_, codec_->componentId_, name,
                                                    0, codec_->compCb_);
    if (ret != HDF_SUCCESS || codec_->compNode_ == nullptr) {
        codec_->compCb_ = nullptr;
        codec_->compMgr_ = nullptr;
        SLOGE("CreateComponent failed, ret=%{public}d", ret);
        return IC_ERR_UNKNOWN;
    }
    codec_->componentName_ = name;
    codec_->compUniqueStr_ = "[" + to_string(codec_->componentId_) + "][" + name + "]";
    SLOGI("create omx node succ");
    return IC_ERR_OK;
}

void ImageCodec::UninitializedState::OnShutDown(const MsgInfo &info)
{
    ReplyErrorCode(info.id, IC_ERR_OK);
}

/**************************** UninitializedState End ******************************/

/**************************** InitializedState Start **********************************/
void ImageCodec::InitializedState::OnStateEntered()
{
    codec_->inputPortEos_ = false;
    codec_->outputPortEos_ = false;
    codec_->outputFormat_.reset();

    ProcessShutDownFromRunning();
    codec_->notifyCallerAfterShutdownComplete_ = false;
    codec_->ProcessDeferredMessages();
}

void ImageCodec::InitializedState::ProcessShutDownFromRunning()
{
    if (!codec_->isShutDownFromRunning_) {
        return;
    }
    SLOGI("we are doing shutdown from running/portchange/flush -> stopping -> initialized");
    codec_->ChangeStateTo(codec_->uninitializedState_);
    if (codec_->notifyCallerAfterShutdownComplete_) {
        SLOGI("reply to release msg");
        MsgInfo msg { MsgWhat::RELEASE, 0, nullptr };
        if (codec_->GetFirstSyncMsgToReply(msg)) {
            ReplyErrorCode(msg.id, IC_ERR_OK);
        }
        codec_->notifyCallerAfterShutdownComplete_ = false;
    }
    codec_->isShutDownFromRunning_ = false;
}

void ImageCodec::InitializedState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::SET_CALLBACK: {
            OnSetCallBack(info);
            return;
        }
        case MsgWhat::CONFIGURE: {
            OnConfigure(info);
            return;
        }
        case MsgWhat::GET_OUTPUT_BUFFER_USAGE: {
            OnGetOutputBufferUsage(info);
            break;
        }
        case MsgWhat::SET_OUTPUT_BUFFER: {
            OnSetOutputBuffer(info);
            break;
        }
        case MsgWhat::START: {
            OnStart(info);
            return;
        }
        default: {
            BaseState::OnMsgReceived(info);
        }
    }
}

void ImageCodec::InitializedState::OnSetCallBack(const MsgInfo &info)
{
    int32_t err;
    shared_ptr<ImageCodecCallback> cb;
    (void)info.param->GetValue("callback", cb);
    if (cb == nullptr) {
        err = IC_ERR_INVALID_VAL;
        SLOGE("invalid param");
    } else {
        codec_->callback_ = cb;
        err = IC_ERR_OK;
    }
    ReplyErrorCode(info.id, err);
}

void ImageCodec::InitializedState::OnConfigure(const MsgInfo &info)
{
    Format fmt;
    (void)info.param->GetValue("format", fmt);
    ReplyErrorCode(info.id, codec_->OnConfigure(fmt));
}

void ImageCodec::InitializedState::OnGetOutputBufferUsage(const MsgInfo &info)
{
    ParamSP reply = ParamBundle::Create();
    reply->SetValue<int32_t>("err", IC_ERR_OK);
    reply->SetValue("usage", codec_->OnGetOutputBufferUsage());
    codec_->PostReply(info.id, reply);
}

void ImageCodec::InitializedState::OnSetOutputBuffer(const MsgInfo &info)
{
    sptr<SurfaceBuffer> output;
    (void)info.param->GetValue("output", output);
    ReplyErrorCode(info.id, codec_->OnSetOutputBuffer(output));
}

void ImageCodec::InitializedState::OnStart(const MsgInfo &info)
{
    if (!codec_->ReadyToStart()) {
        ReplyErrorCode(info.id, IC_ERR_INVALID_OPERATION);
        return;
    }
    SLOGI("begin to set omx to idle");
    int32_t ret = codec_->compNode_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
    if (ret == HDF_SUCCESS) {
        codec_->ReplyToSyncMsgLater(info);
        codec_->ChangeStateTo(codec_->startingState_);
    } else {
        SLOGE("set omx to idle failed, ret=%{public}d", ret);
        ReplyErrorCode(info.id, IC_ERR_UNKNOWN);
    }
}

void ImageCodec::InitializedState::OnShutDown(const MsgInfo &info)
{
    SLOGI("receive RELEASE");
    codec_->ChangeStateTo(codec_->uninitializedState_);
    codec_->notifyCallerAfterShutdownComplete_ = false;
    ReplyErrorCode(info.id, IC_ERR_OK);
}
/**************************** InitializedState End ******************************/

/**************************** StartingState Start ******************************/
void ImageCodec::StartingState::OnStateEntered()
{
    hasError_ = false;

    ParamSP msg = ParamBundle::Create();
    msg->SetValue("generation", codec_->stateGeneration_);
    codec_->SendAsyncMsg(MsgWhat::CHECK_IF_STUCK, msg, THREE_SECONDS_IN_US);

    int32_t ret = AllocateBuffers();
    if (ret != IC_ERR_OK) {
        SLOGE("AllocateBuffers failed, back to init state");
        hasError_ = true;
        ReplyStartMsg(ret);
        codec_->ChangeStateTo(codec_->initializedState_);
    }
}

int32_t ImageCodec::StartingState::AllocateBuffers()
{
    int32_t ret = codec_->AllocateBuffersOnPort(OMX_DirInput, false);
    if (ret != IC_ERR_OK) {
        return ret;
    }
    ret = codec_->AllocateBuffersOnPort(OMX_DirOutput, false);
    if (ret != IC_ERR_OK) {
        return ret;
    }
    return IC_ERR_OK;
}

void ImageCodec::StartingState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::GET_INPUT_FORMAT:
        case MsgWhat::GET_OUTPUT_FORMAT: {
            codec_->DeferMessage(info);
            return;
        }
        case MsgWhat::START: {
            ReplyErrorCode(info.id, IC_ERR_OK);
            return;
        }
        case MsgWhat::CHECK_IF_STUCK: {
            int32_t generation;
            if (info.param->GetValue("generation", generation) &&
                generation == codec_->stateGeneration_) {
                SLOGE("stucked, force state transition");
                hasError_ = true;
                ReplyStartMsg(IC_ERR_UNKNOWN);
                codec_->ChangeStateTo(codec_->initializedState_);
            }
            return;
        }
        default: {
            BaseState::OnMsgReceived(info);
        }
    }
}

void ImageCodec::StartingState::OnCodecEvent(CodecEventType event, uint32_t data1, uint32_t data2)
{
    if (event != CODEC_EVENT_CMD_COMPLETE) {
        return BaseState::OnCodecEvent(event, data1, data2);
    }
    if (data1 != static_cast<uint32_t>(CODEC_COMMAND_STATE_SET)) {
        SLOGW("ignore event: data1=%{public}u, data2=%{public}u", data1, data2);
        return;
    }
    if (data2 == static_cast<uint32_t>(CODEC_STATE_IDLE)) {
        SLOGI("omx now idle, begin to set omx to executing");
        int32_t ret = codec_->compNode_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, {});
        if (ret != HDF_SUCCESS) {
            SLOGE("set omx to executing failed, ret=%{public}d", ret);
            hasError_ = true;
            ReplyStartMsg(IC_ERR_UNKNOWN);
            codec_->ChangeStateTo(codec_->initializedState_);
        }
    } else if (data2 == static_cast<uint32_t>(CODEC_STATE_EXECUTING)) {
        SLOGI("omx now executing");
        ReplyStartMsg(IC_ERR_OK);
        codec_->SubmitAllBuffersOwnedByUs();
        codec_->ChangeStateTo(codec_->runningState_);
    }
}

void ImageCodec::StartingState::OnShutDown(const MsgInfo &info)
{
    codec_->DeferMessage(info);
}

void ImageCodec::StartingState::ReplyStartMsg(int32_t errCode)
{
    MsgInfo msg {MsgWhat::START, 0, nullptr};
    if (codec_->GetFirstSyncMsgToReply(msg)) {
        SLOGI("start %{public}s", (errCode == 0) ? "succ" : "failed");
        ReplyErrorCode(msg.id, errCode);
    } else {
        SLOGE("there should be a start msg to reply");
    }
}

void ImageCodec::StartingState::OnStateExited()
{
    if (hasError_) {
        SLOGW("error occured, roll omx back to loaded and free allocated buffers");
        if (codec_->RollOmxBackToLoaded()) {
            codec_->ClearBufferPool(OMX_DirInput);
            codec_->ClearBufferPool(OMX_DirOutput);
        }
    }
    BaseState::OnStateExited();
}

/**************************** StartingState End ******************************/

/**************************** RunningState Start ********************************/
void ImageCodec::RunningState::OnStateEntered()
{
    codec_->ProcessDeferredMessages();
}

void ImageCodec::RunningState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::START:
            ReplyErrorCode(info.id, codec_->SubmitAllBuffersOwnedByUs());
            break;
        case MsgWhat::QUEUE_INPUT_BUFFER:
            codec_->OnQueueInputBuffer(info, inputMode_);
            break;
        case MsgWhat::RELEASE_OUTPUT_BUFFER:
            codec_->OnReleaseOutputBuffer(info, outputMode_);
            break;
        default:
            BaseState::OnMsgReceived(info);
            break;
    }
}

void ImageCodec::RunningState::OnCodecEvent(CodecEventType event, uint32_t data1, uint32_t data2)
{
    switch (event) {
        case CODEC_EVENT_PORT_SETTINGS_CHANGED: {
            if (data1 != OMX_DirOutput) {
                SLOGI("ignore input port changed");
                return;
            }
            if (data2 == 0 || data2 == OMX_IndexParamPortDefinition) {
                SLOGI("output port settings changed, begin to ask omx to disable out port");
                codec_->UpdateOutPortFormat();
                int32_t ret = codec_->compNode_->SendCommand(
                    CODEC_COMMAND_PORT_DISABLE, OMX_DirOutput, {});
                if (ret == HDF_SUCCESS) {
                    codec_->EraseOutBuffersOwnedByUs();
                    codec_->ChangeStateTo(codec_->outputPortChangedState_);
                } else {
                    SLOGE("ask omx to disable out port failed");
                    codec_->SignalError(IC_ERR_UNKNOWN);
                }
            } else if (data2 == OMX_IndexColorAspects) {
                codec_->UpdateColorAspects();
            } else {
                SLOGI("unknown data2 0x%{public}x for CODEC_EVENT_PORT_SETTINGS_CHANGED", data2);
            }
            return;
        }
        default: {
            BaseState::OnCodecEvent(event, data1, data2);
        }
    }
}

void ImageCodec::RunningState::OnShutDown(const MsgInfo &info)
{
    codec_->isShutDownFromRunning_ = true;
    codec_->notifyCallerAfterShutdownComplete_ = true;
    codec_->isBufferCirculating_ = false;

    SLOGI("receive release msg, begin to set omx to idle");
    int32_t ret = codec_->compNode_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
    if (ret == HDF_SUCCESS) {
        codec_->ReplyToSyncMsgLater(info);
        codec_->ChangeStateTo(codec_->stoppingState_);
    } else {
        SLOGE("set omx to idle failed, ret=%{public}d", ret);
        ReplyErrorCode(info.id, IC_ERR_UNKNOWN);
    }
}
/**************************** RunningState End ********************************/


/**************************** OutputPortChangedState Start ********************************/
void ImageCodec::OutputPortChangedState::OnStateEntered()
{
    ParamSP msg = ParamBundle::Create();
    msg->SetValue("generation", codec_->stateGeneration_);
    codec_->SendAsyncMsg(MsgWhat::CHECK_IF_STUCK, msg, THREE_SECONDS_IN_US);
}

void ImageCodec::OutputPortChangedState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::START:
        case MsgWhat::GET_INPUT_FORMAT:
        case MsgWhat::GET_OUTPUT_FORMAT: {
            codec_->DeferMessage(info);
            return;
        }
        case MsgWhat::QUEUE_INPUT_BUFFER: {
            codec_->OnQueueInputBuffer(info, inputMode_);
            return;
        }
        case MsgWhat::RELEASE_OUTPUT_BUFFER: {
            codec_->OnReleaseOutputBuffer(info, outputMode_);
            return;
        }
        case MsgWhat::FORCE_SHUTDOWN: {
            OnForceShutDown(info);
            return;
        }
        case MsgWhat::CHECK_IF_STUCK: {
            OnCheckIfStuck(info);
            return;
        }
        default: {
            BaseState::OnMsgReceived(info);
        }
    }
}

void ImageCodec::OutputPortChangedState::OnShutDown(const MsgInfo &info)
{
    if (codec_->hasFatalError_) {
        ParamSP stopMsg = ParamBundle::Create();
        stopMsg->SetValue("generation", codec_->stateGeneration_);
        codec_->SendAsyncMsg(MsgWhat::FORCE_SHUTDOWN, stopMsg, THREE_SECONDS_IN_US);
    }
    codec_->ReclaimBuffer(OMX_DirOutput, BufferOwner::OWNED_BY_USER, true);
    codec_->DeferMessage(info);
}

void ImageCodec::OutputPortChangedState::OnCodecEvent(CodecEventType event, uint32_t data1, uint32_t data2)
{
    switch (event) {
        case CODEC_EVENT_CMD_COMPLETE: {
            if (data1 == CODEC_COMMAND_PORT_DISABLE) {
                if (data2 != OMX_DirOutput) {
                    SLOGW("ignore input port disable complete");
                    return;
                }
                SLOGI("output port is disabled");
                HandleOutputPortDisabled();
            } else if (data1 == CODEC_COMMAND_PORT_ENABLE) {
                if (data2 != OMX_DirOutput) {
                    SLOGW("ignore input port enable complete");
                    return;
                }
                SLOGI("output port is enabled");
                HandleOutputPortEnabled();
            }
            return;
        }
        default: {
            BaseState::OnCodecEvent(event, data1, data2);
        }
    }
}

void ImageCodec::OutputPortChangedState::HandleOutputPortDisabled()
{
    int32_t ret = IC_ERR_OK;
    if (!codec_->outputBufferPool_.empty()) {
        SLOGE("output port is disabled but not empty: %{public}zu", codec_->outputBufferPool_.size());
        ret = IC_ERR_UNKNOWN;
    }
    if (ret == IC_ERR_OK) {
        ret = codec_->ReConfigureOutputBufferCnt();
    }
    if (ret == IC_ERR_OK) {
        SLOGI("begin to ask omx to enable out port");
        int32_t err = codec_->compNode_->SendCommand(CODEC_COMMAND_PORT_ENABLE, OMX_DirOutput, {});
        if (err == HDF_SUCCESS) {
            ret = codec_->AllocateBuffersOnPort(OMX_DirOutput, true);
        } else {
            SLOGE("ask omx to enable out port failed, ret=%{public}d", ret);
            ret = IC_ERR_UNKNOWN;
        }
    }
    if (ret != IC_ERR_OK) {
        codec_->SignalError(IC_ERR_INVALID_VAL);
    }
}

void ImageCodec::OutputPortChangedState::HandleOutputPortEnabled()
{
    if (codec_->isBufferCirculating_) {
        codec_->SubmitOutputBuffersToOmxNode();
    }
    codec_->callback_->OnOutputFormatChanged(*(codec_->outputFormat_.get()));
    codec_->ChangeStateTo(codec_->runningState_);
}
/**************************** OutputPortChangedState End ********************************/

/**************************** StoppingState Start ********************************/
void ImageCodec::StoppingState::OnStateEntered()
{
    omxNodeInIdleState_ = false;
    omxNodeIsChangingToLoadedState_ = false;
    codec_->ReclaimBuffer(OMX_DirInput, BufferOwner::OWNED_BY_USER);
    codec_->ReclaimBuffer(OMX_DirOutput, BufferOwner::OWNED_BY_USER);
    SLOGI("all buffer owned by user are now owned by us");

    ParamSP msg = ParamBundle::Create();
    msg->SetValue("generation", codec_->stateGeneration_);
    codec_->SendAsyncMsg(MsgWhat::CHECK_IF_STUCK, msg, THREE_SECONDS_IN_US);
}

void ImageCodec::StoppingState::OnMsgReceived(const MsgInfo &info)
{
    switch (info.type) {
        case MsgWhat::CHECK_IF_STUCK: {
            int32_t generation;
            (void)info.param->GetValue("generation", generation);
            if (generation == codec_->stateGeneration_) {
                SLOGE("stucked, force state transition");
                codec_->ReclaimBuffer(OMX_DirInput, BufferOwner::OWNED_BY_OMX);
                codec_->ReclaimBuffer(OMX_DirOutput, BufferOwner::OWNED_BY_OMX);
                SLOGI("all buffer owned by omx are now owned by us");
                ChangeOmxNodeToLoadedState(true);
                codec_->ChangeStateTo(codec_->initializedState_);
            }
            return;
        }
        default: {
            BaseState::OnMsgReceived(info);
        }
    }
}

void ImageCodec::StoppingState::OnCodecEvent(CodecEventType event, uint32_t data1, uint32_t data2)
{
    switch (event) {
        case CODEC_EVENT_CMD_COMPLETE: {
            if (data1 != static_cast<uint32_t>(CODEC_COMMAND_STATE_SET)) {
                SLOGW("unexpected CODEC_EVENT_CMD_COMPLETE: %{public}u %{public}u", data1, data2);
                return;
            }
            if (data2 == static_cast<uint32_t>(CODEC_STATE_IDLE)) {
                SLOGI("omx now idle");
                omxNodeInIdleState_ = true;
                ChangeStateIfWeOwnAllBuffers();
            } else if (data2 == static_cast<uint32_t>(CODEC_STATE_LOADED)) {
                SLOGI("omx now loaded");
                codec_->ChangeStateTo(codec_->initializedState_);
            }
            return;
        }
        default: {
            BaseState::OnCodecEvent(event, data1, data2);
        }
    }
}

void ImageCodec::StoppingState::ChangeStateIfWeOwnAllBuffers()
{
    if (omxNodeInIdleState_ && codec_->IsAllBufferOwnedByUs()) {
        ChangeOmxNodeToLoadedState(false);
    } else {
        SLOGD("cannot change state yet");
    }
}

void ImageCodec::StoppingState::ChangeOmxNodeToLoadedState(bool forceToFreeBuffer)
{
    if (!omxNodeIsChangingToLoadedState_) {
        SLOGI("begin to set omx to loaded");
        int32_t ret = codec_->compNode_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, {});
        if (ret == HDF_SUCCESS) {
            omxNodeIsChangingToLoadedState_ = true;
        } else {
            SLOGE("set omx to loaded failed, ret=%{public}d", ret);
        }
    }
    if (forceToFreeBuffer || omxNodeIsChangingToLoadedState_) {
        codec_->ClearBufferPool(OMX_DirInput);
        codec_->ClearBufferPool(OMX_DirOutput);
        return;
    }
    codec_->SignalError(IC_ERR_UNKNOWN);
}

void ImageCodec::StoppingState::OnShutDown(const MsgInfo &info)
{
    codec_->DeferMessage(info);
}
/**************************** StoppingState End ********************************/

} // namespace OHOS::ImagePlugin