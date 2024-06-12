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

#ifndef IMAGE_CODEC_H
#define IMAGE_CODEC_H

#include <queue>
#include <array>
#include <functional>
#include "securec.h"
#include "OMX_Component.h"  // third_party/openmax/api/1.1.2
#include "param_bundle.h"
#include "image_codec_buffer.h"
#include "image_codec_common.h"
#include "format.h"
#include "state_machine.h"
#include "type_converter.h"
#include "codec_omx_ext.h"
#include "hdi_define.h"

namespace OHOS::ImagePlugin {
inline constexpr int TIME_RATIO_S_TO_MS = 1000;
inline constexpr double US_TO_MS = 1000.0;
inline constexpr double US_TO_S = 1000000.0;
inline constexpr uint32_t STRIDE_ALIGNMENT = 32;

inline uint32_t GetYuv420Size(uint32_t w, uint32_t h)
{
    return w * h * 3 / 2;  // 3: nom of ratio, 2: denom of ratio
}

class ImageCodec : protected StateMachine {
public:
    static std::shared_ptr<ImageCodec> Create();
    std::string GetComponentName() const { return componentName_; }
    int32_t SetCallback(const std::shared_ptr<ImageCodecCallback> &callback);
    int32_t Configure(const Format &format);
    int32_t QueueInputBuffer(uint32_t index);
    int32_t ReleaseOutputBuffer(uint32_t index);
    int32_t GetInputFormat(Format& format);
    int32_t GetOutputFormat(Format& format);
    int32_t Start();
    int32_t Release();
    int32_t GetOutputBufferUsage(uint64_t& usage);
    int32_t SetOutputBuffer(sptr<SurfaceBuffer> output);
protected:
    enum MsgWhat : MsgType {
        INIT,
        SET_CALLBACK,
        CONFIGURE,
        START,
        GET_INPUT_FORMAT,
        GET_OUTPUT_FORMAT,
        QUEUE_INPUT_BUFFER,
        RELEASE_OUTPUT_BUFFER,
        RELEASE,
        GET_OUTPUT_BUFFER_USAGE,
        SET_OUTPUT_BUFFER,

        INNER_MSG_BEGIN = 1000,
        CODEC_EVENT,
        OMX_EMPTY_BUFFER_DONE,
        OMX_FILL_BUFFER_DONE,
        CHECK_IF_STUCK,
        FORCE_SHUTDOWN,
    };

    enum BufferOperationMode {
        KEEP_BUFFER,
        RESUBMIT_BUFFER,
        FREE_BUFFER,
    };

    enum BufferOwner {
        OWNED_BY_US = 0,
        OWNED_BY_USER = 1,
        OWNED_BY_OMX = 2,
        OWNER_CNT = 3,
    };

    struct PortInfo {
        uint32_t width;
        uint32_t height;
        OMX_VIDEO_CODINGTYPE codingType;
        std::optional<PixelFmt> pixelFmt;
        double frameRate;
        std::optional<uint32_t> inputBufSize;
        std::optional<uint32_t> bufferCnt;
    };

    struct BufferInfo {
        BufferInfo() : lastOwnerChangeTime(std::chrono::steady_clock::now()) {}
        bool isInput = true;
        BufferOwner owner = OWNED_BY_US;
        std::chrono::time_point<std::chrono::steady_clock> lastOwnerChangeTime;
        uint32_t bufferId = 0;
        std::shared_ptr<HdiCodecNamespace::OmxCodecBuffer> omxBuffer;
        sptr<SurfaceBuffer> surfaceBuffer;
        std::shared_ptr<ImageCodecBuffer> imgCodecBuffer;

        void CleanUpUnusedInfo();
        void BeginCpuAccess();
        void EndCpuAccess();
        bool IsValidFrame() const;
        void Dump(const std::string& prefix, bool dumpMode) const;

    private:
        void Dump(const std::string& prefix) const;
        void DumpSurfaceBuffer(const std::string& prefix) const;
        void DumpLinearBuffer(const std::string& prefix) const;
        static constexpr char DUMP_PATH[] = "/data/misc/imagecodecdump";
    };
protected:
    ImageCodec(OMX_VIDEO_CODINGTYPE codingType, bool isEncoder);
    ~ImageCodec() override;
    static const char* ToString(MsgWhat what);
    static const char* ToString(BufferOwner owner);
    void ReplyErrorCode(MsgId id, int32_t err);
    void PrintAllBufferInfo();
    std::array<uint32_t, OWNER_CNT> CountOwner(bool isInput);
    void ChangeOwner(BufferInfo& info, BufferOwner newOwner);
    void UpdateInputRecord(const BufferInfo& info, std::chrono::time_point<std::chrono::steady_clock> now);
    void UpdateOutputRecord(const BufferInfo& info, std::chrono::time_point<std::chrono::steady_clock> now);

    // configure
    virtual int32_t OnConfigure(const Format &format) = 0;
    bool GetPixelFmtFromUser(const Format &format);
    static std::optional<double> GetFrameRateFromUser(const Format &format);
    int32_t SetVideoPortInfo(OMX_DIRTYPE portIndex, const PortInfo& info);
    virtual int32_t UpdateInPortFormat() = 0;
    virtual int32_t UpdateOutPortFormat() = 0;
    virtual void UpdateColorAspects() {}
    void PrintPortDefinition(const OMX_PARAM_PORTDEFINITIONTYPE& def);
    int32_t SetFrameRateAdaptiveMode(const Format &format);
    int32_t SetProcessName(const Format &format);
    virtual int32_t ReConfigureOutputBufferCnt() = 0;
    virtual uint64_t OnGetOutputBufferUsage() = 0;
    virtual int32_t OnSetOutputBuffer(sptr<SurfaceBuffer> output) = 0;

    // start
    virtual bool ReadyToStart() = 0;
    virtual int32_t AllocateBuffersOnPort(OMX_DIRTYPE portIndex) = 0;
    virtual void UpdateFormatFromSurfaceBuffer() = 0;
    int32_t GetPortDefinition(OMX_DIRTYPE portIndex, OMX_PARAM_PORTDEFINITIONTYPE& def);
    int32_t AllocateSurfaceBuffers(OMX_DIRTYPE portIndex, sptr<SurfaceBuffer> output = nullptr);
    int32_t AllocateHardwareBuffers(OMX_DIRTYPE portIndex);
    std::shared_ptr<HdiCodecNamespace::OmxCodecBuffer> SurfaceBufferToOmxBuffer(
        const sptr<SurfaceBuffer>& surfaceBuffer);
    std::shared_ptr<HdiCodecNamespace::OmxCodecBuffer> DynamicSurfaceBufferToOmxBuffer();

    virtual int32_t SubmitAllBuffersOwnedByUs() = 0;
    virtual int32_t SubmitOutputBuffersToOmxNode() { return IC_ERR_UNSUPPORT; }
    BufferInfo* FindBufferInfoByID(OMX_DIRTYPE portIndex, uint32_t bufferId);
    std::optional<size_t> FindBufferIndexByID(OMX_DIRTYPE portIndex, uint32_t bufferId);

    // input buffer circulation
    virtual void NotifyUserToFillThisInBuffer(BufferInfo &info);
    virtual void OnQueueInputBuffer(const MsgInfo &msg, BufferOperationMode mode);
    void OnQueueInputBuffer(BufferOperationMode mode, BufferInfo* info);
    int32_t NotifyOmxToEmptyThisInBuffer(BufferInfo& info);
    virtual void OnOMXEmptyBufferDone(uint32_t bufferId, BufferOperationMode mode) = 0;

    // output buffer circulation
    int32_t NotifyOmxToFillThisOutBuffer(BufferInfo &info);
    void OnOMXFillBufferDone(const HdiCodecNamespace::OmxCodecBuffer& omxBuffer, BufferOperationMode mode);
    void OnOMXFillBufferDone(BufferOperationMode mode, BufferInfo& info, size_t bufferIdx);
    void NotifyUserOutBufferAvaliable(BufferInfo &info);
    void OnReleaseOutputBuffer(const MsgInfo &msg, BufferOperationMode mode);

    // // stop/release
    void ReclaimBuffer(OMX_DIRTYPE portIndex, BufferOwner owner, bool erase = false);
    bool IsAllBufferOwnedByUs(OMX_DIRTYPE portIndex);
    bool IsAllBufferOwnedByUs();
    void EraseOutBuffersOwnedByUs();
    void ClearBufferPool(OMX_DIRTYPE portIndex);
    virtual void EraseBufferFromPool(OMX_DIRTYPE portIndex, size_t i) = 0;
    void FreeOmxBuffer(OMX_DIRTYPE portIndex, const BufferInfo& info);

    // template
    template <typename T>
    static inline void InitOMXParam(T& param)
    {
        (void)memset_s(&param, sizeof(T), 0x0, sizeof(T));
        param.nSize = sizeof(T);
        param.nVersion.s.nVersionMajor = 1;
    }

    template <typename T>
    static inline void InitOMXParamExt(T& param)
    {
        (void)memset_s(&param, sizeof(T), 0x0, sizeof(T));
        param.size = sizeof(T);
        param.version.s.nVersionMajor = 1;
    }

    template <typename T>
    bool GetParameter(uint32_t index, T& param, bool isCfg = false)
    {
        int8_t* p = reinterpret_cast<int8_t*>(&param);
        std::vector<int8_t> inVec(p, p + sizeof(T));
        std::vector<int8_t> outVec;
        int32_t ret = isCfg ? compNode_->GetConfig(index, inVec, outVec) :
                              compNode_->GetParameter(index, inVec, outVec);
        if (ret != HDF_SUCCESS) {
            return false;
        }
        if (outVec.size() != sizeof(T)) {
            return false;
        }
        ret = memcpy_s(&param, sizeof(T), outVec.data(), outVec.size());
        if (ret != EOK) {
            return false;
        }
        return true;
    }

    template <typename T>
    bool SetParameter(uint32_t index, const T& param, bool isCfg = false)
    {
        const int8_t* p = reinterpret_cast<const int8_t*>(&param);
        std::vector<int8_t> inVec(p, p + sizeof(T));
        int32_t ret = isCfg ? compNode_->SetConfig(index, inVec) :
                              compNode_->SetParameter(index, inVec);
        if (ret != HDF_SUCCESS) {
            return false;
        }
        return true;
    }

protected:
    bool isEncoder_;
    OMX_VIDEO_CODINGTYPE codingType_;
    uint32_t componentId_ = 0;
    std::string componentName_;
    std::string compUniqueStr_;
    bool debugMode_ = false;
    bool dumpMode_ = false;
    sptr<HdiCodecNamespace::ICodecCallback> compCb_ = nullptr;
    sptr<HdiCodecNamespace::ICodecComponent> compNode_ = nullptr;
    sptr<HdiCodecNamespace::ICodecComponentManager> compMgr_ = nullptr;

    std::shared_ptr<ImageCodecCallback> callback_;
    PixelFmt configuredFmt_{};
    BufferRequestConfig requestCfg_{};
    std::shared_ptr<Format> configFormat_;
    std::shared_ptr<Format> inputFormat_;
    std::shared_ptr<Format> outputFormat_;

    std::vector<BufferInfo> inputBufferPool_;
    std::vector<BufferInfo> outputBufferPool_;
    bool isBufferCirculating_ = false;
    bool inputPortEos_ = false;
    bool outputPortEos_ = false;

    struct TotalCntAndCost {
        uint64_t totalCnt = 0;
        uint64_t totalCostUs = 0;
    };
    std::array<std::array<TotalCntAndCost, OWNER_CNT>, OWNER_CNT> inputHoldTimeRecord_;
    std::chrono::time_point<std::chrono::steady_clock> firstInTime_;
    uint64_t inTotalCnt_ = 0;
    std::array<std::array<TotalCntAndCost, OWNER_CNT>, OWNER_CNT> outputHoldTimeRecord_;
    std::chrono::time_point<std::chrono::steady_clock> firstOutTime_;
    TotalCntAndCost outRecord_;
    std::unordered_map<int64_t, std::chrono::time_point<std::chrono::steady_clock>> inTimeMap_;

    static constexpr char BUFFER_ID[] = "buffer-id";
    static constexpr uint32_t WAIT_FENCE_MS = 1000;
private:
    struct BaseState : State {
    protected:
        BaseState(ImageCodec *codec, const std::string &stateName,
                  BufferOperationMode inputMode = KEEP_BUFFER, BufferOperationMode outputMode = KEEP_BUFFER)
            : State(stateName), codec_(codec), inputMode_(inputMode), outputMode_(outputMode) {}
        void OnMsgReceived(const MsgInfo &info) override;
        void ReplyErrorCode(MsgId id, int32_t err);
        void OnCodecEvent(const MsgInfo &info);
        virtual void OnCodecEvent(HdiCodecNamespace::CodecEventType event, uint32_t data1, uint32_t data2);
        void OnGetFormat(const MsgInfo &info);
        virtual void OnShutDown(const MsgInfo &info) = 0;
        void OnCheckIfStuck(const MsgInfo &info);
        void OnForceShutDown(const MsgInfo &info);
        void OnStateExited() override { codec_->stateGeneration_++; }

    protected:
        ImageCodec *codec_;
        BufferOperationMode inputMode_;
        BufferOperationMode outputMode_;
    };

    struct UninitializedState : BaseState {
        explicit UninitializedState(ImageCodec *codec) : BaseState(codec, "Uninitialized") {}
    private:
        void OnStateEntered() override;
        void OnMsgReceived(const MsgInfo &info) override;
        int32_t OnAllocateComponent(const std::string &name);
        void OnShutDown(const MsgInfo &info) override;
    };

    struct InitializedState : BaseState {
        explicit InitializedState(ImageCodec *codec) : BaseState(codec, "Initialized") {}
    private:
        void OnStateEntered() override;
        void ProcessShutDownFromRunning();
        void OnMsgReceived(const MsgInfo &info) override;
        void OnSetCallBack(const MsgInfo &info);
        void OnConfigure(const MsgInfo &info);
        void OnGetOutputBufferUsage(const MsgInfo &info);
        void OnSetOutputBuffer(const MsgInfo &info);
        void OnStart(const MsgInfo &info);
        void OnShutDown(const MsgInfo &info) override;
    };

    struct StartingState : BaseState {
        explicit StartingState(ImageCodec *codec) : BaseState(codec, "Starting") {}
    private:
        void OnStateEntered() override;
        void OnStateExited() override;
        void OnMsgReceived(const MsgInfo &info) override;
        int32_t AllocateBuffers();
        void OnCodecEvent(HdiCodecNamespace::CodecEventType event, uint32_t data1, uint32_t data2) override;
        void OnShutDown(const MsgInfo &info) override;
        void ReplyStartMsg(int32_t errCode);
        bool hasError_ = false;
    };

    struct RunningState : BaseState {
        explicit RunningState(ImageCodec *codec) : BaseState(codec, "Running", RESUBMIT_BUFFER, RESUBMIT_BUFFER) {}
    private:
        void OnStateEntered() override;
        void OnMsgReceived(const MsgInfo &info) override;
        void OnCodecEvent(HdiCodecNamespace::CodecEventType event, uint32_t data1, uint32_t data2) override;
        void OnShutDown(const MsgInfo &info) override;
    };

    struct OutputPortChangedState : BaseState {
        explicit OutputPortChangedState(ImageCodec *codec)
            : BaseState(codec, "OutputPortChanged", RESUBMIT_BUFFER, FREE_BUFFER) {}
    private:
        void OnStateEntered() override;
        void OnMsgReceived(const MsgInfo &info) override;
        void OnCodecEvent(HdiCodecNamespace::CodecEventType event, uint32_t data1, uint32_t data2) override;
        void OnShutDown(const MsgInfo &info) override;
        void HandleOutputPortDisabled();
        void HandleOutputPortEnabled();
    };

    struct StoppingState : BaseState {
        explicit StoppingState(ImageCodec *codec) : BaseState(codec, "Stopping"),
            omxNodeInIdleState_(false),
            omxNodeIsChangingToLoadedState_(false) {}
    private:
        void OnStateEntered() override;
        void OnMsgReceived(const MsgInfo &info) override;
        void OnCodecEvent(HdiCodecNamespace::CodecEventType event, uint32_t data1, uint32_t data2) override;
        void OnShutDown(const MsgInfo &info) override;
        void ChangeStateIfWeOwnAllBuffers();
        void ChangeOmxNodeToLoadedState(bool forceToFreeBuffer);
        bool omxNodeInIdleState_;
        bool omxNodeIsChangingToLoadedState_;
    };

    class HdiCallback : public HdiCodecNamespace::ICodecCallback {
    public:
        explicit HdiCallback(ImageCodec* codec) : codec_(codec) { }
        virtual ~HdiCallback() = default;
        int32_t EventHandler(HdiCodecNamespace::CodecEventType event, const HdiCodecNamespace::EventInfo& info);
        int32_t EmptyBufferDone(int64_t appData, const HdiCodecNamespace::OmxCodecBuffer& buffer);
        int32_t FillBufferDone(int64_t appData, const HdiCodecNamespace::OmxCodecBuffer& buffer);
    private:
        ImageCodec* codec_;
    };
private:
    int32_t DoSyncCall(MsgWhat msgType, std::function<void(ParamSP)> oper);
    int32_t DoSyncCallAndGetReply(MsgWhat msgType, std::function<void(ParamSP)> oper, ParamSP &reply);
    int32_t InitWithName(const std::string &name);
    void ReleaseComponent();
    void CleanUpOmxNode();
    void ChangeOmxToTargetState(HdiCodecNamespace::CodecStateType &state,
                                HdiCodecNamespace::CodecStateType targetState);
    bool RollOmxBackToLoaded();

    int32_t ForceShutdown(int32_t generation);
    void SignalError(ImageCodecError err);
    void DeferMessage(const MsgInfo &info);
    void ProcessDeferredMessages();
    void ReplyToSyncMsgLater(const MsgInfo& msg);
    bool GetFirstSyncMsgToReply(MsgInfo& msg);

private:
    static constexpr size_t MAX_IMAGE_CODEC_BUFFER_SIZE = 8192 * 4096 * 4; // 8K RGBA
    static constexpr uint32_t THREE_SECONDS_IN_US = 3'000'000;
    static constexpr double FRAME_RATE_COEFFICIENT = 65536.0;

    std::shared_ptr<UninitializedState> uninitializedState_;
    std::shared_ptr<InitializedState> initializedState_;
    std::shared_ptr<StartingState> startingState_;
    std::shared_ptr<RunningState> runningState_;
    std::shared_ptr<OutputPortChangedState> outputPortChangedState_;
    std::shared_ptr<StoppingState> stoppingState_;

    int32_t stateGeneration_ = 0;
    bool isShutDownFromRunning_ = false;
    bool notifyCallerAfterShutdownComplete_ = false;
    bool hasFatalError_ = false;
    std::list<MsgInfo> deferredQueue_;
    std::map<MsgType, std::queue<std::pair<MsgId, ParamSP>>> syncMsgToReply_;
}; // class ImageCodec
} // namespace OHOS::ImagePlugin

#endif // IMAGE_CODEC_H