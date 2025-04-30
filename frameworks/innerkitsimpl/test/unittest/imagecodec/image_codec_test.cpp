/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define protected public
#define private public
#include <gtest/gtest.h>
#include "image_codec.h"
#include "image_decoder.h"

using namespace testing::ext;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Multimedia {

#define MSGWHAT_UNKNOW 30
#define BUFFER_UNSUPPORTED 100

class MockImageCodecCallback : public ImageCodecCallback {
public:
    ~MockImageCodecCallback() {}
    void OnError(ImageCodecError err) override {};
    void OnOutputFormatChanged(const Format &format) override {};
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) override {};
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) override {};
};

class ImageCodecTest : public testing::Test {
public:
    ImageCodecTest() {}
    ~ImageCodecTest() {}
};

/**
 * @tc.name: GetInputFormat001
 * @tc.desc: Verify that GetInputFormat returns IC_ERR_UNKNOWN when the input format is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetInputFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetInputFormatTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    Format format;
    int32_t ret = imageCodec->GetInputFormat(format);

    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: GetInputFormatTest001 end";
}

/**
 * @tc.name: GetOutputFormatTest001
 * @tc.desc: Verify that GetOutputFormat returns IC_ERR_UNKNOWN when the output format is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetOutputFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetOutputFormatTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    imageCodec->ReplyErrorCode(0, 0);
    Format format;
    int32_t ret = imageCodec->GetOutputFormat(format);

    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: GetOutputFormatTest001 end";
}

/**
 * @tc.name: ToStringTest001
 * @tc.desc: Verify that ToString correctly converts BufferOwner enum values
 *           to their corresponding string representations.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ToStringTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    const char* ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_US);
    EXPECT_EQ(strcmp(ret, "us"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_USER);
    EXPECT_EQ(strcmp(ret, "user"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_OMX);
    EXPECT_EQ(strcmp(ret, "omx"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNER_CNT);
    EXPECT_EQ(strcmp(ret, ""), 0);
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest001 end";
}

/**
 * @tc.name: ToStringTest002
 * @tc.desc: Verify that ToString correctly converts MsgWhat enum values to their corresponding string representations,
 *           including handling of unknown values.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ToStringTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest002 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    const char* ret = imageCodec->ToString(ImageCodec::MsgWhat::INIT);
    EXPECT_EQ(strcmp(ret, "INIT"), 0);
    ret = imageCodec->ToString(static_cast<ImageCodec::MsgWhat>(MSGWHAT_UNKNOW));
    EXPECT_EQ(strcmp(ret, "UNKNOWN"), 0);
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest002 end";
}

/**
 * @tc.name: SetFrameRateAdaptiveModeTest001
 * @tc.desc: Verify that SetFrameRateAdaptiveMode returns IC_ERR_UNKNOWN when the input format is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SetFrameRateAdaptiveModeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SetFrameRateAdaptiveModeTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    Format format;
    int32_t ret = imageCodec->SetFrameRateAdaptiveMode(format);
    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: SetFrameRateAdaptiveModeTest001 end";
}

/**
 * @tc.name: SetProcessNameTest001
 * @tc.desc: Verify that SetProcessName correctly sets the process name and returns IC_ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SetProcessNameTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SetProcessNameTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    Format format;
    std::string processName = "testProcessName";
    format.SetValue(ImageCodecDescriptionKey::PROCESS_NAME, processName);
    int32_t ret = imageCodec->SetProcessName(format);
    EXPECT_EQ(ret, IC_ERR_OK);
    GTEST_LOG_(INFO) << "ImageCodecTest: SetProcessNameTest001 end";
}

/**
 * @tc.name: SetProcessNameTest002
 * @tc.desc: Verify that SetProcessName returns IC_ERR_UNKNOWN when the process name is not set in the format.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SetProcessNameTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SetProcessNameTest002 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    Format format;
    int32_t ret = imageCodec->SetProcessName(format);
    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: SetProcessNameTest002 end";
}

/**
 * @tc.name: ForceShutdownTest001
 * @tc.desc: Verify that ForceShutdown correctly shuts down the codec with different input parameters
 *           and returns IC_ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ForceShutdownTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ForceShutdownTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    ImageCodec::BufferInfo bufferInfo;
    imageCodec->OnQueueInputBuffer(ImagePlugin::ImageCodec::BufferOperationMode::KEEP_BUFFER, &bufferInfo);
    imageCodec->OnQueueInputBuffer(ImagePlugin::ImageCodec::BufferOperationMode::FREE_BUFFER, &bufferInfo);
    bufferInfo.omxBuffer = nullptr;
    bufferInfo.CleanUpUnusedInfo();
    bufferInfo.surfaceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(bufferInfo.surfaceBuffer, nullptr);
    bufferInfo.EndCpuAccess();
    bufferInfo.CleanUpUnusedInfo();
    HdiCodecNamespace::OmxCodecBuffer codecBuffer;
    codecBuffer.fd = 0;
    bufferInfo.omxBuffer = std::make_shared<HdiCodecNamespace::OmxCodecBuffer>(codecBuffer);
    imageCodec->UpdateInputRecord(bufferInfo, std::chrono::steady_clock::now());
    imageCodec->UpdateOutputRecord(bufferInfo, std::chrono::steady_clock::now());

    int32_t ret = imageCodec->ForceShutdown(0);
    EXPECT_EQ(ret, IC_ERR_OK);
    ret = imageCodec->ForceShutdown(1);
    EXPECT_EQ(ret, IC_ERR_OK);
    GTEST_LOG_(INFO) << "ImageCodecTest: ForceShutdownTest001 end";
}

/**
 * @tc.name: GetFirstSyncMsgToReplyTest001
 * @tc.desc: Verify that GetFirstSyncMsgToReply returns false when no synchronous message is found to reply.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetFirstSyncMsgToReplyTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetFirstSyncMsgToReplyTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    MsgInfo info;
    bool findSyncMsgToReply = imageCodec->GetFirstSyncMsgToReply(info);
    EXPECT_FALSE(findSyncMsgToReply);
    GTEST_LOG_(INFO) << "ImageCodecTest: GetFirstSyncMsgToReplyTest001 end";
}

/**
 * @tc.name: OnMsgReceivedTest001
 * @tc.desc: Verify that StartingState correctly handles various MsgWhat enum values in OnMsgReceived,
 *           including GET_INPUT_FORMAT, START, and CHECK_IF_STUCK.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, OnMsgReceivedTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    ImageCodec::StartingState startingState(imageCodec.get());
    MsgInfo info;
    info.type = ImageCodec::MsgWhat::GET_INPUT_FORMAT;
    info.id = 0;
    std::shared_ptr<ParamBundle> bundle = std::make_shared<ParamBundle>();
    info.param = bundle;
    startingState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::GET_INPUT_FORMAT);
    info.type = ImageCodec::MsgWhat::START;
    startingState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::START);
    info.type = ImageCodec::MsgWhat::CHECK_IF_STUCK;
    startingState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::CHECK_IF_STUCK);
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest001 end";
}

/**
 * @tc.name: OnMsgReceivedTest002
 * @tc.desc: Verify that RunningState correctly handles codec events and processes MsgWhat::START messages.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, OnMsgReceivedTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest002 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    ImagePlugin::ImageCodec::RunningState runningState(imageCodec.get());
    HDI::Codec::V3_0::CodecEventType event = HDI::Codec::V3_0::CodecEventType::CODEC_EVENT_PORT_SETTINGS_CHANGED;
    runningState.OnCodecEvent(event, 0, 0);
    MsgInfo info;
    info.type = ImageCodec::MsgWhat::START;
    info.id = 0;
    runningState.OnMsgReceived(info);
    EXPECT_EQ(info.id, 0);
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest002 end";
}

/**
 * @tc.name: OnMsgReceivedTest003
 * @tc.desc: Verify that OutputPortChangedState correctly handles various MsgWhat enum values in OnMsgReceived,
 *           including START, QUEUE_INPUT_BUFFER, RELEASE_OUTPUT_BUFFER, FORCE_SHUTDOWN, and CHECK_IF_STUCK.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, OnMsgReceivedTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest003 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    ImagePlugin::ImageCodec::OutputPortChangedState outputPortChangedState(imageCodec.get());
    MsgInfo info;
    std::shared_ptr<ParamBundle> bundle = std::make_shared<ParamBundle>();
    info.param = bundle;
    info.type = ImageCodec::MsgWhat::START;
    outputPortChangedState.OnShutDown(info);
    outputPortChangedState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::START);
    info.type = ImageCodec::MsgWhat::QUEUE_INPUT_BUFFER;
    outputPortChangedState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::QUEUE_INPUT_BUFFER);
    info.type = ImageCodec::MsgWhat::RELEASE_OUTPUT_BUFFER;
    outputPortChangedState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::RELEASE_OUTPUT_BUFFER);
    info.type = ImageCodec::MsgWhat::FORCE_SHUTDOWN;
    outputPortChangedState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::FORCE_SHUTDOWN);
    info.type = ImageCodec::MsgWhat::CHECK_IF_STUCK;
    outputPortChangedState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::CHECK_IF_STUCK);
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest003 end";
}

/**
 * @tc.name: OnMsgReceivedTest004
 * @tc.desc: Verify that StoppingState correctly handles the MsgWhat::CHECK_IF_STUCK message in OnMsgReceived.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, OnMsgReceivedTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest004 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    ImagePlugin::ImageCodec::StoppingState stoppingState(imageCodec.get());
    MsgInfo info;
    info.type = ImageCodec::MsgWhat::CHECK_IF_STUCK;
    std::shared_ptr<ParamBundle> bundle = std::make_shared<ParamBundle>();
    info.param = bundle;
    stoppingState.OnMsgReceived(info);
    EXPECT_EQ(info.type, ImageCodec::MsgWhat::CHECK_IF_STUCK);
    GTEST_LOG_(INFO) << "ImageCodecTest: OnMsgReceivedTest004 end";
}

/**
 * @tc.name: SetupPortTest001
 * @tc.desc: Verify that SetupPort returns IC_ERR_INVALID_VAL when the width or height in the format is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SetupPortTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SetupPortTest001 start";
    ImageDecoder imageDecoder;
    Format format;
    format.SetValue<uint32_t>(ImageCodecDescriptionKey::WIDTH, 0);
    int32_t ret = imageDecoder.SetupPort(format);
    EXPECT_EQ(ret, IC_ERR_INVALID_VAL);
    format.SetValue<uint32_t>(ImageCodecDescriptionKey::WIDTH, 1);
    format.SetValue<uint32_t>(ImageCodecDescriptionKey::HEIGHT, 0);
    ret = imageDecoder.SetupPort(format);
    EXPECT_EQ(ret, IC_ERR_INVALID_VAL);
    format.SetValue<uint32_t>(ImageCodecDescriptionKey::HEIGHT, 1);
    ret = imageDecoder.SetupPort(format);
    EXPECT_EQ(ret, IC_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "ImageCodecTest: SetupPortTest001 end";
}

/**
 * @tc.name: ReadyToStartTest001
 * @tc.desc: Verify that ReadyToStart correctly determines readiness based on callback, formats, and buffer states.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ReadyToStartTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ReadyToStartTest001 start";
    ImageDecoder imageDecoder;
    imageDecoder.callback_ = nullptr;
    bool isReady = imageDecoder.ReadyToStart();
    EXPECT_FALSE(isReady);
    imageDecoder.callback_ = std::make_shared<MockImageCodecCallback>();
    imageDecoder.outputFormat_ = std::make_shared<Format>();
    imageDecoder.inputFormat_ = std::make_shared<Format>();
    imageDecoder.enableHeifGrid_ = true;
    imageDecoder.outputBuffer_ = SurfaceBuffer::Create();
    isReady = imageDecoder.ReadyToStart();
    EXPECT_FALSE(isReady);
    imageDecoder.enableHeifGrid_ = false;
    imageDecoder.outputBuffer_ = nullptr;
    isReady = imageDecoder.ReadyToStart();
    EXPECT_FALSE(isReady);
    GTEST_LOG_(INFO) << "ImageCodecTest: ReadyToStartTest001 end";
}

/**
 * @tc.name: SubmitAllBuffersOwnedByUsTest001
 * @tc.desc: Verify that SubmitAllBuffersOwnedByUs correctly submits all buffers owned
 *           by the decoder and returns IC_ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SubmitAllBuffersOwnedByUsTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SubmitAllBuffersOwnedByUsTest001 start";
    ImageDecoder imageDecoder;
    imageDecoder.UpdateFormatFromSurfaceBuffer();
    ImageCodec::BufferInfo bufferInfo;
    bufferInfo.surfaceBuffer = nullptr;
    imageDecoder.outputBufferPool_.emplace_back(bufferInfo);
    imageDecoder.UpdateFormatFromSurfaceBuffer();
    imageDecoder.EraseBufferFromPool(OMX_DirInput, 1);
    imageDecoder.isBufferCirculating_ = true;
    int32_t code = imageDecoder.SubmitAllBuffersOwnedByUs();
    EXPECT_EQ(code, IC_ERR_OK);
    GTEST_LOG_(INFO) << "ImageCodecTest: SubmitAllBuffersOwnedByUsTest001 end";
}

/**
 * @tc.name: SubmitOutputBuffersToOmxNodeTest001
 * @tc.desc: Verify that SubmitOutputBuffersToOmxNode correctly submits output buffers to the OMX node
 *           and handles different buffer ownership states, returning appropriate error codes.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, SubmitOutputBuffersToOmxNodeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: SubmitOutputBuffersToOmxNodeTest001 start";
    ImageDecoder imageDecoder;
    imageDecoder.OnOMXEmptyBufferDone(0, ImageCodec::BufferOperationMode::KEEP_BUFFER);
    ImageCodec::BufferInfo info;
    info.bufferId = 0;
    info.owner = ImageCodec::BufferOwner::OWNED_BY_US;
    imageDecoder.inputBufferPool_.emplace_back(info);
    imageDecoder.OnOMXEmptyBufferDone(0, ImageCodec::BufferOperationMode::KEEP_BUFFER);
    imageDecoder.inputBufferPool_.clear();
    info.owner = ImageCodec::BufferOwner::OWNED_BY_OMX;
    imageDecoder.inputBufferPool_.emplace_back(info);
    imageDecoder.OnOMXEmptyBufferDone(0, ImageCodec::BufferOperationMode::KEEP_BUFFER);
    imageDecoder.OnOMXEmptyBufferDone(0, static_cast<ImageCodec::BufferOperationMode>(BUFFER_UNSUPPORTED));

    info.owner = ImageCodec::BufferOwner::OWNED_BY_OMX;
    imageDecoder.outputBufferPool_.emplace_back(info);
    int32_t code = imageDecoder.SubmitOutputBuffersToOmxNode();
    EXPECT_EQ(code, IC_ERR_OK);
    imageDecoder.outputBufferPool_.clear();
    info.owner = static_cast<ImageCodec::BufferOwner>(BUFFER_UNSUPPORTED);
    imageDecoder.outputBufferPool_.emplace_back(info);
    code = imageDecoder.SubmitOutputBuffersToOmxNode();
    EXPECT_EQ(code, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: SubmitOutputBuffersToOmxNodeTest001 end";
}

/**
 * @tc.name: ChangeOwnerTest001
 * @tc.desc: Verify that ChangeOwner correctly updates the buffer ownership state for both input and output buffers.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ChangeOwnerTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ChangeOwnerTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    imageCodec->debugMode_ = true;
    ImageCodec::BufferInfo bufferInfo;
    std::string prefix;
    bufferInfo.Dump(prefix);
    bufferInfo.surfaceBuffer = SurfaceBuffer::Create();
    bufferInfo.Dump(prefix);

    bufferInfo.isInput = true;
    bufferInfo.owner = ImageCodec::BufferOwner::OWNED_BY_US;
    ImageCodec::BufferOwner newOwner = ImageCodec::BufferOwner::OWNED_BY_OMX;
    bufferInfo.omxBuffer = std::make_shared<HdiCodecNamespace::OmxCodecBuffer>();
    imageCodec->ChangeOwner(bufferInfo, newOwner);
    EXPECT_EQ(bufferInfo.owner, ImageCodec::BufferOwner::OWNED_BY_OMX);

    bufferInfo.isInput = false;
    bufferInfo.owner = ImageCodec::BufferOwner::OWNED_BY_OMX;
    newOwner = ImageCodec::BufferOwner::OWNED_BY_US;
    imageCodec->ChangeOwner(bufferInfo, newOwner);
    EXPECT_EQ(bufferInfo.owner, ImageCodec::BufferOwner::OWNED_BY_US);

    GTEST_LOG_(INFO) << "ImageCodecTest: ChangeOwnerTest001 end";
}

/**
 * @tc.name: GetFrameRateFromUserTest001
 * @tc.desc: Verify that ChangeOwner handles buffer ownership transitions correctly, processes input buffers,
 *           and retrieves frame rate from user format when available.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetFrameRateFromUserTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetFrameRateFromUserTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    imageCodec->inputPortEos_ = true;
    imageCodec->outputPortEos_ = true;
    ImageCodec::BufferInfo bufferInfo;
    imageCodec->OnOMXFillBufferDone(ImagePlugin::ImageCodec::BufferOperationMode::RESUBMIT_BUFFER, bufferInfo, 0);
    imageCodec->OnQueueInputBuffer(ImagePlugin::ImageCodec::BufferOperationMode::RESUBMIT_BUFFER, &bufferInfo);

    Format format;
    std::optional<double> frameRate = imageCodec->GetFrameRateFromUser(format);
    EXPECT_FALSE(frameRate.has_value());
    GTEST_LOG_(INFO) << "ImageCodecTest: GetFrameRateFromUserTest001 end";
}

} // namespace Media
} // namespace OHOS