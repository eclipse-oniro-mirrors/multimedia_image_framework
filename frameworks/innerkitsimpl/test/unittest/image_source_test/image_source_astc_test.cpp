/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define private public
#define protected public

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_source.h"
#include "media_errors.h"
#include "source_stream.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
constexpr size_t ASTC_HEADER_SIZE = 16;
constexpr uint32_t NORMAL_HEADER_SIZE = 4;
const std::string IMAGE_INPUT_ADOBERGB_JPEG_PATH = "/data/local/tmp/image/adobergb.jpg";

class ImageSourceAstcTest : public testing::Test {
};

class AstcFormatAgent : public ImagePlugin::AbsImageFormatAgent {
public:
    AstcFormatAgent(std::string format, uint32_t headerSize, bool matches)
        : format_(std::move(format)), headerSize_(headerSize), matches_(matches)
    {
    }

    virtual ~AstcFormatAgent() = default;

    std::string GetFormatType() override
    {
        return format_;
    }

    uint32_t GetHeaderSize() override
    {
        return headerSize_;
    }

    bool CheckFormat(const void *headerData, uint32_t dataSize) override
    {
        if (decodingMutex_ != nullptr) {
            std::thread lockProbe([this]() {
                lockWasAvailable_ = decodingMutex_->try_lock();
                if (lockWasAvailable_) {
                    decodingMutex_->unlock();
                }
            });
            lockProbe.join();
        }
        return matches_;
    }

    void SetDecodingMutex(std::recursive_mutex *decodingMutex)
    {
        decodingMutex_ = decodingMutex;
    }

    bool WasLockAvailable() const
    {
        return lockWasAvailable_;
    }

private:
    std::string format_;
    uint32_t headerSize_;
    bool matches_;
    std::recursive_mutex *decodingMutex_ = nullptr;
    bool lockWasAvailable_ = true;
};

class RecordingSourceStream : public SourceStream {
public:
    explicit RecordingSourceStream(std::vector<uint8_t> data, uint32_t tellBase = 0,
        bool invalidateBorrowedBufferOnSeek = false)
        : data_(std::move(data)), tellBase_(tellBase),
          invalidateBorrowedBufferOnSeek_(invalidateBorrowedBufferOnSeek)
    {
    }

    ~RecordingSourceStream() override = default;

    bool Read(uint32_t desiredSize, ImagePlugin::DataStreamBuffer &outData) override
    {
        if (!Peek(desiredSize, outData)) {
            return false;
        }
        position_ += outData.dataSize;
        return true;
    }

    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        if (!Peek(desiredSize, outBuffer, bufferSize, readSize)) {
            return false;
        }
        position_ += readSize;
        return true;
    }

    bool Peek(uint32_t desiredSize, ImagePlugin::DataStreamBuffer &outData) override
    {
        peekSizes_.push_back(desiredSize);
        if (desiredSize == 0 || desiredSize > data_.size() - position_) {
            return false;
        }
        outData.inputStreamBuffer = data_.data() + position_;
        outData.bufferSize = data_.size() - position_;
        outData.dataSize = desiredSize;
        hasBorrowedBuffer_ = true;
        return true;
    }

    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        peekSizes_.push_back(desiredSize);
        if (outBuffer == nullptr || desiredSize > bufferSize || desiredSize > data_.size() - position_) {
            return false;
        }
        std::copy_n(data_.data() + position_, desiredSize, outBuffer);
        readSize = desiredSize;
        return true;
    }

    uint32_t Tell() override
    {
        return tellBase_ + position_;
    }

    bool Seek(uint32_t position) override
    {
        if (position > data_.size()) {
            return false;
        }
        if (invalidateBorrowedBufferOnSeek_ && hasBorrowedBuffer_) {
            std::fill_n(data_.begin(), std::min<size_t>(NORMAL_HEADER_SIZE, data_.size()), 0);
            hasBorrowedBuffer_ = false;
        }
        position_ = position;
        return true;
    }

    size_t GetStreamSize() override
    {
        return data_.size();
    }

    uint8_t *GetDataPtr() override
    {
        return data_.data();
    }

    uint32_t GetStreamType() override
    {
        return ImagePlugin::BUFFER_SOURCE_TYPE;
    }

    bool IsStreamCompleted() override
    {
        return true;
    }

    const std::vector<uint32_t> &GetPeekSizes() const
    {
        return peekSizes_;
    }

private:
    std::vector<uint8_t> data_;
    std::vector<uint32_t> peekSizes_;
    uint32_t position_ = 0;
    uint32_t tellBase_ = 0;
    bool invalidateBorrowedBufferOnSeek_ = false;
    bool hasBorrowedBuffer_ = false;
};

class ScopedFormatAgent {
public:
    ScopedFormatAgent(ImageSource::FormatAgentMap &formatAgentMap, const std::string &format,
        ImagePlugin::AbsImageFormatAgent *agent) : formatAgentMap_(formatAgentMap), format_(format)
    {
        inserted_ = formatAgentMap_.emplace(format_, agent).second;
    }

    ~ScopedFormatAgent()
    {
        if (inserted_) {
            formatAgentMap_.erase(format_);
        }
    }

    bool IsInserted() const
    {
        return inserted_;
    }

private:
    ImageSource::FormatAgentMap &formatAgentMap_;
    std::string format_;
    bool inserted_ = false;
};

std::vector<uint8_t> CreateAstcData(bool includeDimensions = false)
{
    std::vector<uint8_t> astcData(ASTC_HEADER_SIZE, 0);
    astcData[0] = 0x13;
    astcData[1] = 0xAB;
    astcData[2] = 0xA1;
    astcData[3] = 0x5C;
    if (includeDimensions) {
        astcData[4] = 4;
        astcData[5] = 4;
        astcData[7] = 1;
        astcData[10] = 1;
    }
    return astcData;
}
} // namespace

/**
 * @tc.name: OnSourceUnresolvedNormalFormatBeforeAstc001
 * @tc.desc: Verify normal format detection reads its header before ASTC fallback detection.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, OnSourceUnresolvedNormalFormatBeforeAstc001, TestSize.Level1)
{
    const std::string format = "image/test-normal-first";
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(std::vector<uint8_t>(ASTC_HEADER_SIZE, 0));
    auto *recordingStream = stream.get();
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);

    auto agent = std::make_unique<AstcFormatAgent>(format, NORMAL_HEADER_SIZE, true);
    ScopedFormatAgent scopedAgent(imageSource->formatAgentMap_, format, agent.get());
    ASSERT_TRUE(scopedAgent.IsInserted());

    imageSource->sourceInfo_.encodedFormat = format;
    imageSource->decodeState_ = SourceDecodingState::UNRESOLVED;
    imageSource->isAstc_.reset();

    EXPECT_EQ(imageSource->OnSourceUnresolved(), SUCCESS);
    const auto &peekSizes = recordingStream->GetPeekSizes();
    ASSERT_FALSE(peekSizes.empty());
    EXPECT_EQ(peekSizes.front(), NORMAL_HEADER_SIZE);
    EXPECT_EQ(peekSizes.size(), 1U);
    EXPECT_EQ(imageSource->sourceInfo_.encodedFormat, format);
}

/**
 * @tc.name: OnSourceUnresolvedAstcFallback001
 * @tc.desc: Verify ASTC is detected after a hinted normal format does not match.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, OnSourceUnresolvedAstcFallback001, TestSize.Level1)
{
    const std::string format = "image/test-astc-fallback";
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(CreateAstcData(true));
    auto *recordingStream = stream.get();
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);

    auto agent = std::make_unique<AstcFormatAgent>(format, NORMAL_HEADER_SIZE, false);
    ScopedFormatAgent scopedAgent(imageSource->formatAgentMap_, format, agent.get());
    ASSERT_TRUE(scopedAgent.IsInserted());

    imageSource->sourceInfo_.encodedFormat = format;
    imageSource->decodeState_ = SourceDecodingState::UNRESOLVED;
    imageSource->isAstc_.reset();

    EXPECT_EQ(imageSource->OnSourceUnresolved(), SUCCESS);
    const auto &peekSizes = recordingStream->GetPeekSizes();
    ASSERT_EQ(peekSizes.size(), 2U);
    EXPECT_EQ(peekSizes[0], NORMAL_HEADER_SIZE);
    EXPECT_EQ(peekSizes[1], ASTC_HEADER_SIZE);
    EXPECT_EQ(imageSource->sourceInfo_.encodedFormat, "image/astc");
    ASSERT_TRUE(imageSource->isAstc_.has_value());
    EXPECT_TRUE(imageSource->isAstc_.value());
}

/**
 * @tc.name: CreatePixelMapExHoldsDecodingLockDuringFormatResolution001
 * @tc.desc: Verify format state resolution in CreatePixelMapEx is protected by the ImageSource decoding lock.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, CreatePixelMapExHoldsDecodingLockDuringFormatResolution001, TestSize.Level1)
{
    const std::string format = "image/test-create-pixel-map-ex-lock";
    SourceOptions sourceOpts;
    auto stream = std::make_unique<RecordingSourceStream>(std::vector<uint8_t>(ASTC_HEADER_SIZE, 0));
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), sourceOpts);
    ASSERT_NE(imageSource, nullptr);

    auto agent = std::make_unique<AstcFormatAgent>(format, NORMAL_HEADER_SIZE, true);
    agent->SetDecodingMutex(&imageSource->decodingMutex_);
    ScopedFormatAgent scopedAgent(imageSource->formatAgentMap_, format, agent.get());
    ASSERT_TRUE(scopedAgent.IsInserted());

    imageSource->sourceInfo_.encodedFormat = format;
    imageSource->decodeState_ = SourceDecodingState::UNRESOLVED;
    DecodeOptions decodeOpts;
    uint32_t errorCode = SUCCESS;
    (void)imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);

    EXPECT_FALSE(agent->WasLockAvailable());
}

/**
 * @tc.name: IsASTCSourceCache001
 * @tc.desc: Verify ASTC source detection is cached after the first successful header read.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, IsASTCSourceCache001, TestSize.Level1)
{
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(CreateAstcData());
    auto *recordingStream = stream.get();
    ASSERT_TRUE(recordingStream->Seek(NORMAL_HEADER_SIZE));
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);
    imageSource->isAstc_.reset();

    EXPECT_TRUE(imageSource->IsASTCSource());
    EXPECT_TRUE(imageSource->IsASTCSource());
    const auto &peekSizes = recordingStream->GetPeekSizes();
    ASSERT_EQ(peekSizes.size(), 1U);
    EXPECT_EQ(peekSizes.front(), ASTC_HEADER_SIZE);
    EXPECT_EQ(recordingStream->Tell(), NORMAL_HEADER_SIZE);
}

/**
 * @tc.name: IsASTCSourceUsesBorrowedBufferBeforeSeek001
 * @tc.desc: Verify ASTC detection reads the borrowed stream buffer before the next stream operation invalidates it.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, IsASTCSourceUsesBorrowedBufferBeforeSeek001, TestSize.Level1)
{
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(CreateAstcData(), 0, true);
    auto *recordingStream = stream.get();
    ASSERT_TRUE(recordingStream->Seek(NORMAL_HEADER_SIZE));
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);
    imageSource->isAstc_.reset();

    EXPECT_TRUE(imageSource->IsASTCSource());
    EXPECT_EQ(recordingStream->Tell(), NORMAL_HEADER_SIZE);
}

/**
 * @tc.name: IsASTCSourceRestoresRelativePositionForAbsoluteTell001
 * @tc.desc: Verify ASTC detection restores a relative stream position when Tell includes a non-zero base offset.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, IsASTCSourceRestoresRelativePositionForAbsoluteTell001, TestSize.Level1)
{
    constexpr uint32_t tellBase = 8;
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(CreateAstcData(), tellBase);
    auto *recordingStream = stream.get();
    ASSERT_TRUE(recordingStream->Seek(NORMAL_HEADER_SIZE));
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);
    imageSource->isAstc_.reset();

    EXPECT_TRUE(imageSource->IsASTCSource());
    EXPECT_EQ(recordingStream->Tell(), tellBase + NORMAL_HEADER_SIZE);
}

/**
 * @tc.name: IsASTCSourceKeepsEofPosition001
 * @tc.desc: Verify ASTC fallback does not move a source stream that is already positioned at EOF.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, IsASTCSourceKeepsEofPosition001, TestSize.Level1)
{
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(std::vector<uint8_t>(ASTC_HEADER_SIZE, 0));
    auto *recordingStream = stream.get();
    ASSERT_TRUE(recordingStream->Seek(ASTC_HEADER_SIZE));
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);
    imageSource->isAstc_.reset();

    EXPECT_FALSE(imageSource->IsASTCSource());
    EXPECT_EQ(recordingStream->Tell(), ASTC_HEADER_SIZE);
    EXPECT_TRUE(recordingStream->GetPeekSizes().empty());
}

/**
 * @tc.name: OnSourceUnresolvedShortInputNotAstc001
 * @tc.desc: Verify short input keeps the normal format error when ASTC fallback cannot read a full header.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, OnSourceUnresolvedShortInputNotAstc001, TestSize.Level1)
{
    constexpr size_t shortDataSize = 8;
    const std::string format = "image/test-short-input";
    SourceOptions opts;
    auto stream = std::make_unique<RecordingSourceStream>(std::vector<uint8_t>(shortDataSize, 0));
    auto *recordingStream = stream.get();
    auto imageSource = std::make_unique<ImageSource>(std::move(stream), opts);
    ASSERT_NE(imageSource, nullptr);

    auto agent = std::make_unique<AstcFormatAgent>(format, NORMAL_HEADER_SIZE, false);
    ScopedFormatAgent scopedAgent(imageSource->formatAgentMap_, format, agent.get());
    ASSERT_TRUE(scopedAgent.IsInserted());

    imageSource->sourceInfo_.encodedFormat = format;
    imageSource->decodeState_ = SourceDecodingState::UNRESOLVED;
    imageSource->isAstc_.reset();

    EXPECT_NE(imageSource->OnSourceUnresolved(), SUCCESS);
    const auto &peekSizes = recordingStream->GetPeekSizes();
    ASSERT_EQ(peekSizes.size(), 2U);
    EXPECT_EQ(peekSizes[0], NORMAL_HEADER_SIZE);
    EXPECT_EQ(peekSizes[1], ASTC_HEADER_SIZE);
    EXPECT_FALSE(imageSource->isAstc_.has_value());
    EXPECT_FALSE(ImageSource::IsASTC(recordingStream->GetDataPtr(), shortDataSize));
}

#ifdef IMAGE_COLORSPACE_FLAG
/**
 * @tc.name: CreatePixelAstcFromImageFilePreservesColorSpace001
 * @tc.desc: Verify that decoding a JPEG to ASTC_4x4 preserves the source color space through the ASTC encoding stage.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceAstcTest, CreatePixelAstcFromImageFilePreservesColorSpace001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_ADOBERGB_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::ASTC_4x4;
    auto pixelMap = imageSource->CreatePixelAstcFromImageFile(0, decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->InnerGetGrColorSpace().GetColorSpaceName(),
        ColorManager::ColorSpaceName::ADOBE_RGB);
}
#endif
} // namespace Media
} // namespace OHOS
