/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <vector>

#include "include/core/SkStream.h"
#include "image_data_writer.h"

using namespace testing::ext;

namespace OHOS::ImagePlugin {
namespace {
constexpr uint32_t JPEG_SOI_SIZE = 2;
constexpr uint32_t JPEG_LENGTH_FIELD_SIZE = 2;
constexpr uint32_t JPEG_SIGNATURE_SIZE = 8;
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP11 = 0xEB;
constexpr uint8_t JPEG_SOI_MARKER = 0xD8;
constexpr uint8_t JPEG_BYTE_SHIFT = 8;
constexpr uint32_t MAX_C2PA_DATA_SIZE_IN_BYTES = 1U << 22; // 4MB

// An SkWStream that records written bytes into a vector and can inject write
// failures after a configurable number of successful calls.
class RecordingSkWStream : public SkWStream {
public:
    // succeedOnFirstNWrites >= 0: first N writes succeed, subsequent writes fail.
    // succeedOnFirstNWrites = -1 (default): all writes succeed.
    explicit RecordingSkWStream(int32_t succeedOnFirstNWrites = -1)
        : succeedOnFirstNWrites_(succeedOnFirstNWrites) {}

    bool write(const void* buffer, size_t size) override
    {
        if (succeedOnFirstNWrites_ >= 0 && callCount_ >= static_cast<uint32_t>(succeedOnFirstNWrites_)) {
            return false;
        }
        callCount_++;
        const uint8_t* bytes = static_cast<const uint8_t*>(buffer);
        written_.insert(written_.end(), bytes, bytes + size);
        return true;
    }

    size_t bytesWritten() const override
    {
        return written_.size();
    }

    const std::vector<uint8_t>& written() const
    {
        return written_;
    }

private:
    int32_t succeedOnFirstNWrites_ = -1;
    uint32_t callCount_ = 0;
    std::vector<uint8_t> written_;
};

// Build a minimal valid JPEG SOI followed by some payload data.
static std::vector<uint8_t> MakeValidJpeg(uint32_t extraSize = 16)
{
    std::vector<uint8_t> data(JPEG_SOI_SIZE + extraSize);
    data[0] = JPEG_MARKER_PREFIX;
    data[1] = JPEG_SOI_MARKER;
    for (uint32_t i = 0; i < extraSize; i++) {
        data[JPEG_SOI_SIZE + i] = static_cast<uint8_t>(i);
    }
    return data;
}

// Verify the output stream has valid SOI + APP11 C2PA structure.
static void VerifyOutputHasC2paStructure(const uint8_t* output, size_t outputSize,
    const uint8_t* originalJpeg, size_t originalJpegSize, uint32_t expectedSegments)
{
    ASSERT_GE(outputSize, JPEG_SOI_SIZE);
    EXPECT_EQ(output[0], JPEG_MARKER_PREFIX);
    EXPECT_EQ(output[1], JPEG_SOI_MARKER);

    size_t offset = JPEG_SOI_SIZE;
    for (uint32_t segIdx = 0; segIdx < expectedSegments; segIdx++) {
        ASSERT_LE(offset + JPEG_LENGTH_FIELD_SIZE + JPEG_SIGNATURE_SIZE, outputSize);
        // APP11 marker
        EXPECT_EQ(output[offset], JPEG_MARKER_PREFIX);
        EXPECT_EQ(output[offset + 1], JPEG_MARKER_APP11);
        // segment length (big-endian)
        uint32_t segLen = (static_cast<uint32_t>(output[offset + 2]) << JPEG_BYTE_SHIFT) |
            static_cast<uint32_t>(output[offset + 3]);
        ASSERT_LE(offset + JPEG_LENGTH_FIELD_SIZE + segLen, outputSize);
        // signature: "JP" + 0x02 + 0x11 + 0x00 + 0x00 + 0x00 + segmentIndex
        EXPECT_EQ(output[offset + 4], 0x4A); // 'J'
        EXPECT_EQ(output[offset + 5], 0x50); // 'P'
        EXPECT_EQ(output[offset + 6], 0x02);
        EXPECT_EQ(output[offset + 7], 0x11);
        EXPECT_EQ(output[offset + 8], 0x00);
        EXPECT_EQ(output[offset + 9], 0x00);
        EXPECT_EQ(output[offset + 10], 0x00);
        EXPECT_EQ(output[offset + 11], static_cast<uint8_t>(segIdx + 1));

        offset += JPEG_LENGTH_FIELD_SIZE + segLen;
    }

    // After all segments, remaining output must match original JPEG payload (after SOI).
    size_t remainingOutput = outputSize - offset;
    size_t remainingJpeg = originalJpegSize - JPEG_SOI_SIZE;
    ASSERT_EQ(remainingOutput, remainingJpeg);
    for (size_t i = 0; i < remainingJpeg; i++) {
        EXPECT_EQ(output[offset + i], originalJpeg[JPEG_SOI_SIZE + i]);
    }
}
} // namespace

class ImageDataWriterTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: WriteJpegC2paDataToStream_001
 * @tc.desc: Normal: valid JPEG with 1KB reserved C2PA space
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_001";
    auto jpeg = MakeValidJpeg(64);
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_TRUE(result);
    ASSERT_GT(output.bytesWritten(), jpeg.size());
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_001";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_002
 * @tc.desc: Minimum valid reserved size creates one APP11 segment
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_002";
    auto jpeg = MakeValidJpeg(32);
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), JPEG_SIGNATURE_SIZE);
    ASSERT_TRUE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_002";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_003
 * @tc.desc: Max reserved size (4MB) - verify no crash with large allocation
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_003";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), MAX_C2PA_DATA_SIZE_IN_BYTES);
    ASSERT_TRUE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_003";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_004
 * @tc.desc: Reserved size = 0, should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_004";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 0);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_004";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_005
 * @tc.desc: Reserved size exceeds MAX_C2PA_DATA_SIZE, should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_005";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), MAX_C2PA_DATA_SIZE_IN_BYTES + 1);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_005";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_006
 * @tc.desc: Null JPEG data pointer, should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_006";
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, nullptr, 2, 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_006";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_007
 * @tc.desc: JPEG data too small (< 2 bytes), should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_007";
    uint8_t data[1] = {0xFF};
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, data, 1, 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_007";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_008
 * @tc.desc: Invalid JPEG - first byte not 0xFF, should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_008";
    uint8_t data[2] = {0x00, JPEG_SOI_MARKER};
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, data, 2, 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_008";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_009
 * @tc.desc: Invalid JPEG - second byte not 0xD8, should return false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_009";
    uint8_t data[2] = {JPEG_MARKER_PREFIX, 0x00};
    RecordingSkWStream output;
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, data, 2, 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_009";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_010
 * @tc.desc: Multi-segment with remainder adjustment and zeroSize == 0 in last segment
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_010";
    auto jpeg = MakeValidJpeg(32);
    RecordingSkWStream output;
    // reservedSize=64512 -> sizeInKilobytes=64 -> reserveSize=65538
    // segment 1: 65528 (adjusted due to remainder=3), remaining=10
    // segment 2: 10 -> paddingSize=0 -> zeroSize=0 -> direct return true
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 64512);
    ASSERT_TRUE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_010";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_011
 * @tc.desc: Single segment: verify output structure (SOI, APP11, C2PA hint, payload)
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_011";
    auto jpeg = MakeValidJpeg(64);
    RecordingSkWStream output;
    // reservedSize=4096 -> sizeInKilobytes=4 -> reserveSize=4098, single segment
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 4096);
    ASSERT_TRUE(result);

    VerifyOutputHasC2paStructure(output.written().data(), output.written().size(),
        jpeg.data(), jpeg.size(), 1);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_011";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_012
 * @tc.desc: Multi-segment (3 segments): verify output structure
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_012";
    auto jpeg = MakeValidJpeg(128);
    RecordingSkWStream output;
    // reservedSize=128*1024 -> sizeInKilobytes=128 -> reserveSize=131074
    // segment 1: 65535 (no adj), remaining=65539
    // segment 2: 65529 (adjusted due to remainder=4), remaining=10
    // segment 3: 10 -> zeroSize=0
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(output, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 128 * 1024);
    ASSERT_TRUE(result);

    VerifyOutputHasC2paStructure(output.written().data(), output.written().size(),
        jpeg.data(), jpeg.size(), 3);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_012";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_013
 * @tc.desc: Write failure on SOI: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_013";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(0); // fail on first write (SOI)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_013";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_014
 * @tc.desc: Write failure on APP11 header: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_014";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(1); // fail on second write (APP11 header)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_014";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_015
 * @tc.desc: Write failure on C2PA signature: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_015";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(2); // fail on third write (signature)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_015";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_016
 * @tc.desc: Write failure on C2PA hint: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_016, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_016";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(3); // fail on fourth write (C2PA hint)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_016";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_017
 * @tc.desc: Write failure on zero padding: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_017, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_017";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(4); // fail on fifth write (zero padding)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_017";
}

/**
 * @tc.name: WriteJpegC2paDataToStream_018
 * @tc.desc: Write failure on payload after segments: mock SkWStream returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataWriterTest, WriteJpegC2paDataToStream_018, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ImageDataWriterTest-begin WriteJpegC2paDataToStream_018";
    auto jpeg = MakeValidJpeg(16);
    RecordingSkWStream failStream(5); // fail on sixth write (payload after segments)
    bool result = ImageDataWriter::WriteJpegC2paDataToStream(failStream, jpeg.data(),
        static_cast<uint32_t>(jpeg.size()), 1024);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageDataWriterTest-end WriteJpegC2paDataToStream_018";
}
} // namespace OHOS::ImagePlugin