/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include "image_dfx.h"
#include "image_decode_aggregate.h"

using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
static const std::string ERROR_MESSAGE = "ImageEventTest SetDecodeErrorMsg";
class ImageEventTest : public testing::Test {
    public:
        ImageEventTest() {}
        ~ImageEventTest() {}
};

/**
 * @tc.name: ImageEvent001
 * @tc.desc: SetDecodeErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent001 start";
    ImageEvent imageEvent;
    imageEvent.SetDecodeErrorMsg(ERROR_MESSAGE);
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent001 end";
}

/**
 * @tc.name: ImageEvent002
 * @tc.desc: SetIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent002 start";
    ImageEvent imageEvent;
    imageEvent.SetIncrementalDecode();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent002 end";
}

/**
 * @tc.name: ImageEvent003
 * @tc.desc: ReportDecodeInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent003 start";
    ImageEvent imageEvent;
    imageEvent.ReportDecodeInfo();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent003 end";
}

/**
 * @tc.name: ImageEvent004
 * @tc.desc: ReportDecodeFault
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent004 start";
    ImageEvent imageEvent;
    imageEvent.ReportDecodeFault();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent004 end";
}

/**
 * @tc.name: ImageSourceExtension001
 * @tc.desc: Report only a bounded lowercase extension, never a path or invalid suffix.
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageSourceExtension001, TestSize.Level3)
{
    EXPECT_EQ(GetImageFileExtension("/data/private/photo.JPEG"), "jpeg");
    EXPECT_EQ(GetImageFileExtension("C:\\private\\photo.HeIf"), "heif");
    EXPECT_EQ(GetImageFileExtension("/data/a.b/photo"), "unknown");
    EXPECT_EQ(GetImageFileExtension("/data/.hidden"), "unknown");
    EXPECT_EQ(GetImageFileExtension("/data/photo."), "unknown");
    EXPECT_EQ(GetImageFileExtension("/data/photo.a-b"), "unknown");
    EXPECT_EQ(GetImageFileExtension("/data/photo.abcdefghijklmnopq"), "unknown");
    EXPECT_EQ(GetImageFileExtension(""), "unknown");
}

/**
 * @tc.name: ImageSourceExtension002
 * @tc.desc: Resolve a file descriptor suffix without consuming data or closing the descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageSourceExtension002, TestSize.Level3)
{
    char path[] = "/data/local/tmp/image_dfx_XXXXXX.JPEG";
    int fd = mkstemps(path, 5);
    if (fd < 0) {
        char localPath[] = "./image_dfx_XXXXXX.JPEG";
        fd = mkstemps(localPath, 5);
        if (fd < 0) {
            GTEST_LOG_(INFO) << "ImageEventTest: skip fd extension test, mkstemps failed";
            return;
        }
        const auto extension = GetImageFileExtension("", fd);
        const auto position = lseek(fd, 0, SEEK_CUR);
        close(fd);
        std::remove(localPath);
        EXPECT_EQ(extension, "jpeg");
        EXPECT_EQ(position, 0);
        return;
    }
    const auto extension = GetImageFileExtension("", fd);
    const auto position = lseek(fd, 0, SEEK_CUR);
    close(fd);
    std::remove(path);
    EXPECT_EQ(extension, "jpeg");
    EXPECT_EQ(position, 0);
    EXPECT_EQ(GetImageFileExtension("", -1), "unknown");
}

namespace {
constexpr uint64_t TEST_BASE_NOW_MS = 1000;
constexpr uint64_t TEST_SOURCE_SIZE = 1024;
constexpr uint64_t TEST_COST_MS = 5;
constexpr uint64_t TEST_RETRY_PUSH_MS = 123;
constexpr uint64_t TEST_BACKWARD_NOW_MS = 500;

std::atomic<uint64_t> g_aggregateNow {TEST_BASE_NOW_MS};
std::atomic<bool> g_aggregateClockValid {true};
bool AggregateClock(uint64_t &now)
{
    now = g_aggregateNow.load();
    return g_aggregateClockValid.load();
}

DecodeDfx::Sample SuccessfulSample()
{
    DecodeInfoOptions options {};
    options.mimeType = "image/jpeg";
    options.sourceSize = TEST_SOURCE_SIZE;
    options.sourceYuvSampling = "4:2:0";
    DecodeDfx::ClassifyRequest request;
    request.options = &options;
    request.point = DecodePoint::NORMAL;
    request.result = DecodeResult::SUCCESS;
    request.error = DecodeError::NONE;
    request.costMs = TEST_COST_MS;
    request.costValid = true;
    request.optionsValid = true;
    request.contextValid = true;
    return DecodeDfx::Classify(request);
}

struct AggregateWrites {
    std::vector<size_t> parts;
    std::vector<DecodeDfx::Window> windows;
    int failPart = -1;
    DecodeDfx::Aggregate *reentrant = nullptr;
};

bool AggregateWriter(const DecodeDfx::Window &window, size_t part, void *context)
{
    auto &writes = *static_cast<AggregateWrites *>(context);
    writes.parts.push_back(part);
    writes.windows.push_back(window);
    if (writes.reentrant != nullptr) {
        EXPECT_FALSE(writes.reentrant->Record(SuccessfulSample()));
    }
    return static_cast<int>(part) != writes.failPart;
}
} // namespace

class DecodeAggregateTest : public testing::Test {
public:
    void SetUp() override
    {
        g_aggregateNow = TEST_BASE_NOW_MS;
        g_aggregateClockValid = true;
    }
};

/**
 * @tc.name: CountAllRecordsAndHourBoundary
 * @tc.desc: Count every point and rotate only when the elapsed window expires.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, CountAllRecordsAndHourBoundary, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    const auto sample = SuccessfulSample();
    for (int i = 0; i < 100000; ++i) {
        ASSERT_FALSE(aggregate.Record(sample));
    }
    g_aggregateNow = TEST_BASE_NOW_MS + DecodeDfx::WINDOW_MS - 1;
    EXPECT_FALSE(aggregate.Record(sample));
    g_aggregateNow = TEST_BASE_NOW_MS + DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(sample));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_EQ(writes.parts, (std::vector<size_t> {0, 1, 2, 3, 4}));
    const auto &window = writes.windows[0];
    EXPECT_EQ(window.totalCount, 100001U);
    EXPECT_EQ(window.results[0], 100001U);
    EXPECT_EQ(window.results[1], 0U);
    EXPECT_EQ(window.counters[DecodeDfx::Offset(DecodeDfx::MIME_RESULT)], 100001U);
    EXPECT_EQ(window.sourceSizeSum, 100001ULL * 1024);
    EXPECT_EQ(window.costSum, 100001ULL * 5);
    EXPECT_EQ(window.endMs - window.startMs, DecodeDfx::WINDOW_MS);
    EXPECT_LE(sizeof(aggregate), 8192U);
}

/**
 * @tc.name: IdlePeriodDoesNotCreateEmptyWindows
 * @tc.desc: Report the old window on the next call without generating empty windows.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, IdlePeriodDoesNotCreateEmptyWindows, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    g_aggregateNow = TEST_BASE_NOW_MS + 4 * DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_EQ(writes.windows.size(), 5U);
    EXPECT_EQ(writes.windows[0].results[0], 1U);
    EXPECT_EQ(writes.windows[0].endMs, 1000 + DecodeDfx::WINDOW_MS);
    EXPECT_FALSE(writes.windows[0].extended);
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
}

/**
 * @tc.name: PartialWriteRetriesOnlyUnconfirmedParts
 * @tc.desc: Retain failed parts and skip parts already accepted by the writer.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, PartialWriteRetriesOnlyUnconfirmedParts, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    aggregate.Record(SuccessfulSample());
    g_aggregateNow = TEST_BASE_NOW_MS + DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    writes.failPart = 2;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.parts, (std::vector<size_t> {0, 1, 2}));
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    g_aggregateNow.fetch_add(DecodeDfx::RETRY_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    writes.failPart = -1;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.parts, (std::vector<size_t> {0, 1, 2, 2, 3, 4}));
    for (const auto &window : writes.windows) {
        EXPECT_EQ(window.id, 1U);
        EXPECT_EQ(window.results[0], 1U);
    }
}

/**
 * @tc.name: BacklogExtendsWindowWithoutDroppingCounts
 * @tc.desc: Bound pending storage by extending the active window without dropping counts.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, BacklogExtendsWindowWithoutDroppingCounts, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    aggregate.Record(SuccessfulSample());
    g_aggregateNow = TEST_BASE_NOW_MS + DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    aggregate.SubmissionFailed();
    g_aggregateNow = TEST_BASE_NOW_MS + 2 * DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    g_aggregateNow.fetch_add(TEST_RETRY_PUSH_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    writes = {};
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_FALSE(writes.windows.empty());
    EXPECT_EQ(writes.windows[0].results[0], 2U);
    EXPECT_TRUE(writes.windows[0].extended);
    EXPECT_EQ(writes.windows[0].endMs, g_aggregateNow.load());
}

/**
 * @tc.name: ConcurrentRecordAndWriteDoNotLoseCounts
 * @tc.desc: Preserve concurrent counts and allow recording outside the writer lock.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ConcurrentRecordAndWriteDoNotLoseCounts, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    std::vector<std::thread> threads;
    for (int thread = 0; thread < 8; ++thread) {
        threads.emplace_back([&aggregate] {
            const auto sample = SuccessfulSample();
            for (int i = 0; i < 10000; ++i) {
                EXPECT_FALSE(aggregate.Record(sample));
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    writes.reentrant = &aggregate;
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_FALSE(writes.windows.empty());
    EXPECT_EQ(writes.windows[0].results[0], 80000U);
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    writes = {};
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.windows[0].results[0], 7U); // two records plus five made by the writer
}

/**
 * @tc.name: MissingClockPreservesRecordsAndMarksUncertainty
 * @tc.desc: Retain records when the elapsed clock is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, MissingClockPreservesRecordsAndMarksUncertainty, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    g_aggregateClockValid = false;
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    g_aggregateClockValid = true;
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.windows[0].results[0], 2U);
    EXPECT_TRUE(writes.windows[0].clockUncertain);
}

/**
 * @tc.name: BackwardClockDoesNotResetOrLoseCounters
 * @tc.desc: Ignore a backward elapsed clock while preserving counts and uncertainty.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, BackwardClockDoesNotResetOrLoseCounters, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    aggregate.Record(SuccessfulSample());
    g_aggregateNow = TEST_BACKWARD_NOW_MS;
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    g_aggregateNow = TEST_BASE_NOW_MS + DecodeDfx::WINDOW_MS;
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.windows[0].results[0], 2U);
    EXPECT_TRUE(writes.windows[0].clockUncertain);
}

/**
 * @tc.name: SaturatingSumsDoNotWrap
 * @tc.desc: Saturate cumulative values and expose overflow instead of wrapping.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, SaturatingSumsDoNotWrap, TestSize.Level1)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    auto sample = SuccessfulSample();
    sample.sourceSize = UINT64_MAX;
    sample.costMs = UINT64_MAX;
    aggregate.Record(sample);
    aggregate.Record(sample);
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(sample));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.windows[0].sourceSizeSum, UINT64_MAX);
    EXPECT_EQ(writes.windows[0].costSum, UINT64_MAX);
    EXPECT_TRUE(writes.windows[0].saturated);
}

/**
 * @tc.name: ClassifyUnknownsIncrementalAndSizeBoundaries
 * @tc.desc: Keep unknowns distinct and classify incremental waiting and size boundaries.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyUnknownsIncrementalAndSizeBoundaries, TestSize.Level1)
{
    DecodeInfoOptions options {};
    options.isIncrementalDecode = true;
    options.sourceFileExtension = "jpeg";
    options.sourceSize = 65536;
    DecodeDfx::ClassifyRequest request;
    request.options = &options;
    request.point = DecodePoint::INCREMENTAL;
    request.result = DecodeResult::INCOMPLETE;
    request.error = DecodeError::NONE;
    request.optionsValid = false;
    request.contextValid = false;
    const auto sample = DecodeDfx::Classify(request);
    // 增量未完成样本不计入 sourceSize，大小分桶落 0。
    EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_SIZE], 0U);
    EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_EXTENSION], 1U);
    EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_COLOR], 16U);
    EXPECT_EQ(sample.buckets[DecodeDfx::HARD_DECODE], 2U);
    EXPECT_EQ(sample.buckets[DecodeDfx::EDITABLE], 2U);
    EXPECT_EQ(sample.buckets[DecodeDfx::COST_TIME], 0U);
    EXPECT_EQ(sample.buckets[DecodeDfx::POINT_RESULT], 11U);
    EXPECT_EQ(sample.buckets[DecodeDfx::ERROR_CLASS], DecodeDfx::NO_BUCKET);
    options.sourceSize = 65535;
    options.mimeType = "image/jpeg";
    options.sourceFileExtension.clear();
    DecodeDfx::ClassifyRequest nextRequest;
    nextRequest.options = &options;
    nextRequest.point = DecodePoint::NORMAL;
    nextRequest.result = DecodeResult::FAILURE;
    nextRequest.error = DecodeError::OPTIONS;
    nextRequest.costValid = true;
    nextRequest.optionsValid = true;
    nextRequest.contextValid = true;
    const auto next = DecodeDfx::Classify(nextRequest);
    EXPECT_EQ(next.buckets[DecodeDfx::SOURCE_SIZE], 1U);
    EXPECT_EQ(next.buckets[DecodeDfx::SOURCE_EXTENSION], DecodeDfx::NO_BUCKET);
    EXPECT_EQ(next.buckets[DecodeDfx::COST_TIME], 1U);
    EXPECT_EQ(next.buckets[DecodeDfx::ERROR_CLASS], static_cast<uint16_t>(DecodeError::OPTIONS));
}

/**
 * @tc.name: DecodeDfxReadClockTest001
 * @tc.desc: Verify the elapsed clock is readable and monotonic when supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, DecodeDfxReadClockTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: DecodeDfxReadClockTest001 start";
    uint64_t first = 0;
    uint64_t second = 0;
    if (DecodeDfx::ReadClock(first)) {
        ASSERT_TRUE(DecodeDfx::ReadClock(second));
        EXPECT_LE(first, second);
    }
    GTEST_LOG_(INFO) << "ImageEventTest: DecodeDfxReadClockTest001 end";
}
} // namespace Multimedia
} // namespace OHOS