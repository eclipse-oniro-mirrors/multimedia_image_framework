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
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
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
    DecodeDfx::Aggregate *reentrantFlush = nullptr;
};

bool AggregateWriter(const DecodeDfx::Window &window, size_t part, void *context)
{
    auto &writes = *static_cast<AggregateWrites *>(context);
    writes.parts.push_back(part);
    writes.windows.push_back(window);
    if (writes.reentrant != nullptr) {
        EXPECT_FALSE(writes.reentrant->Record(SuccessfulSample()));
    }
    if (writes.reentrantFlush != nullptr) {
        // 上报期间的重入 Flush 与提交失败恢复都必须直接返回，不能影响外层分片写入。
        writes.reentrantFlush->Flush(AggregateWriter, &writes);
        writes.reentrantFlush->SubmissionFailed();
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

/**
 * @tc.name: ClassifyNullOptionsTest001
 * @tc.desc: Verify a null options pointer produces an unclassified failure sample.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyNullOptionsTest001, TestSize.Level3)
{
    DecodeDfx::ClassifyRequest request;
    request.options = nullptr;
    request.result = DecodeResult::SUCCESS;
    const auto sample = DecodeDfx::Classify(request);
    EXPECT_EQ(sample.result, DecodeResult::FAILURE);
    for (size_t i = 0; i < DecodeDfx::METRIC_COUNT; ++i) {
        EXPECT_EQ(sample.buckets[i], DecodeDfx::NO_BUCKET);
    }
}

/**
 * @tc.name: ClassifyHeicAliasAndDefaultErrorClassTest001
 * @tc.desc: Verify HEIC aliases share one MIME bucket and failure without error uses the default class.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyHeicAliasAndDefaultErrorClassTest001, TestSize.Level3)
{
    uint16_t aliasBucket = DecodeDfx::NO_BUCKET;
    for (const char *mime : { "image/heic", "image/heifs", "image/heics" }) {
        DecodeInfoOptions options {};
        options.mimeType = mime;
        DecodeDfx::ClassifyRequest request;
        request.options = &options;
        request.result = DecodeResult::SUCCESS;
        request.optionsValid = true;
        const auto sample = DecodeDfx::Classify(request);
        const uint16_t bucket = sample.buckets[DecodeDfx::MIME_RESULT];
        if (aliasBucket == DecodeDfx::NO_BUCKET) {
            aliasBucket = bucket;
        }
        EXPECT_EQ(bucket, aliasBucket);
    }
    EXPECT_NE(aliasBucket, DecodeDfx::NO_BUCKET);

    DecodeInfoOptions options {};
    options.mimeType = "image/jpeg";
    DecodeDfx::ClassifyRequest request;
    request.options = &options;
    request.result = DecodeResult::FAILURE;
    request.error = DecodeError::NONE;
    request.optionsValid = true;
    const auto sample = DecodeDfx::Classify(request);
    // 失败但未给出错误分类时落在默认错误桶 1。
    EXPECT_EQ(sample.buckets[DecodeDfx::ERROR_CLASS], 1U);

    options.memoryType = 99;
    request.contextValid = true;
    const auto outOfRange = DecodeDfx::Classify(request);
    // 越界内存类型归入「其他」桶，公开取值为 0..4。
    EXPECT_GT(outOfRange.buckets[DecodeDfx::MEMORY_TYPE], 4U);
}

/**
 * @tc.name: ClassifyPointTypesTest001
 * @tc.desc: Verify every decode point maps to its own point-result bucket.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyPointTypesTest001, TestSize.Level3)
{
    DecodeInfoOptions options {};
    options.mimeType = "image/jpeg";
    for (auto point : { DecodePoint::NORMAL, DecodePoint::EXTENDED, DecodePoint::HEADER,
        DecodePoint::INCREMENTAL, DecodePoint::THUMBNAIL }) {
        DecodeDfx::ClassifyRequest request;
        request.options = &options;
        request.point = point;
        request.result = DecodeResult::SUCCESS;
        request.optionsValid = true;
        const auto sample = DecodeDfx::Classify(request);
        EXPECT_EQ(sample.buckets[DecodeDfx::POINT_RESULT],
            static_cast<uint16_t>(static_cast<uint16_t>(point) * DecodeDfx::RESULT_KIND_COUNT +
            static_cast<uint16_t>(DecodeResult::SUCCESS)));
    }
}
namespace {
template<size_t N>
uint16_t ExpectedRange(uint64_t value, const std::array<uint64_t, N> &limits)
{
    for (size_t i = 0; i < N; ++i) {
        if (value < limits[i]) {
            return static_cast<uint16_t>(i);
        }
    }
    return static_cast<uint16_t>(N);
}

uint16_t ExpectedSizeBucket(uint64_t value)
{
    constexpr std::array<uint64_t, 8> limits = {
        64ULL << 10, 256ULL << 10, 1ULL << 20, 4ULL << 20,
        16ULL << 20, 64ULL << 20, 256ULL << 20, 1ULL << 30};
    if (value == 0) {
        return 0;
    }
    return static_cast<uint16_t>(1 + ExpectedRange(value, limits));
}

uint16_t ExpectedDimension(int64_t value, size_t slots)
{
    constexpr std::array<uint64_t, 8> limits = {256, 512, 1024, 2048, 4096, 8192, 16384, 32768};
    if (value <= 0) {
        return 0;
    }
    const auto bucket = static_cast<uint16_t>(1 + ExpectedRange(static_cast<uint64_t>(value), limits));
    return std::min<uint16_t>(bucket, static_cast<uint16_t>(slots - 1));
}

DecodeDfx::Sample ClassifyWithOptions(const DecodeInfoOptions &options, bool optionsValid, bool contextValid)
{
    DecodeDfx::ClassifyRequest request;
    request.options = &options;
    request.point = DecodePoint::NORMAL;
    request.result = DecodeResult::SUCCESS;
    request.error = DecodeError::NONE;
    request.optionsValid = optionsValid;
    request.contextValid = contextValid;
    return DecodeDfx::Classify(request);
}
} // namespace

/**
 * @tc.name: ClassifyMimeDictionaryTest001
 * @tc.desc: Every documented MIME type maps to its own MIME bucket.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyMimeDictionaryTest001, TestSize.Level3)
{
    const std::vector<std::string> mimes = {
        "image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp", "image/heif", "image/avif",
        "image/tiff", "image/svg+xml", "image/x-icon", "image/vnd.wap.wbmp", "image/astc",
        "image/x-adobe-dng", "image/x-raw", "", "image/other-format"};
    for (size_t i = 0; i < mimes.size(); ++i) {
        DecodeInfoOptions options {};
        options.mimeType = mimes[i];
        const auto sample = ClassifyWithOptions(options, true, true);
        EXPECT_EQ(sample.buckets[DecodeDfx::MIME_RESULT],
            static_cast<uint16_t>(i) * DecodeDfx::RESULT_KIND_COUNT) << mimes[i];
    }
}

/**
 * @tc.name: ClassifyTextDictionariesTest001
 * @tc.desc: YUV sampling, plugin type and image source names map to their dictionaries.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyTextDictionariesTest001, TestSize.Level3)
{
    struct TextCase {
        std::string value;
        uint16_t expected;
    };
    const std::vector<TextCase> yuvCases = {
        {"4:4:4", 0}, {"4:2:2", 1}, {"4:2:0", 2}, {"4:4:0", 3}, {"4:1:1", 4}, {"4:1:0", 5},
        {"4:0:0", 6}, {"not_yuv", 7}, {"", 8}, {"4:2:2:0", 9}};
    for (const auto &item : yuvCases) {
        DecodeInfoOptions options {};
        options.sourceYuvSampling = item.value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::SOURCE_YUV], item.expected)
            << item.value;
    }

    const std::vector<TextCase> pluginCases = {
        {"ext", 0}, {"jpeg", 1}, {"png", 2}, {"webp", 3}, {"svg", 4}, {"raw", 5}, {"", 6}, {"custom", 7}};
    for (const auto &item : pluginCases) {
        DecodeInfoOptions options {};
        options.pluginType = item.value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::PLUGIN_TYPE], item.expected)
            << item.value;
    }

    const std::vector<TextCase> sourceCases = {
        {"CreateImageSource by istream", 0}, {"CreateImageSource by data", 1},
        {"CreateImageSource by pathName", 2}, {"CreateImageSource by fd", 3},
        {"CreateImageSource by fd offset and length", 4}, {"incremental", 5}, {"", 6}, {"custom", 7}};
    for (const auto &item : sourceCases) {
        DecodeInfoOptions options {};
        options.imageSource = item.value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::IMAGE_SOURCE], item.expected)
            << item.value;
    }

    DecodeInfoOptions incremental {};
    incremental.imageSource = "CreateImageSource by pathName";
    incremental.isIncrementalDecode = true;
    EXPECT_EQ(ClassifyWithOptions(incremental, true, true).buckets[DecodeDfx::IMAGE_SOURCE], 5U);
}

/**
 * @tc.name: ClassifySourceExtensionTest001
 * @tc.desc: Only a cleaned extension or an unknown MIME keeps the extension bucket.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifySourceExtensionTest001, TestSize.Level3)
{
    DecodeInfoOptions known {};
    known.mimeType = "image/jpeg";
    known.sourceFileExtension = "jpeg";
    EXPECT_EQ(ClassifyWithOptions(known, true, true).buckets[DecodeDfx::SOURCE_EXTENSION], 1U);

    DecodeInfoOptions unknownSuffix {};
    unknownSuffix.mimeType = "image/jpeg";
    unknownSuffix.sourceFileExtension = "JPG";
    EXPECT_EQ(ClassifyWithOptions(unknownSuffix, true, true).buckets[DecodeDfx::SOURCE_EXTENSION], 9U);

    DecodeInfoOptions unknownMime {};
    unknownMime.sourceFileExtension.clear();
    EXPECT_EQ(ClassifyWithOptions(unknownMime, true, true).buckets[DecodeDfx::SOURCE_EXTENSION], 8U);

    DecodeInfoOptions knownWithoutSuffix {};
    knownWithoutSuffix.mimeType = "image/png";
    EXPECT_EQ(ClassifyWithOptions(knownWithoutSuffix, true, true).buckets[DecodeDfx::SOURCE_EXTENSION],
        DecodeDfx::NO_BUCKET);
}

/**
 * @tc.name: ClassifyPixelAndMemoryBucketsTest001
 * @tc.desc: Public, SUT and invalid pixel formats and memory types map to their buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyPixelAndMemoryBucketsTest001, TestSize.Level3)
{
    struct BucketCase {
        int32_t value;
        uint16_t expected;
    };
    const std::vector<BucketCase> pixelCases = {
        {-1, 23}, {0, 0}, {17, 17}, {18, 23}, {100, 23}, {101, 18}, {104, 21}, {105, 23}};
    for (const auto &item : pixelCases) {
        DecodeInfoOptions options {};
        options.desirePixelFormat = item.value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::DESIRED_PIXEL_FORMAT], item.expected)
            << item.value;
    }

    const std::vector<BucketCase> memoryCases = {{-1, 7}, {0, 0}, {4, 4}, {5, 7}};
    for (const auto &item : memoryCases) {
        DecodeInfoOptions options {};
        options.memoryType = item.value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::MEMORY_TYPE], item.expected)
            << item.value;
    }

    DecodeInfoOptions noContext {};
    noContext.memorySize = 4096;
    noContext.memoryType = 1;
    noContext.isHardDecode = true;
    const auto noContextSample = ClassifyWithOptions(noContext, false, false);
    EXPECT_EQ(noContextSample.buckets[DecodeDfx::MEMORY_TYPE], 6U);
    EXPECT_EQ(noContextSample.buckets[DecodeDfx::MEMORY_SIZE], 0U);
    EXPECT_EQ(noContextSample.buckets[DecodeDfx::HARD_DECODE], 2U);
}

/**
 * @tc.name: ClassifyColorBucketsTest001
 * @tc.desc: Source and desired color space values map to their own buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyColorBucketsTest001, TestSize.Level3)
{
    const std::vector<int32_t> sourceNames = {0, 4, 3, 2, 27, 1, 24, 25, 15, 14, 9, 10, 19, 20, 26, 5};
    for (size_t i = 0; i < sourceNames.size(); ++i) {
        DecodeInfoOptions options {};
        options.sourceColorSpace = sourceNames[i];
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::SOURCE_COLOR], i)
            << sourceNames[i];
    }
    DecodeInfoOptions unavailable {};
    EXPECT_EQ(ClassifyWithOptions(unavailable, true, true).buckets[DecodeDfx::SOURCE_COLOR], 16U);
    DecodeInfoOptions otherSource {};
    otherSource.sourceColorSpace = 99;
    EXPECT_EQ(ClassifyWithOptions(otherSource, true, true).buckets[DecodeDfx::SOURCE_COLOR], 17U);

    for (int32_t value : {0, 13}) {
        DecodeInfoOptions options {};
        options.desireColorSpace = value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::DESIRED_COLOR_SPACE],
            static_cast<uint16_t>(value)) << value;
    }
    for (int32_t value : {-1, 14}) {
        DecodeInfoOptions options {};
        options.desireColorSpace = value;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::DESIRED_COLOR_SPACE], 15U) << value;
    }
    DecodeInfoOptions invalid {};
    EXPECT_EQ(ClassifyWithOptions(invalid, false, true).buckets[DecodeDfx::DESIRED_COLOR_SPACE], 14U);
}

/**
 * @tc.name: ClassifySampleAndIndexRangesTest001
 * @tc.desc: Sample size and index options map to their range buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifySampleAndIndexRangesTest001, TestSize.Level3)
{
    constexpr std::array<uint64_t, 4> sampleLimits = {1, 2, 4, 8};
    constexpr std::array<uint64_t, 4> indexLimits = {1, 2, 10, 100};
    for (uint32_t sampleSize : {0U, 1U, 2U, 3U, 4U, 8U, 9U, 4096U}) {
        DecodeInfoOptions options {};
        options.sampleSize = sampleSize;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::SAMPLE_SIZE],
            static_cast<uint16_t>(1 + ExpectedRange(sampleSize, sampleLimits))) << sampleSize;
    }
    for (uint32_t index : {0U, 1U, 2U, 9U, 10U, 100U, 1000U}) {
        DecodeInfoOptions options {};
        options.index = index;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::INDEX],
            static_cast<uint16_t>(1 + ExpectedRange(index, indexLimits))) << index;
    }
}

/**
 * @tc.name: ClassifyDensityAndRegionRangesTest001
 * @tc.desc: Fit density and region coordinates map to their range buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyDensityAndRegionRangesTest001, TestSize.Level3)
{
    constexpr std::array<uint64_t, 4> densityLimits = {160, 240, 320, 480};
    constexpr std::array<uint64_t, 4> regionLimits = {1, 256, 1024, 4096};
    for (int32_t density : {0, -5, 1, 159, 160, 240, 480, 1000}) {
        DecodeInfoOptions options {};
        options.fitDensity = density;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::FIT_DENSITY], density <= 0 ? 0 :
            static_cast<uint16_t>(1 + ExpectedRange(static_cast<uint64_t>(density), densityLimits))) << density;
    }
    for (int32_t coord : {-1, 0, 1, 255, 256, 4096, 99999}) {
        DecodeInfoOptions options {};
        options.desireRegionX = coord;
        options.desireRegionY = coord;
        const auto sample = ClassifyWithOptions(options, true, true);
        const uint16_t expected = coord < 0 ? 0 :
            static_cast<uint16_t>(1 + ExpectedRange(static_cast<uint64_t>(coord), regionLimits));
        EXPECT_EQ(sample.buckets[DecodeDfx::REGION_X], expected) << coord;
        EXPECT_EQ(sample.buckets[DecodeDfx::REGION_Y], expected) << coord;
    }
}

/**
 * @tc.name: ClassifyDimensionRangesTest001
 * @tc.desc: Desired size and region width/height options map to dimension buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyDimensionRangesTest001, TestSize.Level3)
{
    for (int32_t dimension : {-1, 0, 255, 256, 1023, 4096, 40000}) {
        DecodeInfoOptions options {};
        options.desireSizeWidth = dimension;
        options.desireSizeHeight = dimension;
        options.desireRegionWidth = dimension;
        options.desireRegionHeight = dimension;
        const auto sample = ClassifyWithOptions(options, true, true);
        const uint16_t expected = ExpectedDimension(dimension, 8);
        EXPECT_EQ(sample.buckets[DecodeDfx::DESIRED_WIDTH], expected) << dimension;
        EXPECT_EQ(sample.buckets[DecodeDfx::DESIRED_HEIGHT], expected) << dimension;
        EXPECT_EQ(sample.buckets[DecodeDfx::REGION_WIDTH], expected) << dimension;
        EXPECT_EQ(sample.buckets[DecodeDfx::REGION_HEIGHT], expected) << dimension;
    }
}

/**
 * @tc.name: ClassifyInvalidOptionsBucketsTest001
 * @tc.desc: Unfilled decode options land in the reserved invalid buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyInvalidOptionsBucketsTest001, TestSize.Level3)
{
    DecodeInfoOptions noOptions {};
    noOptions.sampleSize = 4;
    noOptions.index = 10;
    noOptions.fitDensity = 320;
    noOptions.desireRegionX = 16;
    const auto invalidSample = ClassifyWithOptions(noOptions, false, true);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::DESIRED_PIXEL_FORMAT], 22U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::INVOKE_TYPE], 3U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::EDITABLE], 2U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::SAMPLE_SIZE], 0U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::ROTATE], 5U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::INDEX], 0U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::FIT_DENSITY], 0U);
    EXPECT_EQ(invalidSample.buckets[DecodeDfx::REGION_X], 0U);
}

/**
 * @tc.name: ClassifyRotateTest001
 * @tc.desc: Only 0/90/180/270 are named buckets; other angles are grouped.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyRotateTest001, TestSize.Level3)
{
    const std::vector<std::pair<double, uint16_t>> cases = {
        {0.0, 0}, {90.0, 1}, {180.0, 2}, {270.0, 3}, {45.0, 4}, {-90.0, 4},
        {std::numeric_limits<double>::quiet_NaN(), 5}};
    for (const auto &item : cases) {
        DecodeInfoOptions options {};
        options.rotate = item.first;
        EXPECT_EQ(ClassifyWithOptions(options, true, true).buckets[DecodeDfx::ROTATE], item.second) << item.first;
    }
}

/**
 * @tc.name: ClassifyErrorAndHardDecodeTest001
 * @tc.desc: Failure errors and hard decode diagnostics land in their own buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyErrorAndHardDecodeTest001, TestSize.Level3)
{
    DecodeInfoOptions options {};
    options.mimeType = "image/jpeg";
    for (uint8_t error = 0; error <= static_cast<uint8_t>(DecodeError::POST_PROCESS); ++error) {
        DecodeDfx::ClassifyRequest request;
        request.options = &options;
        request.result = DecodeResult::FAILURE;
        request.error = static_cast<DecodeError>(error);
        request.optionsValid = true;
        request.contextValid = true;
        const auto sample = DecodeDfx::Classify(request);
        EXPECT_EQ(sample.buckets[DecodeDfx::ERROR_CLASS], error == 0 ? 1 : static_cast<uint16_t>(error));
    }
    DecodeInfoOptions hard {};
    hard.isHardDecode = true;
    hard.hardDecodeError = "hard decode failed";
    const auto sample = ClassifyWithOptions(hard, true, true);
    EXPECT_EQ(sample.buckets[DecodeDfx::HARD_DECODE], 1U);
    EXPECT_EQ(sample.buckets[DecodeDfx::HARD_ERROR_CLASS], 7U);
    EXPECT_EQ(sample.buckets[DecodeDfx::ERROR_CLASS], DecodeDfx::NO_BUCKET);
}

/**
 * @tc.name: ClassifyGridAndSizeBucketsTest001
 * @tc.desc: Grid dimensions and source size boundaries map to their buckets.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, ClassifyGridAndSizeBucketsTest001, TestSize.Level3)
{
    for (int32_t grid : {0, 300, 1024, 16384, 100000}) {
        DecodeInfoOptions options {};
        options.heifGridWidth = grid;
        options.heifGridHeight = grid;
        const auto sample = ClassifyWithOptions(options, true, true);
        const uint16_t expected = ExpectedDimension(grid, 6);
        EXPECT_EQ(sample.buckets[DecodeDfx::GRID_WIDTH], expected) << grid;
        EXPECT_EQ(sample.buckets[DecodeDfx::GRID_HEIGHT], expected) << grid;
    }
    for (uint64_t size : {0ULL, 1ULL, (64ULL << 10) - 1, 64ULL << 10, 1ULL << 20, 1ULL << 30, 2ULL << 30}) {
        DecodeInfoOptions options {};
        options.sourceSize = size;
        DecodeDfx::ClassifyRequest request;
        request.options = &options;
        request.result = DecodeResult::SUCCESS;
        request.optionsValid = true;
        const auto sample = DecodeDfx::Classify(request);
        EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_SIZE], ExpectedSizeBucket(size)) << size;
    }
    for (int32_t width : {-1, 0, 300, 8192, 40000}) {
        DecodeInfoOptions options {};
        options.sourceWidth = width;
        options.sourceHeight = width;
        const auto sample = ClassifyWithOptions(options, true, true);
        const uint16_t expected = ExpectedDimension(width, DecodeDfx::METRICS[DecodeDfx::SOURCE_WIDTH].size);
        EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_WIDTH], expected) << width;
        EXPECT_EQ(sample.buckets[DecodeDfx::SOURCE_HEIGHT], expected) << width;
    }
}

/**
 * @tc.name: AggregateClampsBucketsAndResultsTest001
 * @tc.desc: Out-of-range buckets and results are counted in the clamped tail bucket.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, AggregateClampsBucketsAndResultsTest001, TestSize.Level3)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    auto sample = SuccessfulSample();
    sample.buckets[DecodeDfx::MIME_RESULT] = 1000;
    sample.result = static_cast<DecodeResult>(9);
    EXPECT_FALSE(aggregate.Record(sample));
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(sample));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_FALSE(writes.windows.empty());
    const auto &window = writes.windows[0];
    const size_t lastBucket = DecodeDfx::OFFSETS[DecodeDfx::MIME_RESULT] +
        DecodeDfx::METRICS[DecodeDfx::MIME_RESULT].size - 1;
    EXPECT_EQ(window.counters[lastBucket], 2U);
    EXPECT_EQ(window.results[1], 2U);
    EXPECT_EQ(window.results[0], 0U);
}

/**
 * @tc.name: AggregateFlushWithoutReservationTest001
 * @tc.desc: Flush without a reserved window writes nothing and keeps the aggregate usable.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, AggregateFlushWithoutReservationTest001, TestSize.Level3)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_TRUE(writes.parts.empty());
    aggregate.SubmissionFailed();
    EXPECT_FALSE(aggregate.Record(SuccessfulSample()));
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_TRUE(writes.parts.empty());
}

/**
 * @tc.name: AggregateFlushWhileRunningTest001
 * @tc.desc: Reentrant flush and submission failure during reporting are ignored.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, AggregateFlushWhileRunningTest001, TestSize.Level3)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    aggregate.Record(SuccessfulSample());
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(SuccessfulSample()));
    AggregateWrites writes;
    writes.reentrantFlush = &aggregate;
    aggregate.Flush(AggregateWriter, &writes);
    EXPECT_EQ(writes.parts, (std::vector<size_t> {0, 1, 2, 3, 4}));
}

/**
 * @tc.name: AggregateRecordWithoutCostAndSizeTest001
 * @tc.desc: Samples without a valid cost or source size do not update the sums.
 * @tc.type: FUNC
 */
HWTEST_F(DecodeAggregateTest, AggregateRecordWithoutCostAndSizeTest001, TestSize.Level3)
{
    DecodeDfx::Aggregate aggregate(AggregateClock);
    auto sample = SuccessfulSample();
    sample.costValid = false;
    sample.sourceSize = 0;
    aggregate.Record(sample);
    g_aggregateNow.fetch_add(DecodeDfx::WINDOW_MS);
    ASSERT_TRUE(aggregate.Record(sample));
    AggregateWrites writes;
    aggregate.Flush(AggregateWriter, &writes);
    ASSERT_FALSE(writes.windows.empty());
    EXPECT_EQ(writes.windows[0].costValidCount, 0U);
    EXPECT_EQ(writes.windows[0].costSum, 0U);
    EXPECT_EQ(writes.windows[0].sourceSizeValidCount, 0U);
    EXPECT_EQ(writes.windows[0].results[0], 2U);
}

} // namespace Multimedia
} // namespace OHOS