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

#ifndef IMAGE_DECODE_AGGREGATE_H
#define IMAGE_DECODE_AGGREGATE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include "image_dfx.h"

namespace OHOS {
namespace Media {
namespace DecodeDfx {
constexpr uint64_t WINDOW_MS = 3600000;
constexpr uint64_t RETRY_MS = 60000;
constexpr size_t PART_COUNT = 5;
constexpr uint16_t NO_BUCKET = UINT16_MAX;
// 成功/失败/不完整三类结果计数，与 MIME/POINT 桶的结果乘数保持一致。
inline constexpr size_t RESULT_KIND_COUNT = 3;
// 双窗口轮转：当前写入窗口与待上报窗口。
inline constexpr size_t WINDOW_COUNT = 2;

enum Metric : size_t {
    MIME_RESULT, SOURCE_COLOR, SOURCE_YUV, SOURCE_EXTENSION, SOURCE_SIZE, SOURCE_WIDTH, SOURCE_HEIGHT,
    COST_TIME, MEMORY_SIZE, MEMORY_TYPE, IMAGE_SOURCE, INVOKE_TYPE, HARD_DECODE, DESIRED_PIXEL_FORMAT,
    DESIRED_COLOR_SPACE, PLUGIN_TYPE, SAMPLE_SIZE, ROTATE, EDITABLE, INDEX, FIT_DENSITY, DESIRED_WIDTH,
    DESIRED_HEIGHT, REGION_WIDTH, REGION_HEIGHT, REGION_X, REGION_Y, GRID_WIDTH, GRID_HEIGHT,
    ERROR_CLASS, HARD_ERROR_CLASS, POINT_RESULT, METRIC_COUNT
};

struct MetricSpec {
    const char *name;
    uint16_t size;
    uint8_t part;
};

// 桶字典变更时必须同时提升 schema 版本。
inline constexpr std::array<MetricSpec, METRIC_COUNT> METRICS = {{
    {"MIME_RESULT_COUNTS", 48, 1}, {"SOURCE_COLOR_COUNTS", 18, 1}, {"SOURCE_YUV_COUNTS", 10, 1},
    {"SOURCE_EXTENSION_COUNTS", 10, 1}, {"SOURCE_SIZE_COUNTS", 10, 2}, {"SOURCE_WIDTH_COUNTS", 10, 2},
    {"SOURCE_HEIGHT_COUNTS", 10, 2}, {"COST_TIME_COUNTS", 10, 2}, {"MEMORY_SIZE_COUNTS", 10, 2},
    {"MEMORY_TYPE_COUNTS", 8, 2}, {"IMAGE_SOURCE_COUNTS", 8, 2}, {"INVOKE_TYPE_COUNTS", 4, 3},
    {"HARD_DECODE_COUNTS", 3, 2}, {"DESIRED_PIXEL_FORMAT_COUNTS", 24, 3},
    {"DESIRED_COLOR_SPACE_COUNTS", 16, 3}, {"PLUGIN_TYPE_COUNTS", 8, 1}, {"SAMPLE_SIZE_COUNTS", 6, 3},
    {"ROTATE_COUNTS", 6, 3}, {"EDITABLE_COUNTS", 3, 3}, {"INDEX_COUNTS", 6, 3},
    {"FIT_DENSITY_COUNTS", 6, 3}, {"DESIRED_WIDTH_COUNTS", 8, 3}, {"DESIRED_HEIGHT_COUNTS", 8, 3},
    {"REGION_WIDTH_COUNTS", 8, 3}, {"REGION_HEIGHT_COUNTS", 8, 3}, {"REGION_X_COUNTS", 6, 3},
    {"REGION_Y_COUNTS", 6, 3}, {"GRID_WIDTH_COUNTS", 6, 1}, {"GRID_HEIGHT_COUNTS", 6, 1},
    {"ERROR_CLASS_COUNTS", 16, 4}, {"HARD_ERROR_CLASS_COUNTS", 8, 4}, {"POINT_RESULT_COUNTS", 15, 0}
}};

constexpr size_t Offset(size_t metric)
{
    size_t offset = 0;
    for (size_t i = 0; i < metric; ++i) {
        offset += METRICS[i].size;
    }
    return offset;
}

constexpr std::array<size_t, METRIC_COUNT> MakeOffsets()
{
    std::array<size_t, METRIC_COUNT> offsets {};
    for (size_t i = 0; i < METRIC_COUNT; ++i) {
        offsets[i] = Offset(i);
    }
    return offsets;
}

inline constexpr auto OFFSETS = MakeOffsets();
constexpr size_t COUNTER_COUNT = Offset(METRIC_COUNT);
static_assert(COUNTER_COUNT == 329);

struct Sample {
    std::array<uint16_t, METRIC_COUNT> buckets {};
    DecodeResult result = DecodeResult::FAILURE;
    uint64_t costMs = 0;
    uint64_t sourceSize = 0;
    bool costValid = false;
};

struct Window {
    std::array<uint64_t, COUNTER_COUNT> counters {};
    std::array<uint64_t, RESULT_KIND_COUNT> results {};
    uint64_t totalCount = 0;
    uint64_t id = 0;
    uint64_t startMs = 0;
    uint64_t endMs = 0;
    uint64_t costSum = 0;
    uint64_t costMax = 0;
    uint64_t costValidCount = 0;
    uint64_t sourceSizeSum = 0;
    uint64_t sourceSizeMax = 0;
    uint64_t sourceSizeValidCount = 0;
    bool initialized = false;
    bool clockValid = false;
    bool clockUncertain = false;
    bool extended = false;
    bool saturated = false;
};

class Aggregate {
public:
    using Clock = bool (*)(uint64_t &);
    using Writer = bool (*)(const Window &, size_t, void *);
    explicit Aggregate(Clock clock) : clock_(clock) {}
    bool Record(const Sample &sample);
    void Flush(Writer writer, void *context);
    void SubmissionFailed();

private:
    void Add(Window &window, const Sample &sample);
    uint64_t Now(bool &valid);
    std::mutex mutex_;
    std::array<Window, WINDOW_COUNT> windows_ {};
    Clock clock_;
    uint64_t lastNow_ = 0;
    uint64_t retryAt_ = 0;
    uint64_t nextId_ = 1;
    size_t active_ = 0;
    int pending_ = -1;
    uint8_t completed_ = 0;
    bool reserved_ = false;
    bool running_ = false;
};
static_assert(sizeof(Aggregate) <= 8192, "Decode counters must fit the per-process memory budget");

// 解码打点入参聚合，避免分类与上报接口的过长参数列表。
struct ClassifyRequest {
    const DecodeInfoOptions *options = nullptr;
    DecodePoint point = DecodePoint::NORMAL;
    DecodeResult result = DecodeResult::SUCCESS;
    DecodeError error = DecodeError::NONE;
    uint64_t costMs = 0;
    bool costValid = false;
    bool optionsValid = false;
    bool contextValid = false;
};

Sample Classify(const ClassifyRequest &request);
bool ReadClock(uint64_t &nowMs);
void Record(const ClassifyRequest &request);
} // namespace DecodeDfx
} // namespace Media
} // namespace OHOS
#endif
