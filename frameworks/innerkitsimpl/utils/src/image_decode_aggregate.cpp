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

#include "image_decode_aggregate.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <new>
#include <string_view>
#include <ctime>

#if !defined(CROSS_PLATFORM)
#include <cstring>
#include <atomic>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include "ffrt.h"
#include "hisysevent.h"
#include "image_utils.h"
#endif

namespace OHOS {
namespace Media {
namespace DecodeDfx {
namespace {
constexpr uint8_t ALL_PARTS = (1U << PART_COUNT) - 1;
// 字典表尾部保留 unknown 与 other 两个提示桶。
constexpr size_t DICT_RESERVED_SLOTS = 2;

void Increase(uint64_t &value, uint64_t amount, bool &saturated)
{
    if (amount > UINT64_MAX - value) {
        value = UINT64_MAX;
        saturated = true;
    } else {
        value += amount;
    }
}

template<size_t N>
uint16_t Dictionary(const std::string &value, const std::array<std::string_view, N> &names)
{
    if (value.empty()) {
        return static_cast<uint16_t>(N - DICT_RESERVED_SLOTS); // unknown, then other
    }
    for (size_t i = 0; i < N; ++i) {
        if (value == names[i]) {
            return static_cast<uint16_t>(i);
        }
    }
    return static_cast<uint16_t>(N - 1);
}

template<size_t N>
uint16_t Range(uint64_t value, const std::array<uint64_t, N> &limits)
{
    for (size_t i = 0; i < N; ++i) {
        if (value < limits[i]) {
            return static_cast<uint16_t>(i);
        }
    }
    return N;
}

uint16_t SizeBucket(uint64_t value)
{
    if (value == 0) {
        return 0;
    }
    constexpr std::array<uint64_t, 8> limits = {
        64ULL << 10, 256ULL << 10, 1ULL << 20, 4ULL << 20,
        16ULL << 20, 64ULL << 20, 256ULL << 20, 1ULL << 30};
    return 1 + Range(value, limits);
}

uint16_t Dimension(int64_t value, size_t slots)
{
    if (value <= 0) {
        return 0;
    }
    // 较小的请求/网格直方图会把最后两个正值区间合并。
    constexpr std::array<uint64_t, 8> limits = {256, 512, 1024, 2048, 4096, 8192, 16384, 32768};
    return std::min<uint16_t>(1 + Range(static_cast<uint64_t>(value), limits), static_cast<uint16_t>(slots - 1));
}

// PixelMap 公开像素格式取值 0..17 直接入桶；SUT 像素格式 101..104 映射到后续桶段。
constexpr int32_t MAX_PUBLIC_PIXEL_FORMAT = 17;
constexpr int32_t SUT_PIXEL_FORMAT_BASE = 101;
constexpr int32_t SUT_PIXEL_FORMAT_MAX = 104;
constexpr uint16_t SUT_PIXEL_BUCKET_BASE = 18;
constexpr uint16_t PIXEL_BUCKET_OTHER = 23;
constexpr uint16_t PIXEL_FORMAT_BUCKET_INVALID = 22;

uint16_t PixelBucket(int32_t value)
{
    if (value >= 0 && value <= MAX_PUBLIC_PIXEL_FORMAT) {
        return static_cast<uint16_t>(value);
    }
    if (value >= SUT_PIXEL_FORMAT_BASE && value <= SUT_PIXEL_FORMAT_MAX) {
        return static_cast<uint16_t>(SUT_PIXEL_BUCKET_BASE + value - SUT_PIXEL_FORMAT_BASE);
    }
    return PIXEL_BUCKET_OTHER;
}

// ColorSpaceName 公开取值命中后按序入桶，未命中与不可用各自保留独立桶。
constexpr uint16_t COLOR_BUCKET_UNAVAILABLE = 16;
constexpr uint16_t COLOR_BUCKET_OTHER = 17;

uint16_t SourceColor(int32_t value)
{
    if (value < 0) {
        return COLOR_BUCKET_UNAVAILABLE;
    }
    // 与 ColorManager::ColorSpaceName 的公开取值一一对应，避免聚合层依赖图形库头文件。
    constexpr std::array<int32_t, 16> names = {0, 4, 3, 2, 27, 1, 24, 25, 15, 14, 9, 10, 19, 20, 26, 5};
    for (size_t i = 0; i < names.size(); ++i) {
        if (value == names[i]) {
            return static_cast<uint16_t>(i);
        }
    }
    return COLOR_BUCKET_OTHER;
}

// 选项类指标在入参不可用时写入的保留桶。
constexpr uint16_t BOOL_BUCKET_UNKNOWN = 2;
constexpr int32_t MAX_PUBLIC_COLOR_SPACE = 13;
constexpr uint16_t COLOR_SPACE_BUCKET_INVALID = 14;
constexpr uint16_t COLOR_SPACE_BUCKET_OTHER = 15;
constexpr uint16_t INVOKE_BUCKET_INVALID = 3;
constexpr uint16_t ROTATE_BUCKET_INVALID = 5;
constexpr uint16_t ROTATE_BUCKET_OTHER = 4;
constexpr size_t DESIRED_DIMENSION_SLOTS = 8;
constexpr size_t GRID_DIMENSION_SLOTS = 6;

constexpr std::array<uint64_t, 4> SAMPLE_SIZE_LIMITS = {1, 2, 4, 8};
constexpr std::array<uint64_t, 4> INDEX_FRAME_LIMITS = {1, 2, 10, 100};
constexpr std::array<uint64_t, 4> FIT_DENSITY_LIMITS = {160, 240, 320, 480};
constexpr std::array<uint64_t, 4> REGION_COORD_LIMITS = {1, 256, 1024, 4096};
constexpr std::array<uint64_t, 8> COST_LIMITS_MS = {1, 2, 5, 10, 20, 50, 100, 500};

uint16_t RotateBucket(double rotate)
{
    // 0/90/180/270 之外的角度统一归入 other 桶。
    constexpr std::array<double, 4> angles = {0.0, 90.0, 180.0, 270.0};
    for (size_t i = 0; i < angles.size(); ++i) {
        if (rotate == angles[i]) {
            return static_cast<uint16_t>(i);
        }
    }
    return ROTATE_BUCKET_OTHER;
}

void ClassifyOptions(const DecodeInfoOptions &o, bool optionsValid, std::array<uint16_t, METRIC_COUNT> &b)
{
    b[DESIRED_PIXEL_FORMAT] = optionsValid ? PixelBucket(o.desirePixelFormat) : PIXEL_FORMAT_BUCKET_INVALID;
    b[DESIRED_COLOR_SPACE] = static_cast<uint16_t>(!optionsValid ? COLOR_SPACE_BUCKET_INVALID :
        (o.desireColorSpace >= 0 && o.desireColorSpace <= MAX_PUBLIC_COLOR_SPACE ? o.desireColorSpace :
        COLOR_SPACE_BUCKET_OTHER));
    b[INVOKE_TYPE] = static_cast<uint16_t>(optionsValid && o.invokeType <= C_INTERFACE ? o.invokeType :
        INVOKE_BUCKET_INVALID);
    b[EDITABLE] = optionsValid ? static_cast<uint16_t>(o.editable) : BOOL_BUCKET_UNKNOWN;
    b[SAMPLE_SIZE] = optionsValid ? 1 + Range(o.sampleSize, SAMPLE_SIZE_LIMITS) : 0;
    b[ROTATE] = !optionsValid || !std::isfinite(o.rotate) ? ROTATE_BUCKET_INVALID : RotateBucket(o.rotate);
    b[INDEX] = optionsValid ? 1 + Range(o.index, INDEX_FRAME_LIMITS) : 0;
    b[FIT_DENSITY] = !optionsValid || o.fitDensity <= 0 ? 0 : 1 + Range(o.fitDensity, FIT_DENSITY_LIMITS);
    b[DESIRED_WIDTH] = optionsValid ? Dimension(o.desireSizeWidth, DESIRED_DIMENSION_SLOTS) : 0;
    b[DESIRED_HEIGHT] = optionsValid ? Dimension(o.desireSizeHeight, DESIRED_DIMENSION_SLOTS) : 0;
    b[REGION_WIDTH] = optionsValid ? Dimension(o.desireRegionWidth, DESIRED_DIMENSION_SLOTS) : 0;
    b[REGION_HEIGHT] = optionsValid ? Dimension(o.desireRegionHeight, DESIRED_DIMENSION_SLOTS) : 0;
    b[REGION_X] = !optionsValid || o.desireRegionX < 0 ? 0 : 1 + Range(o.desireRegionX, REGION_COORD_LIMITS);
    b[REGION_Y] = !optionsValid || o.desireRegionY < 0 ? 0 : 1 + Range(o.desireRegionY, REGION_COORD_LIMITS);
}

constexpr std::array<std::string_view, 16> MIME_NAMES = {"image/jpeg", "image/png", "image/webp", "image/gif",
    "image/bmp", "image/heif", "image/avif", "image/tiff", "image/svg+xml", "image/x-icon",
    "image/vnd.wap.wbmp", "image/astc", "image/x-adobe-dng", "image/x-raw", "unknown", "other"};
constexpr size_t MIME_INDEX_HEIF = 5;
constexpr size_t MIME_INDEX_UNKNOWN = 14;
constexpr std::array<std::string_view, 10> YUV_NAMES = {"4:4:4", "4:2:2", "4:2:0", "4:4:0", "4:1:1",
    "4:1:0", "4:0:0", "not_yuv", "unknown", "other"};
constexpr std::array<std::string_view, 10> SUFFIX_NAMES = {
    "jpg", "jpeg", "png", "heic", "heif", "avif", "webp", "gif", "unknown", "other"};
constexpr std::array<std::string_view, 8> SOURCE_NAMES = {"CreateImageSource by istream", "CreateImageSource by data",
    "CreateImageSource by pathName", "CreateImageSource by fd", "CreateImageSource by fd offset and length",
    "incremental", "unknown", "other"};
constexpr std::array<std::string_view, 8> PLUGIN_NAMES = {
    "ext", "jpeg", "png", "webp", "svg", "raw", "unknown", "other"};
constexpr uint16_t SOURCE_BUCKET_INCREMENTAL = 5;
constexpr uint16_t MEMORY_TYPE_BUCKET_INVALID = 6;
constexpr int32_t MAX_MEMORY_TYPE = 4;
constexpr uint16_t MEMORY_TYPE_BUCKET_OTHER = 7;
constexpr uint16_t HARD_ERROR_BUCKET_TEXT = 7;

uint16_t MimeValue(const DecodeInfoOptions &o)
{
    uint16_t mime = Dictionary(o.mimeType, MIME_NAMES);
    if (o.mimeType == "image/heic" || o.mimeType == "image/heifs" || o.mimeType == "image/heics") {
        mime = static_cast<uint16_t>(MIME_INDEX_HEIF); // HEIC 系列别名统一归入 HEIF 桶。
    }
    if (!o.sourceFileExtension.empty()) {
        mime = static_cast<uint16_t>(MIME_INDEX_UNKNOWN); // UNKNOWN_FORMAT 优先于保留的 MIME 提示。
    }
    return mime;
}
} // namespace

uint64_t Aggregate::Now(bool &valid)
{
    uint64_t now = 0;
    valid = clock_(now) && now >= lastNow_;
    if (valid) {
        lastNow_ = now;
    }
    return lastNow_;
}

void Aggregate::Add(Window &window, const Sample &sample)
{
    Increase(window.totalCount, 1, window.saturated);
    const size_t result = static_cast<size_t>(sample.result);
    Increase(window.results[result < window.results.size() ? result : 1], 1, window.saturated);
    for (size_t i = 0; i < METRIC_COUNT; ++i) {
        uint16_t bucket = sample.buckets[i];
        if (bucket != NO_BUCKET) {
            bucket = std::min<uint16_t>(bucket, METRICS[i].size - 1);
            Increase(window.counters[OFFSETS[i] + bucket], 1, window.saturated);
        }
    }
    if (sample.costValid) {
        Increase(window.costSum, sample.costMs, window.saturated);
        Increase(window.costValidCount, 1, window.saturated);
        window.costMax = std::max(window.costMax, sample.costMs);
    }
    if (sample.sourceSize != 0) {
        Increase(window.sourceSizeSum, sample.sourceSize, window.saturated);
        Increase(window.sourceSizeValidCount, 1, window.saturated);
        window.sourceSizeMax = std::max(window.sourceSizeMax, sample.sourceSize);
    }
}

bool Aggregate::Record(const Sample &sample)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool clockValid = false;
    const uint64_t now = Now(clockValid);
    Window &current = windows_[active_];
    if (!current.initialized) {
        current.initialized = true;
        current.id = nextId_++;
    }
    if (!clockValid) {
        current.clockUncertain = true;
    } else if (!current.clockValid) {
        current.startMs = now;
        current.clockValid = true;
    }
    if (clockValid && now - current.startMs >= WINDOW_MS) {
        if (pending_ < 0) {
            current.endMs = current.extended ? now : current.startMs + WINDOW_MS;
            pending_ = static_cast<int>(active_);
            active_ ^= 1;
            windows_[active_] = {};
            windows_[active_].initialized = true;
            windows_[active_].clockValid = true;
            windows_[active_].id = nextId_++;
            windows_[active_].startMs = now;
            completed_ = 0;
            retryAt_ = now;
        } else {
            current.extended = true;
        }
    }
    Add(windows_[active_], sample);
    if (clockValid && pending_ >= 0 && !reserved_ && now >= retryAt_) {
        reserved_ = true;
        retryAt_ = now > UINT64_MAX - RETRY_MS ? UINT64_MAX : now + RETRY_MS;
        return true;
    }
    return false;
}

void Aggregate::SubmissionFailed()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) {
        reserved_ = false;
    }
}

void Aggregate::Flush(Writer writer, void *context)
{
    const Window *window = nullptr;
    uint8_t completed = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!reserved_ || running_ || pending_ < 0) {
            return;
        }
        running_ = true;
        window = &windows_[pending_];
        completed = completed_;
    }
    for (size_t part = 0; part < PART_COUNT; ++part) {
        const uint8_t bit = 1U << part;
        if (!(completed & bit)) {
            if (!writer(*window, part, context)) {
                break;
            }
            completed |= bit;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    completed_ = completed;
    if (completed == ALL_PARTS) {
        windows_[pending_] = {};
        pending_ = -1;
    }
    running_ = false;
    reserved_ = false;
    bool valid = false;
    uint64_t now = Now(valid);
    if (pending_ >= 0) {
        retryAt_ = now > UINT64_MAX - RETRY_MS ? UINT64_MAX : now + RETRY_MS;
    }
}

Sample Classify(const ClassifyRequest &request)
{
    Sample s;
    s.buckets.fill(NO_BUCKET);
    if (request.options == nullptr) {
        return s;
    }
    const DecodeInfoOptions &o = *request.options;
    s.result = request.result;
    s.costMs = request.costMs;
    s.costValid = request.costValid;
    // 增量未完成样本对同一源会重复上报，sourceSize 置 0，不计入 SUM/MAX/VALID_COUNT 与大小分桶。
    s.sourceSize = request.result == DecodeResult::INCOMPLETE ? 0 : o.sourceSize;
    auto &b = s.buckets;
    const uint16_t mime = MimeValue(o);
    b[MIME_RESULT] = static_cast<uint16_t>(mime * RESULT_KIND_COUNT + static_cast<uint16_t>(request.result));
    b[POINT_RESULT] = static_cast<uint16_t>(static_cast<uint16_t>(request.point) * RESULT_KIND_COUNT +
        static_cast<uint16_t>(request.result));
    b[SOURCE_COLOR] = SourceColor(o.sourceColorSpace);
    b[SOURCE_YUV] = Dictionary(o.sourceYuvSampling, YUV_NAMES);
    // 非空且已清洗的后缀同时标识 UNKNOWN_FORMAT 状态，其 MIME 可能仍是旧值。
    if (mime == MIME_INDEX_UNKNOWN || !o.sourceFileExtension.empty()) {
        b[SOURCE_EXTENSION] = Dictionary(o.sourceFileExtension, SUFFIX_NAMES);
    }
    b[SOURCE_SIZE] = SizeBucket(o.sourceSize);
    b[SOURCE_WIDTH] = Dimension(o.sourceWidth, METRICS[SOURCE_WIDTH].size);
    b[SOURCE_HEIGHT] = Dimension(o.sourceHeight, METRICS[SOURCE_HEIGHT].size);
    b[COST_TIME] = request.costValid ? 1 + Range(request.costMs, COST_LIMITS_MS) : 0;
    b[MEMORY_SIZE] = request.contextValid ? SizeBucket(o.memorySize) : 0;
    b[MEMORY_TYPE] = static_cast<uint16_t>(!request.contextValid ? MEMORY_TYPE_BUCKET_INVALID :
        (o.memoryType >= 0 && o.memoryType <= MAX_MEMORY_TYPE ? o.memoryType : MEMORY_TYPE_BUCKET_OTHER));
    b[HARD_DECODE] = request.contextValid ? static_cast<uint16_t>(o.isHardDecode) : BOOL_BUCKET_UNKNOWN;
    b[IMAGE_SOURCE] = request.point == DecodePoint::INCREMENTAL || o.isIncrementalDecode ?
        SOURCE_BUCKET_INCREMENTAL : Dictionary(o.imageSource, SOURCE_NAMES);
    b[PLUGIN_TYPE] = Dictionary(o.pluginType, PLUGIN_NAMES);
    ClassifyOptions(o, request.optionsValid, b);
    b[GRID_WIDTH] = Dimension(o.heifGridWidth, GRID_DIMENSION_SLOTS);
    b[GRID_HEIGHT] = Dimension(o.heifGridHeight, GRID_DIMENSION_SLOTS);
    if (request.result == DecodeResult::FAILURE) {
        b[ERROR_CLASS] = request.error == DecodeError::NONE ? 1 : static_cast<uint16_t>(request.error);
    }
    if (!o.hardDecodeError.empty()) {
        b[HARD_ERROR_CLASS] = HARD_ERROR_BUCKET_TEXT; // 既有的自由文本诊断不做解析。
    }
    return s;
}

constexpr uint64_t MS_PER_SECOND = 1000;
constexpr uint64_t NS_PER_MS = 1000000;

bool ReadClock(uint64_t &nowMs)
{
#if !defined(CROSS_PLATFORM)
    struct timespec ts {};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0 || ts.tv_sec < 0) {
        return false;
    }
    nowMs = static_cast<uint64_t>(ts.tv_sec) * MS_PER_SECOND + static_cast<uint64_t>(ts.tv_nsec) / NS_PER_MS;
    return true;
#else
    (void)nowMs;
    return false;
#endif
}

#if !defined(CROSS_PLATFORM)
namespace {
constexpr size_t INSTANCE_WORDS = 2;
constexpr size_t INSTANCE_HEX_LEN = INSTANCE_WORDS * 16;
constexpr size_t INSTANCE_NAME_LEN = INSTANCE_HEX_LEN + 1;
constexpr size_t PROCESS_NAME_LEN = 128;

struct Reporter {
    Aggregate aggregate {ReadClock};
    std::mutex submitMutex;
    ffrt::task_handle task;
    uint64_t instance[INSTANCE_WORDS] {};
    char instanceName[INSTANCE_NAME_LEN] {};
    char processName[PROCESS_NAME_LEN] {};
};

struct ReporterPage {
    // WIPEONFORK 让子进程恢复为零初始化的私有互斥量。
    pthread_mutex_t initMutex = PTHREAD_MUTEX_INITIALIZER;
    std::atomic<bool> initialized {false};
    alignas(Reporter) unsigned char reporter[sizeof(Reporter)] {};
};
static_assert(std::atomic<bool>::is_always_lock_free &&
    std::atomic<ReporterPage *>::is_always_lock_free, "Fork reset needs lock-free page state");
constexpr size_t REPORTER_BYTES = 8192;
static_assert(sizeof(ReporterPage) <= REPORTER_BYTES, "Process reporter exceeds its memory budget");

class ReporterStorage {
public:
    Reporter *Get()
    {
        ReporterPage *page = page_.load(std::memory_order_acquire);
        if (page == nullptr) {
            void *memory = mmap(nullptr, REPORTER_BYTES, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (memory == MAP_FAILED) {
                return nullptr;
            }
            if (madvise(memory, REPORTER_BYTES, MADV_WIPEONFORK) != 0) {
                munmap(memory, REPORTER_BYTES);
                return nullptr;
            }
            auto *candidate = new (memory) ReporterPage;
            if (page_.compare_exchange_strong(page, candidate, std::memory_order_release,
                std::memory_order_acquire)) {
                page = candidate;
            } else {
                pthread_mutex_destroy(&candidate->initMutex);
                munmap(candidate, REPORTER_BYTES);
            }
        }
        if (!page->initialized.load(std::memory_order_acquire)) {
            // 被清零的子进程页中不存在继承的已加锁互斥量或挂起任务。
            if (pthread_mutex_lock(&page->initMutex) != 0) {
                return nullptr;
            }
            if (!page->initialized.load(std::memory_order_relaxed)) {
                new (page->reporter) Reporter;
                page->initialized.store(true, std::memory_order_release);
            }
            pthread_mutex_unlock(&page->initMutex);
        }
        return std::launder(reinterpret_cast<Reporter *>(page->reporter));
    }

    ~ReporterStorage()
    {
        ReporterPage *page = page_.load(std::memory_order_relaxed);
        if (page == nullptr) {
            return;
        }
        if (page->initialized.load(std::memory_order_acquire)) {
            auto *reporter = std::launder(reinterpret_cast<Reporter *>(page->reporter));
            // 库卸载前 API 调用方已结束，等待其已提交的任务完成。
            if (static_cast<void *>(reporter->task) != nullptr) {
                ffrt::wait({reporter->task});
            }
            reporter->~Reporter();
        }
        pthread_mutex_destroy(&page->initMutex);
        munmap(page, REPORTER_BYTES);
    }

private:
    std::atomic<ReporterPage *> page_ {nullptr};
};
ReporterStorage g_reporterStorage;

constexpr int NIBBLE_BITS = 4;
constexpr int NIBBLE_MASK = 0xF;
constexpr int HIGH_NIBBLE_SHIFT = 64 - NIBBLE_BITS;
const char HEX_DIGITS[] = "0123456789abcdef";

void FillInstanceName(Reporter &reporter)
{
    // 128 位实例随机数展开为 32 个小写十六进制字符。
    size_t pos = 0;
    for (const uint64_t word : reporter.instance) {
        for (int shift = HIGH_NIBBLE_SHIFT; shift >= 0; shift -= NIBBLE_BITS) {
            reporter.instanceName[pos++] = HEX_DIGITS[(word >> shift) & NIBBLE_MASK];
        }
    }
    reporter.instanceName[pos] = '\0';
}

bool InitializeIdentity(Reporter &reporter)
{
    if (reporter.instanceName[0] != '\0') {
        return true;
    }
    const auto bytes = getrandom(reporter.instance, sizeof(reporter.instance), GRND_NONBLOCK);
    if (bytes != static_cast<ssize_t>(sizeof(reporter.instance))) {
        return false;
    }
    FillInstanceName(reporter);
    const auto name = ImageUtils::GetCurrentProcessName();
    size_t length = std::min(name.size(), sizeof(reporter.processName) - 1);
    while (length > 0 && (static_cast<unsigned char>(name.c_str()[length]) & 0xC0) == 0x80) {
        --length;
    }
    std::copy_n(name.c_str(), length, reporter.processName);
    reporter.processName[length] = '\0';
    return true;
}

constexpr size_t MAX_EVENT_PARAMS = 64;
constexpr uint64_t SCHEMA_VERSION = 2;
constexpr size_t RESULT_INDEX_SUCCESS = 0;
constexpr size_t RESULT_INDEX_FAILURE = 1;
constexpr size_t RESULT_INDEX_INCOMPLETE = 2;

struct ParamWriter {
    HiSysEventParam params[MAX_EVENT_PARAMS] {};
    size_t count = 0;

    HiSysEventParam& Append(const char *name, HiSysEventParamType type)
    {
        auto &param = params[count++];
        std::copy_n(name, std::strlen(name) + 1, param.name);
        param.t = type;
        return param;
    }

    void Number(const char *name, uint64_t value)
    {
        Append(name, HISYSEVENT_UINT64).v.ui64 = value;
    }

    void Flag(const char *name, bool value)
    {
        Append(name, HISYSEVENT_BOOL).v.b = value;
    }

    void String(const char *name, char *value)
    {
        Append(name, HISYSEVENT_STRING).v.s = value;
    }
};

void WriteProcessFields(ParamWriter &writer, Reporter &reporter)
{
    writer.Number("SCHEMA_VERSION", SCHEMA_VERSION);
    writer.String("PROCESS_NAME", reporter.processName);
    writer.String("PROCESS_INSTANCE_ID", reporter.instanceName);
    writer.Number("UID", getuid());
    writer.Number("PID", getpid());
}

void WriteWindowFields(ParamWriter &writer, const Window &window, size_t part)
{
    writer.Number("WINDOW_ID", window.id);
    writer.Number("WINDOW_START_MS", window.startMs);
    writer.Number("WINDOW_END_MS", window.endMs);
    writer.Number("DURATION_MS", window.endMs - window.startMs);
    uint64_t now = 0;
    const bool nowValid = ReadClock(now);
    writer.Number("REPORT_LAG_MS", nowValid && now >= window.endMs ? now - window.endMs : 0);
    writer.Flag("CLOCK_UNCERTAIN", window.clockUncertain || !nowValid);
    writer.Flag("WINDOW_EXTENDED", window.extended);
    writer.Flag("COUNTER_SATURATED", window.saturated);
    writer.Number("PART_INDEX", part);
    writer.Number("PART_COUNT", PART_COUNT);
    if (part == 0) {
        writer.Number("TOTAL_POINT_COUNT", window.totalCount);
        writer.Number("SUCCESS_COUNT", window.results[RESULT_INDEX_SUCCESS]);
        writer.Number("FAILURE_COUNT", window.results[RESULT_INDEX_FAILURE]);
        writer.Number("INCOMPLETE_COUNT", window.results[RESULT_INDEX_INCOMPLETE]);
        writer.Number("COST_SUM_MS", window.costSum);
        writer.Number("COST_MAX_MS", window.costMax);
        writer.Number("COST_VALID_COUNT", window.costValidCount);
        writer.Number("SOURCE_SIZE_SUM", window.sourceSizeSum);
        writer.Number("SOURCE_SIZE_MAX", window.sourceSizeMax);
        writer.Number("SOURCE_SIZE_VALID_COUNT", window.sourceSizeValidCount);
    }
}

void WriteMetricArrays(const Window &window, size_t part, ParamWriter &writer)
{
    for (size_t i = 0; i < METRIC_COUNT; ++i) {
        if (METRICS[i].part == part) {
            auto &param = writer.Append(METRICS[i].name, HISYSEVENT_UINT64_ARRAY);
            param.v.array = const_cast<uint64_t *>(window.counters.data() + OFFSETS[i]);
            param.arraySize = METRICS[i].size;
        }
    }
}

bool WritePart(const Window &window, size_t part, void *context)
{
    auto &reporter = *static_cast<Reporter *>(context);
    if (!InitializeIdentity(reporter)) {
        return false;
    }
    ParamWriter writer;
    WriteProcessFields(writer, reporter);
    WriteWindowFields(writer, window, part);
    WriteMetricArrays(window, part, writer);
    return OH_HiSysEvent_Write("IMAGE_FWK_UE", "DECODE_HOURLY_STATISTICS", HISYSEVENT_STATISTIC,
        writer.params, writer.count) == 0;
}
} // namespace
#endif

void Record(const ClassifyRequest &request)
{
#if !defined(CROSS_PLATFORM)
    auto *state = g_reporterStorage.Get();
    if (state == nullptr) {
        return;
    }
    auto &reporter = *state;
    if (!reporter.aggregate.Record(Classify(request))) {
        return;
    }
    // FFRT 能力探测：受限进程提交失败时恢复重试标记，窗口过期只在解码调用时检查。
    std::lock_guard<std::mutex> submitLock(reporter.submitMutex);
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        reporter.aggregate.SubmissionFailed();
        return;
    }
    close(fd);
    const auto write = [&reporter] { reporter.aggregate.Flush(WritePart, &reporter); };
    ffrt::task_handle handle;
    if (static_cast<void *>(reporter.task) == nullptr) {
        handle = ffrt::submit_h(write, {}, {});
    } else {
        // 同时保证任务包装对象在后续任务或库卸载前完成析构。
        handle = ffrt::submit_h(write, {reporter.task}, {});
    }
    if (static_cast<void *>(handle) == nullptr) {
        reporter.aggregate.SubmissionFailed();
    } else {
        reporter.task = std::move(handle);
    }
#else
    (void)request.options;
    (void)request.point;
    (void)request.result;
    (void)request.error;
    (void)request.costMs;
    (void)request.costValid;
    (void)request.optionsValid;
    (void)request.contextValid;
#endif
}
} // namespace DecodeDfx
} // namespace Media
} // namespace OHOS
