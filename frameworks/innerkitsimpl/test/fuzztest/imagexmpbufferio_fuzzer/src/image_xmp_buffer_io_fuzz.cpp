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

#include "xmp_buffer_io.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <vector>

#include "image_log.h"
#include "image_xmp_buffer_io_fuzz.h"

namespace OHOS {
namespace Media {
namespace {
constexpr size_t ACTION_REPEAT_MAX = 8;
constexpr size_t MAX_RW_SIZE = 1024;
constexpr uint32_t COMMON_OPT_SIZE = 80;

enum class ReadOnlyAction : uint8_t {
    READ = 0,
    SEEK = 1,
    LENGTH = 2,
    STATUS = 3,
};

static constexpr uint8_t READ_ONLY_ACTION_COUNT = 4;

enum class WritableAction : uint8_t {
    WRITE = 0,
    SEEK = 1,
    TRUNCATE = 2,
    TEMP = 3,
    READ = 4,
    LENGTH = 5,
    STATUS = 6,
};

static constexpr uint8_t WRITABLE_ACTION_COUNT = 7;

void ExerciseReadOnlyBufferIO(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    size_t rounds = fdp->ConsumeIntegralInRange<size_t>(1, ACTION_REPEAT_MAX);
    for (size_t index = 0; index < rounds; ++index) {
        uint8_t actionRaw = fdp->ConsumeIntegral<uint8_t>() % READ_ONLY_ACTION_COUNT;
        ReadOnlyAction action = static_cast<ReadOnlyAction>(actionRaw);
        IMAGE_LOGI("[FUZZ] %{public}s: round=%{public}zu/%{public}zu action=%{public}u",
            __func__, index + 1, rounds, actionRaw);
        if (action == ReadOnlyAction::READ) {
            size_t readCount = fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE);
            std::vector<uint8_t> readBuffer(readCount == 0 ? 1 : readCount);
            io.Read(readBuffer.data(), static_cast<XMP_Uns32>(readCount), false);
            continue;
        }

        if (action == ReadOnlyAction::SEEK) {
            XMP_Int64 length = io.Length();
            XMP_Int64 offset = static_cast<XMP_Int64>(fdp->ConsumeIntegralInRange<uint32_t>(0,
                static_cast<uint32_t>(length > 0 ? length : 0)));
            io.Seek(offset, kXMP_SeekFromStart);
            continue;
        }

        if (action == ReadOnlyAction::LENGTH) {
            io.Length();
            continue;
        }

        io.GetDataPtr();
        io.GetDataSize();
    }
}

void HandleWritableWriteAction(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    static uint8_t dummy = 0;
    size_t writeCount = fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE);
    std::vector<uint8_t> writeBuffer = fdp->ConsumeBytes<uint8_t>(writeCount);
    const void *writePtr = writeBuffer.empty() ? &dummy : writeBuffer.data();
    io.Write(writePtr, static_cast<XMP_Uns32>(writeBuffer.size()));
}

void HandleWritableSeekAction(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    XMP_Int64 length = io.Length();
    XMP_Int64 offset = static_cast<XMP_Int64>(fdp->ConsumeIntegralInRange<uint32_t>(0,
        static_cast<uint32_t>(length > 0 ? length : 0)));
    io.Seek(offset, kXMP_SeekFromStart);
}

void HandleWritableTruncateAction(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    XMP_Int64 length = io.Length();
    XMP_Int64 truncateLength = static_cast<XMP_Int64>(fdp->ConsumeIntegralInRange<uint32_t>(0,
        static_cast<uint32_t>(length > 0 ? length : 0)));
    io.Truncate(truncateLength);
}

void HandleWritableTempAction(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    static uint8_t dummy = 0;
    XMP_IO *temp = io.DeriveTemp();
    if (temp == nullptr) {
        IMAGE_LOGI("[FUZZ] %{public}s: DeriveTemp failed", __func__);
        return;
    }
    std::vector<uint8_t> tempData = fdp->ConsumeBytes<uint8_t>(
        fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE));
    const void *tempPtr = tempData.empty() ? &dummy : tempData.data();
    temp->Write(tempPtr, static_cast<XMP_Uns32>(tempData.size()));
    if (fdp->ConsumeBool()) {
        IMAGE_LOGI("[FUZZ] %{public}s: AbsorbTemp", __func__);
        io.AbsorbTemp();
    } else {
        IMAGE_LOGI("[FUZZ] %{public}s: DeleteTemp", __func__);
        io.DeleteTemp();
    }
}

void HandleWritableReadAction(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    size_t readCount = fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE);
    std::vector<uint8_t> readBuffer(readCount == 0 ? 1 : readCount);
    io.Read(readBuffer.data(), static_cast<XMP_Uns32>(readCount), false);
}

void HandleWritableStatusAction(XMPBuffer_IO &io)
{
    io.GetDataPtr();
    io.GetDataSize();
}

void ExerciseWritableBufferIO(XMPBuffer_IO &io, FuzzedDataProvider *fdp)
{
    size_t rounds = fdp->ConsumeIntegralInRange<size_t>(1, ACTION_REPEAT_MAX);
    for (size_t index = 0; index < rounds; ++index) {
        uint8_t actionRaw = fdp->ConsumeIntegral<uint8_t>() % WRITABLE_ACTION_COUNT;
        WritableAction action = static_cast<WritableAction>(actionRaw);
        IMAGE_LOGI("[FUZZ] %{public}s: round=%{public}zu/%{public}zu action=%{public}u",
            __func__, index + 1, rounds, actionRaw);
        switch (action) {
            case WritableAction::WRITE:
                HandleWritableWriteAction(io, fdp);
                break;
            case WritableAction::SEEK:
                HandleWritableSeekAction(io, fdp);
                break;
            case WritableAction::TRUNCATE:
                HandleWritableTruncateAction(io, fdp);
                break;
            case WritableAction::TEMP:
                HandleWritableTempAction(io, fdp);
                break;
            case WritableAction::READ:
                HandleWritableReadAction(io, fdp);
                break;
            case WritableAction::LENGTH:
                io.Length();
                break;
            default:
                HandleWritableStatusAction(io);
                break;
        }
    }
}

void XMPBufferIOFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    XMPBuffer_IO readOnlyIO(data, static_cast<XMP_Uns32>(size), true);
    XMPBuffer_IO writableIO(data, static_cast<XMP_Uns32>(size), false);

    FuzzedDataProvider fdp(data, size);
    ExerciseReadOnlyBufferIO(readOnlyIO, &fdp);
    ExerciseWritableBufferIO(writableIO, &fdp);

    if (fdp.ConsumeBool()) {
        XMPBuffer_IO emptyWritable;
        ExerciseWritableBufferIO(emptyWritable, &fdp);
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <= COMMON_OPT_SIZE) {
        return 0;
    }
    IMAGE_LOGI("[FUZZ] %{public}s: size=%{public}zu", __func__, size);

    XMPBufferIOFuzzTest(data, size - COMMON_OPT_SIZE);
    return 0;
}
} // namespace Media
} // namespace OHOS
