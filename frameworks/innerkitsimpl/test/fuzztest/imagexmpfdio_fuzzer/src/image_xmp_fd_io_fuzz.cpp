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

#include "xmp_fd_io.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "image_log.h"
#include "image_xmp_fd_io_fuzz.h"

namespace OHOS {
namespace Media {
namespace {
constexpr size_t MAX_RW_SIZE = 512;
constexpr size_t ACTION_REPEAT_MAX = 8;
constexpr uint32_t COMMON_OPT_SIZE = 80;
const std::string TEST_FILE_PATH = "/data/local/tmp/test_xmp_fd_io.bin";

enum class SeekModeChoice : uint8_t {
    FROM_START = 0,
    FROM_CURRENT = 1,
    FROM_END = 2,
};

static constexpr uint8_t SEEK_MODE_CHOICE_COUNT = 3;

enum class FdAction : uint8_t {
    READ = 0,
    WRITE = 1,
    SEEK = 2,
    LENGTH = 3,
    TRUNCATE = 4,
    TEMP = 5,
    STATUS = 6,
};

static constexpr uint8_t FD_ACTION_COUNT = 7;

bool WriteRawDataToFile(const uint8_t *data, size_t size, const std::string &filePath)
{
    if (data == nullptr || size == 0 || filePath.empty()) {
        return false;
    }

    int fd = open(filePath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        IMAGE_LOGE("[FUZZ] %{public}s: open failed path=[%{public}.64s] errno=%{public}d",
            __func__, filePath.c_str(), errno);
        return false;
    }

    size_t writtenTotal = 0;
    while (writtenTotal < size) {
        ssize_t bytesWritten = write(fd, data + writtenTotal, size - writtenTotal);
        if (bytesWritten <= 0) {
            close(fd);
            return false;
        }
        writtenTotal += static_cast<size_t>(bytesWritten);
    }
    close(fd);
    return true;
}

SeekMode BuildSeekMode(FuzzedDataProvider *fdp)
{
    uint8_t modeRaw = fdp->ConsumeIntegral<uint8_t>() % SEEK_MODE_CHOICE_COUNT;
    SeekModeChoice mode = static_cast<SeekModeChoice>(modeRaw);
    switch (mode) {
        case SeekModeChoice::FROM_START:
            return kXMP_SeekFromStart;
        case SeekModeChoice::FROM_CURRENT:
            return kXMP_SeekFromCurrent;
        default:
            return kXMP_SeekFromEnd;
    }
}

void HandleFdReadAction(XMPFd_IO &io, FuzzedDataProvider *fdp)
{
    size_t readCount = fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE);
    std::vector<uint8_t> buffer(readCount == 0 ? 1 : readCount);
    io.Read(buffer.data(), static_cast<XMP_Uns32>(readCount), false);
}

void HandleFdWriteAction(XMPFd_IO &io, bool readOnly, FuzzedDataProvider *fdp)
{
    static uint8_t dummy = 0;
    if (readOnly) {
        return;
    }
    size_t writeCount = fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE);
    std::vector<uint8_t> payload = fdp->ConsumeBytes<uint8_t>(writeCount);
    const void *writeBuffer = payload.empty() ? &dummy : payload.data();
    io.Write(writeBuffer, static_cast<XMP_Uns32>(payload.size()));
}

void HandleFdSeekAction(XMPFd_IO &io, FuzzedDataProvider *fdp)
{
    XMP_Int64 offset = static_cast<XMP_Int64>(fdp->ConsumeIntegralInRange<uint32_t>(0, MAX_RW_SIZE));
    SeekMode mode = BuildSeekMode(fdp);
    io.Seek(offset, mode);
}

void HandleFdTruncateAction(XMPFd_IO &io, bool readOnly, FuzzedDataProvider *fdp)
{
    if (readOnly) {
        return;
    }
    XMP_Int64 maxLength = io.Length();
    XMP_Int64 length = static_cast<XMP_Int64>(fdp->ConsumeIntegralInRange<uint32_t>(0,
        static_cast<uint32_t>(maxLength > 0 ? maxLength : 0)));
    io.Truncate(length);
}

void HandleFdTempAction(XMPFd_IO &io, bool readOnly, FuzzedDataProvider *fdp)
{
    static uint8_t dummy = 0;
    if (readOnly) {
        return;
    }
    XMP_IO *temp = io.DeriveTemp();
    if (temp == nullptr) {
        IMAGE_LOGI("[FUZZ] %{public}s: DeriveTemp failed", __func__);
        return;
    }
    std::vector<uint8_t> tempData = fdp->ConsumeBytes<uint8_t>(
        fdp->ConsumeIntegralInRange<size_t>(0, MAX_RW_SIZE));
    const void *tempBuffer = tempData.empty() ? &dummy : tempData.data();
    temp->Write(tempBuffer, static_cast<XMP_Uns32>(tempData.size()));
    if (fdp->ConsumeBool()) {
        IMAGE_LOGI("[FUZZ] %{public}s: AbsorbTemp", __func__);
        io.AbsorbTemp();
    } else {
        IMAGE_LOGI("[FUZZ] %{public}s: DeleteTemp", __func__);
        io.DeleteTemp();
    }
}

void HandleFdStatusAction(XMPFd_IO &io)
{
    io.IsValid();
    io.GetFd();
}

void ExerciseXMPFdIO(XMPFd_IO &io, bool readOnly, FuzzedDataProvider *fdp)
{
    size_t rounds = fdp->ConsumeIntegralInRange<size_t>(1, ACTION_REPEAT_MAX);
    for (size_t index = 0; index < rounds; ++index) {
        uint8_t actionRaw = fdp->ConsumeIntegral<uint8_t>() % FD_ACTION_COUNT;
        FdAction action = static_cast<FdAction>(actionRaw);
        IMAGE_LOGI("[FUZZ] %{public}s: round=%{public}zu/%{public}zu action=%{public}u readOnly=%{public}d",
            __func__, index + 1, rounds, actionRaw, readOnly);
        switch (action) {
            case FdAction::READ:
                HandleFdReadAction(io, fdp);
                break;
            case FdAction::WRITE:
                HandleFdWriteAction(io, readOnly, fdp);
                break;
            case FdAction::SEEK:
                HandleFdSeekAction(io, fdp);
                break;
            case FdAction::LENGTH:
                io.Length();
                break;
            case FdAction::TRUNCATE:
                HandleFdTruncateAction(io, readOnly, fdp);
                break;
            case FdAction::TEMP:
                HandleFdTempAction(io, readOnly, fdp);
                break;
            default:
                HandleFdStatusAction(io);
                break;
        }
    }
}

void XMPFdIOFromFdFuzzTest(FuzzedDataProvider *fdp)
{
    bool readOnly = fdp->ConsumeBool();
    int openFlags = readOnly ? O_RDONLY : O_RDWR;
    int fd = open(TEST_FILE_PATH.c_str(), openFlags);
    if (fd < 0) {
        IMAGE_LOGE("[FUZZ] %{public}s: open failed flags=%{public}d errno=%{public}d", __func__, openFlags, errno);
        return;
    }

    XMPFd_IO io(fd, readOnly, false);
    ExerciseXMPFdIO(io, readOnly, fdp);
    close(fd);
}

void XMPFdIOFromPathFuzzTest(FuzzedDataProvider *fdp)
{
    std::string path = TEST_FILE_PATH;
    bool readOnly = fdp->ConsumeBool();
    XMPFd_IO io(path, readOnly);
    ExerciseXMPFdIO(io, readOnly, fdp);
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <= COMMON_OPT_SIZE) {
        return 0;
    }

    std::string fileDataPath = TEST_FILE_PATH;
    if (!WriteRawDataToFile(data, size - COMMON_OPT_SIZE, fileDataPath)) {
        return 0;
    }

    FuzzedDataProvider optFdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    FuzzedDataProvider testFdp(data, size - COMMON_OPT_SIZE);

    uint8_t action = optFdp.ConsumeIntegral<uint8_t>() % 2;
    IMAGE_LOGI("[FUZZ] %{public}s: action=%{public}u size=%{public}zu", __func__, action, size);
    if (action == 0) {
        XMPFdIOFromFdFuzzTest(&testFdp);
    } else {
        XMPFdIOFromPathFuzzTest(&testFdp);
    }
    return 0;
}
} // namespace Media
} // namespace OHOS
