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

#include "xmp_fd_io.h"

#include "xmp_helper.h"

#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <securec.h>
#include <sys/stat.h>
#include <unistd.h>

namespace OHOS {
namespace Media {
namespace {
constexpr size_t ERR_MSG_MAX = 256;
constexpr size_t COPY_BUFFER_SIZE = 8192;
constexpr size_t FD_LINK_PATH_MAX = 64;
constexpr mode_t DEFAULT_TEMP_FILE_MODE = S_IRUSR | S_IWUSR;
constexpr int MAX_TEMP_FILE_SUFFIX = 100;
constexpr int TEMP_SUFFIX_DIGITS = 2;
constexpr size_t DERIVED_TEMP_SUFFIX_BUFFER_SIZE = 16;

void ResetDerivedTemp(XMP_IO *&derivedTemp)
{
    CHECK_ERROR_RETURN(derivedTemp == nullptr);
    delete derivedTemp;
    derivedTemp = nullptr;
}

void RemoveTempFile(std::string &tempFilePath)
{
    CHECK_ERROR_RETURN(tempFilePath.empty());
    if (unlink(tempFilePath.c_str()) == 0) {
        tempFilePath.clear();
    }
}

void CloseOwnedFd(int &fd, bool ownsFd)
{
    CHECK_ERROR_RETURN(!ownsFd || fd < 0);
    close(fd);
    fd = -1;
}

bool TryGetFdPath(int fd, std::string &filePath)
{
    char fdLinkPath[FD_LINK_PATH_MAX] = {0};
    int linkPathLen = sprintf_s(fdLinkPath, sizeof(fdLinkPath), "/proc/self/fd/%d", fd);
    if (linkPathLen <= 0 || static_cast<size_t>(linkPathLen) >= sizeof(fdLinkPath) - 1) {
        return false;
    }

    char resolvedPath[PATH_MAX] = {0};
    ssize_t resolvedPathLen = readlink(fdLinkPath, resolvedPath, sizeof(resolvedPath) - 1);
    if (resolvedPathLen <= 0) {
        return false;
    }

    if (static_cast<size_t>(resolvedPathLen) >= sizeof(resolvedPath) - 1) {
        return false;
    }

    resolvedPath[resolvedPathLen] = '\0';
    filePath.assign(resolvedPath, static_cast<size_t>(resolvedPathLen));
    return !filePath.empty() && filePath[0] == '/';
}

struct TempFileGuard {
    int fd = -1;
    std::string path;

    ~TempFileGuard()
    {
        if (fd >= 0) {
            close(fd);
        }
        if (!path.empty()) {
            unlink(path.c_str());
        }
    }

    void Release()
    {
        fd = -1;
        path.clear();
    }
};

struct FdGuard {
    int fd;
    bool ownsFd;

    explicit FdGuard(int f, bool own) : fd(f), ownsFd(own) {}

    ~FdGuard()
    {
        if (fd >= 0 && ownsFd) {
            close(fd);
        }
    }

    void Release()
    {
        ownsFd = false;
    }
};

std::string CreateDerivedTempPath(const std::string &sourcePath, int index)
{
    if (sourcePath.empty() || index < 0 || index >= MAX_TEMP_FILE_SUFFIX) {
        return "";
    }

    char suffix[DERIVED_TEMP_SUFFIX_BUFFER_SIZE] = {0};
    int suffixLen = sprintf_s(suffix, sizeof(suffix), "._%0*d_", TEMP_SUFFIX_DIGITS, index);
    if (suffixLen <= 0 || static_cast<size_t>(suffixLen) >= sizeof(suffix)) {
        return "";
    }

    std::string tempPath = sourcePath;
    tempPath += suffix;
    return tempPath;
}

bool TryCreateDerivedTempFd(const std::string &sourcePath, int &tempFd, std::string &tempPath, int &err)
{
    for (int index = 0; index < MAX_TEMP_FILE_SUFFIX; ++index) {
        tempPath = CreateDerivedTempPath(sourcePath, index);
        if (tempPath.empty()) {
            err = EINVAL;
            return false;
        }

        tempFd = open(tempPath.c_str(), O_CREAT | O_EXCL | O_RDWR, DEFAULT_TEMP_FILE_MODE);
        if (tempFd >= 0) {
            return true;
        }
        if (errno == EEXIST) {
            continue;
        }

        err = errno;
        return false;
    }

    err = EEXIST;
    return false;
}

} // anonymous namespace

XMPFd_IO::XMPFd_IO(int fd, bool readOnly, bool takeOwnership)
    : fd_(fd), readOnly_(readOnly), ownsFd_(takeOwnership), derivedTemp_(nullptr)
{
    XMP_TRY();
    FdGuard guard(fd_, takeOwnership);
    this->ValidateFdOrThrow("XMPFd_IO::XMPFd_IO");
    this->ValidateAccessModeOrThrow("XMPFd_IO::XMPFd_IO");
    this->ValidateSeekableOrThrow("XMPFd_IO::XMPFd_IO");
    guard.Release();
    XMP_CATCH_THROW();
}

XMPFd_IO::XMPFd_IO(const std::string &filePath, bool readOnly)
    : fd_(-1), readOnly_(readOnly), ownsFd_(true), derivedTemp_(nullptr)
{
    XMP_TRY();
    int flags = readOnly_ ? O_RDONLY : O_RDWR;
    fd_ = open(filePath.c_str(), flags);
    if (fd_ < 0) {
        this->ThrowErrnoExternalFailure("XMPFd_IO::XMPFd_IO(open)", errno);
    }
    FdGuard guard(fd_, true);
    this->ValidateFdOrThrow("XMPFd_IO::XMPFd_IO(open)");
    this->ValidateAccessModeOrThrow("XMPFd_IO::XMPFd_IO(open)");
    this->ValidateSeekableOrThrow("XMPFd_IO::XMPFd_IO(open)");
    guard.Release();
    XMP_CATCH_THROW();
}

XMPFd_IO::~XMPFd_IO()
{
    XMP_TRY();
    ResetDerivedTemp(derivedTemp_);
    CloseOwnedFd(fd_, ownsFd_);
    RemoveTempFile(tempFilePath_);
    XMP_CATCH_NO_RETURN();
}

XMP_Uns32 XMPFd_IO::Read(void *buffer, XMP_Uns32 count, bool readAll)
{
    XMP_TRY();
    this->ValidateFdOrThrow("XMPFd_IO::Read");
    this->ValidateAccessModeOrThrow("XMPFd_IO::Read");
    this->ValidateSeekableOrThrow("XMPFd_IO::Read");
    if (buffer == nullptr) {
        XMP_Throw("XMPFd_IO::Read, null buffer", kXMPErr_BadParam);
    }

    XMP_Uns32 total = 0;
    while (total < count) {
        const XMP_Uns32 remaining = count - total;
        ssize_t bytesRead = read(fd_, static_cast<char *>(buffer) + total, remaining);
        if (bytesRead > 0) {
            total += static_cast<XMP_Uns32>(bytesRead);
            if (!readAll) {
                break;
            }
            continue;
        }
        if (bytesRead == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        this->ThrowErrnoExternalFailure("XMPFd_IO::Read(read)", errno);
    }

    if (readAll && total < count) {
        XMP_Throw("XMPFd_IO::Read, not enough data", kXMPErr_EnforceFailure);
    }

    return total;
    XMP_CATCH_THROW();
    return 0;
}

void XMPFd_IO::Write(const void *buffer, XMP_Uns32 count)
{
    XMP_TRY();
    this->ValidateWritableOrThrow("XMPFd_IO::Write");
    this->ValidateSeekableOrThrow("XMPFd_IO::Write");
    if (buffer == nullptr) {
        XMP_Throw("XMPFd_IO::Write, null buffer", kXMPErr_BadParam);
    }

    XMP_Uns32 total = 0;
    while (total < count) {
        const XMP_Uns32 remaining = count - total;
        ssize_t bytesWritten = write(fd_, static_cast<const char *>(buffer) + total, remaining);
        if (bytesWritten > 0) {
            total += static_cast<XMP_Uns32>(bytesWritten);
            continue;
        }
        if (bytesWritten == 0) {
            XMP_Throw("XMPFd_IO::Write, write returned 0", kXMPErr_ExternalFailure);
        }
        if (errno == EINTR) {
            continue;
        }
        this->ThrowErrnoExternalFailure("XMPFd_IO::Write(write)", errno);
    }
    XMP_CATCH_THROW();
}

XMP_Int64 XMPFd_IO::Seek(XMP_Int64 offset, SeekMode mode)
{
    XMP_TRY();
    this->ValidateFdOrThrow("XMPFd_IO::Seek");
    this->ValidateAccessModeOrThrow("XMPFd_IO::Seek");
    this->ValidateSeekableOrThrow("XMPFd_IO::Seek");

    int whence;
    switch (mode) {
        case kXMP_SeekFromStart:
            whence = SEEK_SET;
            break;
        case kXMP_SeekFromCurrent:
            whence = SEEK_CUR;
            break;
        case kXMP_SeekFromEnd:
            whence = SEEK_END;
            break;
        default:
            XMP_Throw("XMPFd_IO::Seek, invalid seek mode", kXMPErr_BadParam);
    }

    if (!this->CanConvertToOffT(offset)) {
        XMP_Throw("XMPFd_IO::Seek, offset out of range", kXMPErr_ExternalFailure);
    }

    off_t newPosition = lseek(fd_, static_cast<off_t>(offset), whence);
    if (newPosition < 0) {
        this->ThrowErrnoExternalFailure("XMPFd_IO::Seek(lseek)", errno);
    }

    return static_cast<XMP_Int64>(newPosition);
    XMP_CATCH_THROW();
    return -1;
}

XMP_Int64 XMPFd_IO::Length()
{
    XMP_TRY();
    this->ValidateFdOrThrow("XMPFd_IO::Length");
    this->ValidateAccessModeOrThrow("XMPFd_IO::Length");

    struct stat fileStat;
    if (fstat(fd_, &fileStat) < 0) {
        this->ThrowErrnoExternalFailure("XMPFd_IO::Length(fstat)", errno);
    }

    if (fileStat.st_size < 0) {
        XMP_Throw("XMPFd_IO::Length, negative file size", kXMPErr_ExternalFailure);
    }

    if (static_cast<XMP_Uns64>(fileStat.st_size) > static_cast<XMP_Uns64>(std::numeric_limits<XMP_Int64>::max())) {
        XMP_Throw("XMPFd_IO::Length, file size out of range", kXMPErr_ExternalFailure);
    }

    return static_cast<XMP_Int64>(fileStat.st_size);
    XMP_CATCH_THROW();
    return -1;
}

void XMPFd_IO::Truncate(XMP_Int64 length)
{
    XMP_TRY();
    this->ValidateWritableOrThrow("XMPFd_IO::Truncate");
    this->ValidateSeekableOrThrow("XMPFd_IO::Truncate");
    if (length < 0) {
        XMP_Throw("XMPFd_IO::Truncate, invalid length", kXMPErr_BadParam);
    }
    if (!this->CanConvertToOffT(length)) {
        XMP_Throw("XMPFd_IO::Truncate, length out of range", kXMPErr_ExternalFailure);
    }

    if (ftruncate(fd_, static_cast<off_t>(length)) < 0) {
        this->ThrowErrnoExternalFailure("XMPFd_IO::Truncate(ftruncate)", errno);
    }

    // Adjust position if beyond new length
    off_t currentPos = lseek(fd_, 0, SEEK_CUR);
    if (currentPos > static_cast<off_t>(length)) {
        lseek(fd_, static_cast<off_t>(length), SEEK_SET);
    }
    XMP_CATCH_THROW();
}

XMP_IO *XMPFd_IO::DeriveTemp()
{
    XMP_TRY();
    this->ValidateWritableOrThrow("XMPFd_IO::DeriveTemp");
    this->ValidateSeekableOrThrow("XMPFd_IO::DeriveTemp");

    if (derivedTemp_ != nullptr) {
        return derivedTemp_;
    }

    std::string sourcePath;
    if (!TryGetFdPath(fd_, sourcePath)) {
        XMP_Throw("XMPFd_IO::DeriveTemp, failed to resolve source path", kXMPErr_ExternalFailure);
    }

    int tempFd = -1;
    int tempErrno = 0;
    std::string tempPath;
    if (!TryCreateDerivedTempFd(sourcePath, tempFd, tempPath, tempErrno)) {
        this->ThrowErrnoExternalFailure("XMPFd_IO::DeriveTemp(open)", tempErrno);
    }

    TempFileGuard tempGuard;
    tempGuard.fd = tempFd;
    tempGuard.path = tempPath;

    derivedTemp_ = new XMPFd_IO(tempGuard.fd, false, true);
    tempFilePath_ = tempGuard.path;
    tempGuard.Release();
    return derivedTemp_;
    XMP_CATCH_THROW();
    return nullptr;
}

void XMPFd_IO::AbsorbTemp()
{
    XMP_TRY();
    XMPFd_IO *temp = static_cast<XMPFd_IO *>(derivedTemp_);
    if (temp == nullptr) {
        XMP_Throw("XMPFd_IO::AbsorbTemp, no temp to absorb", kXMPErr_InternalFailure);
    }
    this->ValidateWritableOrThrow("XMPFd_IO::AbsorbTemp");
    this->ValidateSeekableOrThrow("XMPFd_IO::AbsorbTemp");

    int tempFd = temp->GetFd();
    if (tempFd < 0) {
        XMP_Throw("XMPFd_IO::AbsorbTemp, invalid temp file descriptor", kXMPErr_BadParam);
    }

    SeekToStartOrThrow(fd_, "XMPFd_IO::AbsorbTemp(lseek orig)");
    SeekToStartOrThrow(tempFd, "XMPFd_IO::AbsorbTemp(lseek temp)");
    TruncateToZeroOrThrow(fd_, "XMPFd_IO::AbsorbTemp(ftruncate)");
    CopyAllOrThrow(tempFd, fd_, "XMPFd_IO::AbsorbTemp(read)", "XMPFd_IO::AbsorbTemp(write)");

    // Cleanup temp file
    delete temp;
    derivedTemp_ = nullptr;

    RemoveTempFile(tempFilePath_);

    SeekToStartOrThrow(fd_, "XMPFd_IO::AbsorbTemp(lseek reset)");
    XMP_CATCH_THROW();
}

void XMPFd_IO::DeleteTemp()
{
    XMP_TRY();
    ResetDerivedTemp(derivedTemp_);
    RemoveTempFile(tempFilePath_);
    XMP_CATCH_NO_RETURN();
}

int XMPFd_IO::GetFd() const
{
    return fd_;
}

bool XMPFd_IO::IsValid() const
{
    // Best-effort validation for external callers; detailed failures are reported by Validate*OrThrow.
    if (fd_ < 0) {
        return false;
    }
    if (fcntl(fd_, F_GETFD) == -1) {
        return false;
    }
    if (lseek(fd_, 0, SEEK_CUR) == static_cast<off_t>(-1)) {
        if (errno == ESPIPE) {
            return false;
        }
    }
    return true;
}

void XMPFd_IO::ValidateFdOrThrow(const char *context) const
{
    if (fd_ < 0) {
        XMP_Throw("XMPFd_IO, invalid file descriptor", kXMPErr_BadParam);
    }
    if (fcntl(fd_, F_GETFD) == -1) {
        ThrowErrnoExternalFailure(context, errno);
    }
}

void XMPFd_IO::ValidateWritableOrThrow(const char *context) const
{
    this->ValidateFdOrThrow(context);
    if (readOnly_) {
        XMP_Throw("XMPFd_IO, write not permitted on read-only stream", kXMPErr_FilePermission);
    }
    this->ValidateAccessModeOrThrow(context);
}

void XMPFd_IO::ValidateSeekableOrThrow(const char *context) const
{
    this->ValidateFdOrThrow(context);
    if (lseek(fd_, 0, SEEK_CUR) == static_cast<off_t>(-1)) {
        ThrowErrnoExternalFailure(context, errno);
    }
}

void XMPFd_IO::ValidateAccessModeOrThrow(const char *context) const
{
    this->ValidateFdOrThrow(context);
    const int flags = fcntl(fd_, F_GETFL);
    if (flags == -1) {
        ThrowErrnoExternalFailure(context, errno);
    }

    const int accMode = (flags & O_ACCMODE);
    if (readOnly_) {
        if (accMode == O_WRONLY) {
            XMP_Throw("XMPFd_IO, fd is write-only but stream is read-only", kXMPErr_ExternalFailure);
        }
    } else {
        if (accMode != O_RDWR) {
            XMP_Throw("XMPFd_IO, fd must be read-write for writable stream", kXMPErr_ExternalFailure);
        }
    }
}

void XMPFd_IO::ThrowErrnoExternalFailure(const char *context, int err)
{
    char msg[ERR_MSG_MAX] = {0};
    char errBuf[ERR_MSG_MAX] = {0};
    const char *errStr = "unknown";
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    char *ret = strerror_r(err, errBuf, sizeof(errBuf));
    if (ret != nullptr) {
        errStr = ret;
    }
#else
    if (strerror_r(err, errBuf, sizeof(errBuf)) == 0) {
        errStr = errBuf;
    }
#endif
    int rc = sprintf_s(msg, sizeof(msg), "%s, errno=%d(%s)", context, err, errStr);
    if (rc <= 0 || static_cast<size_t>(rc) >= sizeof(msg)) {
        XMP_Throw("XMPFd_IO, failed to format error message", kXMPErr_ExternalFailure);
    }
    XMP_Throw(msg, kXMPErr_ExternalFailure);
}

void XMPFd_IO::SeekToStartOrThrow(int fd, const char *context)
{
    if (lseek(fd, 0, SEEK_SET) < 0) {
        ThrowErrnoExternalFailure(context, errno);
    }
}

void XMPFd_IO::TruncateToZeroOrThrow(int fd, const char *context)
{
    if (ftruncate(fd, 0) < 0) {
        ThrowErrnoExternalFailure(context, errno);
    }
}

void XMPFd_IO::WriteAllOrThrow(int fd, const void *buffer, size_t size, const char *contextWrite)
{
    const uint8_t *data = static_cast<const uint8_t *>(buffer);
    size_t writtenTotal = 0;
    while (writtenTotal < size) {
        ssize_t bytesWritten = write(fd, data + writtenTotal, size - writtenTotal);
        if (bytesWritten > 0) {
            writtenTotal += static_cast<size_t>(bytesWritten);
            continue;
        }
        if (bytesWritten == 0) {
            XMP_Throw("XMPFd_IO::WriteAllOrThrow, write returned 0", kXMPErr_ExternalFailure);
        }
        if (errno == EINTR) {
            continue;
        }
        ThrowErrnoExternalFailure(contextWrite, errno);
    }
}

void XMPFd_IO::CopyAllOrThrow(int srcFd, int dstFd, const char *contextRead, const char *contextWrite)
{
    char buffer[COPY_BUFFER_SIZE];
    for (ssize_t bytesRead = read(srcFd, buffer, sizeof(buffer)); bytesRead != 0;
         bytesRead = read(srcFd, buffer, sizeof(buffer))) {
        if (bytesRead > 0) {
            WriteAllOrThrow(dstFd, buffer, static_cast<size_t>(bytesRead), contextWrite);
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        ThrowErrnoExternalFailure(contextRead, errno);
    }
}

bool XMPFd_IO::CanConvertToOffT(XMP_Int64 value)
{
    if (value < static_cast<XMP_Int64>(std::numeric_limits<off_t>::min())) {
        return false;
    }
    if (value > static_cast<XMP_Int64>(std::numeric_limits<off_t>::max())) {
        return false;
    }
    return true;
}
} // namespace Media
} // namespace OHOS
