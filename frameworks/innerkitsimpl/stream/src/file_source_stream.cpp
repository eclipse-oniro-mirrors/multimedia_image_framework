/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "file_source_stream.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "directory_ex.h"
#include "file_packer_stream.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
#include <sys/mman.h>
#define SUPPORT_MMAP
#endif

const unsigned HMDFS_IOC = 0xf2;
#define HMDFS_IOC_GET_LOCATION _IOR(HMDFS_IOC, 7, unsigned int)

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "FileSourceStream"

namespace OHOS {
namespace Media {
using namespace std;
using namespace ImagePlugin;

constexpr int INVALID_POSITION = -1;
constexpr int IOCTL_SUCCESS = 0;
constexpr int LOCAL_FILE_POSITION = 1;

FileSourceStream::FileSourceStream(std::FILE *file, size_t size, size_t offset, size_t original,
                                   bool useMmap, int originalFd)
    : filePtr_(file), fileSize_(size), fileOffset_(offset), fileOriginalOffset_(original),
    useMmap_(useMmap)
{
    originalFd_ = originalFd;
}

FileSourceStream::FileSourceStream(std::FILE *file, size_t size, size_t offset, size_t original,
                                   bool useMmap, const std::string &originalPath)
    : filePtr_(file), fileSize_(size), fileOffset_(offset), fileOriginalOffset_(original),
    useMmap_(useMmap)
{
    originalPath_ = originalPath;
}

FileSourceStream::~FileSourceStream()
{
    IMAGE_LOGD("[FileSourceStream]destructor enter.");
    if (filePtr_ != nullptr) {
        fclose(filePtr_);
        filePtr_ = nullptr;
    }
    ResetReadBuffer();
}

unique_ptr<FileSourceStream> FileSourceStream::CreateSourceStream(const string &pathName)
{
    string realPath;
    if (!PathToRealPath(pathName, realPath)) {
        IMAGE_LOGE("[FileSourceStream]input the file path exception, errno:%{public}d.", errno);
        return nullptr;
    }
    FILE *filePtr = fopen(realPath.c_str(), "rb");
    if (filePtr == nullptr) {
        IMAGE_LOGE("[FileSourceStream]open file fail.");
        return nullptr;
    }
    int fd = fileno(filePtr);
    bool useMmap = ShouldUseMmap(fd);
    size_t size = 0;
    if (!ImageUtils::GetFileSize(realPath, size)) {
        IMAGE_LOGE("[FileSourceStream]get the file size fail");
        fclose(filePtr);
        return nullptr;
    }
    int64_t offset = ftell(filePtr);
    if (offset < 0) {
        IMAGE_LOGE("[FileSourceStream]get the position fail.");
        fclose(filePtr);
        return nullptr;
    }
    return make_unique<FileSourceStream>(filePtr, size, offset, offset, useMmap, realPath);
}

unique_ptr<FileSourceStream> FileSourceStream::CreateSourceStream(const int fd)
{
    int dupFd = dup(fd);
    if (dupFd < 0) {
        IMAGE_LOGE("[FileSourceStream]Fail to dup fd.");
        return nullptr;
    }

    FILE *filePtr = fdopen(dupFd, "rb");
    if (filePtr == nullptr) {
        IMAGE_LOGE("[FileSourceStream]open file fail.");
        return nullptr;
    }
    bool useMmap = ShouldUseMmap(fd);
    size_t size = 0;
    if (!ImageUtils::GetFileSize(dupFd, size)) {
        IMAGE_LOGE("[FileSourceStream]get the file size fail. dupFd=%{public}d", dupFd);
        fclose(filePtr);
        return nullptr;
    }

    int ret = fseek(filePtr, 0, SEEK_SET);
    if (ret != 0) {
        IMAGE_LOGE("[FileSourceStream]Go to 0 position fail, ret:%{public}d.", ret);
    }

    int64_t offset = ftell(filePtr);
    if (offset < 0) {
        IMAGE_LOGE("[FileSourceStream]get the position fail.");
        fclose(filePtr);
        return nullptr;
    }
    return make_unique<FileSourceStream>(filePtr, size, offset, offset, useMmap, dupFd);
}

unique_ptr<FileSourceStream> FileSourceStream::CreateSourceStream(
    const int fd, int32_t offset, int32_t length)
{
    int dupFd = dup(fd);
    if (dupFd < 0) {
        IMAGE_LOGE("[FileSourceStream]Fail to dup fd.");
        return nullptr;
    }

    FILE *filePtr = fdopen(dupFd, "rb");
    if (filePtr == nullptr) {
        IMAGE_LOGE("[FileSourceStream]open file fail.");
        return nullptr;
    }
    bool useMmap = ShouldUseMmap(fd);
    int ret = fseek(filePtr, offset, SEEK_SET);
    if (ret != 0) {
        IMAGE_LOGE("[FileSourceStream]Go to %{public}d position fail, ret:%{public}d.", offset, ret);
        return nullptr;
    }
    return make_unique<FileSourceStream>(filePtr, length, offset, offset, useMmap, dupFd);
}

bool FileSourceStream::Read(uint32_t desiredSize, DataStreamBuffer &outData)
{
    if (desiredSize == 0 || filePtr_ == nullptr) {
        IMAGE_LOGE("[FileSourceStream]read stream input parameter exception.");
        return false;
    }
    if (!GetData(desiredSize, outData)) {
        IMAGE_LOGI("[FileSourceStream]read dataStreamBuffer fail.");
        return false;
    }
    fileOffset_ += outData.dataSize;
    return true;
}

bool FileSourceStream::Peek(uint32_t desiredSize, DataStreamBuffer &outData)
{
    if (desiredSize == 0 || filePtr_ == nullptr) {
        IMAGE_LOGE("[FileSourceStream]peek stream input parameter exception.");
        return false;
    }
    if (!GetData(desiredSize, outData)) {
        IMAGE_LOGD("[FileSourceStream]peek dataStreamBuffer fail, desiredSize:%{public}u", desiredSize);
        return false;
    }
    int ret = fseek(filePtr_, fileOffset_, SEEK_SET);
    if (ret != 0) {
        IMAGE_LOGE("[FileSourceStream]go to original position fail, ret:%{public}d.", ret);
        return false;
    }
    return true;
}

bool FileSourceStream::Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize)
{
    if (desiredSize == 0 || outBuffer == nullptr || desiredSize > bufferSize || desiredSize > fileSize_) {
        IMAGE_LOGE("[FileSourceStream]input parameter exception, desiredSize:%{public}u,"
            "bufferSize:%{public}u,fileSize_:%{public}zu.", desiredSize, bufferSize, fileSize_);
        return false;
    }
    if (!GetData(desiredSize, outBuffer, bufferSize, readSize)) {
        IMAGE_LOGD("[FileSourceStream]read outBuffer fail.");
        return false;
    }
    fileOffset_ += readSize;
    return true;
}

bool FileSourceStream::Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize)
{
    if (desiredSize == 0 || outBuffer == nullptr || desiredSize > bufferSize || desiredSize > fileSize_) {
        IMAGE_LOGE("[FileSourceStream]input parameter exception, desiredSize:%{public}u,"
            "bufferSize:%{public}u, fileSize_:%{public}zu.", desiredSize, bufferSize, fileSize_);
        return false;
    }
    if (!GetData(desiredSize, outBuffer, bufferSize, readSize)) {
        IMAGE_LOGI("[FileSourceStream]peek outBuffer fail.");
        return false;
    }
    if (filePtr_ == nullptr) {
        return false;
    }
    int ret = fseek(filePtr_, fileOffset_, SEEK_SET);
    if (ret != 0) {
        IMAGE_LOGE("[FileSourceStream]go to original position fail, ret:%{public}d.", ret);
        return false;
    }
    return true;
}

bool FileSourceStream::Seek(uint32_t position)
{
    if (position > fileSize_) {
        IMAGE_LOGE("[FileSourceStream]Seek the position greater than the file size, position:%{public}u.",
            position);
        return false;
    }
    if (filePtr_ == nullptr) {
        return false;
    }
    size_t targetPosition = position + fileOriginalOffset_;
    fileOffset_ = ((targetPosition < fileSize_) ? targetPosition : fileSize_);
    int ret = fseek(filePtr_, fileOffset_, SEEK_SET);
    if (ret != 0) {
        IMAGE_LOGE("[FileSourceStream]go to offset position fail, ret:%{public}d.", ret);
        return false;
    }
    return true;
}

uint32_t FileSourceStream::Tell()
{
    return fileOffset_ - fileOriginalOffset_;
}

bool FileSourceStream::GetData(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize)
{
    if (fileSize_ == fileOffset_) {
        IMAGE_LOGE("[FileSourceStream]read data finish, offset:%{public}zu ,dataSize%{public}zu.",
            fileOffset_, fileSize_);
        return false;
    }
    if (filePtr_ == nullptr) {
        return false;
    }
    if (desiredSize > (fileSize_ - fileOffset_)) {
        desiredSize = fileSize_ - fileOffset_;
    }
    size_t bytesRead = fread(outBuffer, sizeof(outBuffer[0]), desiredSize, filePtr_);
    if (bytesRead < desiredSize) {
        IMAGE_LOGD("read outBuffer end, bytesRead:%{public}zu, desiredSize:%{public}u, fileSize_:%{public}zu,"
            "fileOffset_:%{public}zu", bytesRead, desiredSize, fileSize_, fileOffset_);
        int fRes = ferror(filePtr_);
        if (fRes) {
            IMAGE_LOGD("fread failed, ferror:%{public}d", fRes);
            return false;
        }
    }
    readSize = bytesRead;
    return true;
}

bool FileSourceStream::GetData(uint32_t desiredSize, DataStreamBuffer &outData)
{
    if (fileSize_ == fileOffset_) {
        IMAGE_LOGE("[FileSourceStream]read finish, offset:%{public}zu ,dataSize%{public}zu.",
            fileOffset_, fileSize_);
        return false;
    }

    if (desiredSize == 0 || desiredSize > MALLOC_MAX_LENTH) {
        IMAGE_LOGE("[FileSourceStream]Invalid value, desiredSize out of size.");
        return false;
    }
    if (filePtr_ == nullptr) {
        return false;
    }

    ResetReadBuffer();
    readBuffer_ = static_cast<uint8_t *>(malloc(desiredSize));
    if (readBuffer_ == nullptr) {
        IMAGE_LOGE("[FileSourceStream]malloc the desiredSize fail.");
        return false;
    }
    outData.bufferSize = desiredSize;
    if (desiredSize > (fileSize_ - fileOffset_)) {
        desiredSize = fileSize_ - fileOffset_;
    }
    size_t bytesRead = fread(readBuffer_, sizeof(uint8_t), desiredSize, filePtr_);
    if (bytesRead < desiredSize) {
        IMAGE_LOGD("read outData end, bytesRead:%{public}zu, desiredSize:%{public}u, fileSize_:%{public}zu,"
            "fileOffset_:%{public}zu", bytesRead, desiredSize, fileSize_, fileOffset_);
        int fRes = ferror(filePtr_);
        if (fRes) {
            IMAGE_LOGD("fread failed, ferror:%{public}d", fRes);
            free(readBuffer_);
            readBuffer_ = nullptr;
            return false;
        }
    }
    outData.inputStreamBuffer = static_cast<uint8_t *>(readBuffer_);
    outData.dataSize = bytesRead;
    return true;
}

size_t FileSourceStream::GetStreamSize()
{
    return fileSize_ - fileOriginalOffset_;
}

static bool DupFd(FILE *f, int &res)
{
    res = fileno(f);
    if (res < 0) {
        IMAGE_LOGE("[FileSourceStream]Fail to fileno fd.");
        return false;
    }
    res = dup(res);
    if (res < 0) {
        IMAGE_LOGE("[FileSourceStream]Fail to dup fd.");
        return false;
    }
    return true;
}

uint8_t *FileSourceStream::GetDataPtr()
{
    return GetDataPtr(false);
}

uint8_t *FileSourceStream::GetDataPtr(bool populate)
{
    if (fileData_ != nullptr) {
        return fileData_;
    }

    if (!useMmap_) {
        uint32_t size = static_cast<uint32_t>(GetStreamSize());
        uint8_t* buffer = new (std::nothrow) uint8_t [size];
        if (buffer == nullptr) {
            IMAGE_LOGE("[FileSourceStream] Failed to new stream buffer.");
            return nullptr;
        }
        uint32_t savedPosition = Tell();
        if (!Seek(0)) {
            IMAGE_LOGE("[FileSourceStream] GetDataPtr seek start failed.");
            delete[] buffer;
            return nullptr;
        }
        uint32_t readSize = 0;
        bool retRead = Read(size, buffer, size, readSize);
        if (!Seek(savedPosition) || !retRead) {
            IMAGE_LOGE("[FileSourceStream] GetDataPtr read failed.");
            delete[] buffer;
            return nullptr;
        }
        IMAGE_LOGD("[FileSourceStream] UseMmap is false, read buffer success.");
        fileData_ = buffer;
        return fileData_;
    }

#ifdef SUPPORT_MMAP
    if (filePtr_ == nullptr) {
        return nullptr;
    }
    if (!DupFd(filePtr_, mmapFd_)) {
        return nullptr;
    }
    auto mmptr = ::mmap(nullptr, fileSize_ - fileOriginalOffset_, PROT_READ,
        populate ? MAP_SHARED | MAP_POPULATE : MAP_SHARED, mmapFd_, fileOriginalOffset_);
    if (mmptr == MAP_FAILED) {
        IMAGE_LOGE("[FileSourceStream] mmap failed, errno:%{public}d", errno);
        close(mmapFd_);
        return nullptr;
    }
    fileData_ = static_cast<uint8_t*>(mmptr);
#endif
    return fileData_;
}

uint32_t FileSourceStream::GetStreamType()
{
    return ImagePlugin::FILE_STREAM_TYPE;
}

void FileSourceStream::ResetReadBuffer()
{
    if (readBuffer_ != nullptr) {
        free(readBuffer_);
        readBuffer_ = nullptr;
    }
    if (fileData_ != nullptr && !mmapFdPassedOn_ && useMmap_) {
#ifdef SUPPORT_MMAP
        ::munmap(fileData_, fileSize_ - fileOriginalOffset_);
        close(mmapFd_);
#endif
    }
    if (!useMmap_) {
        delete [] fileData_;
    }
    fileData_ = nullptr;
}

OutputDataStream* FileSourceStream::ToOutputDataStream()
{
    int dupFd = -1;
    if (filePtr_ == nullptr) {
        return nullptr;
    }
    if (DupFd(filePtr_, dupFd)) {
        IMAGE_LOGE("[FileSourceStream] ToOutputDataStream fd failed");
        return nullptr;
    }
    return new (std::nothrow) FilePackerStream(dupFd);
}

int FileSourceStream::GetMMapFd()
{
    mmapFdPassedOn_ = true;
    return mmapFd_;
}

bool FileSourceStream::ShouldUseMmap(int fd)
{
    int location = INVALID_POSITION;
    bool useMmap = false;
    int err = ioctl(fd, HMDFS_IOC_GET_LOCATION, &location);
    if (err != IOCTL_SUCCESS) {
        IMAGE_LOGD("[FileSourceStream] ioctl failed, error: %{public}d, errno: %{public}d.", err, errno);
        return useMmap;
    }

    if (location == LOCAL_FILE_POSITION) {
        useMmap = true;
    }
    IMAGE_LOGD("[FileSourceStream] File position: %{public}d.", location);
    return useMmap;
}

} // namespace Media
} // namespace OHOS
