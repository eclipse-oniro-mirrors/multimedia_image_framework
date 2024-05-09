/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file_metadata_stream.h"
#include "image_log.h"
#include "metadata_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "FileMetadataStream"

namespace OHOS {
namespace Media {
ssize_t FileWrapper::FWrite(const void *src, size_t size, ssize_t nmemb, FILE *file)
{
    return ::fwrite(src, size, nmemb, file);
}

ssize_t FileWrapper::FRead(void *destv, size_t size, ssize_t nmemb, FILE *file)
{
    return ::fread(destv, size, nmemb, file);
}

FileMetadataStream::FileMetadataStream(const std::string &filePath)
{
    initPath_ = INIT_FROM_PATH;
    Initialize(filePath);
}

FileMetadataStream::FileMetadataStream(int fileDescriptor)
{
    initPath_ = INIT_FROM_FD;
    Initialize("", fileDescriptor);
}

FileMetadataStream::FileMetadataStream(const std::string &filePath, std::unique_ptr<FileWrapper> fileWrapper)
    : fp_(nullptr), fileWrapper_(std::move(fileWrapper))
{
    initPath_ = INIT_FROM_PATH;
    Initialize(filePath);
}

FileMetadataStream::~FileMetadataStream()
{
    Close();
}

void FileMetadataStream::Initialize(const std::string &filePath, int fileDescriptor)
{
    this->fp_ = nullptr;
    this->filePath_ = filePath;
    this->dupFD_ = dup(fileDescriptor);
    if (!fileWrapper_) {
        this->fileWrapper_ = std::make_unique<FileWrapper>();
    }
    mappedMemory_ = nullptr;
}

// Error handling function
void HandleFileError(const std::string &operation, const std::string &filePath, int fileDescriptor, ssize_t result,
    ssize_t expectedSize)
{
    std::string buf(METADATA_STREAM_ERROR_BUFFER_SIZE, '\0');
    strerror_r(errno, &buf[0], buf.size());

    if (fileDescriptor != -1) { // If the operation is through a file descriptor
        IMAGE_LOGE("%{public}s file failed: %{public}d, reason: "
            "%{public}s. result is %{public}zd, expected size is %{public}zd",
            operation.c_str(), fileDescriptor, buf.c_str(), result, expectedSize);
    } else { // If the operation is through a file path
        IMAGE_LOGE("%{public}s file failed: %{public}s, reason: "
            "%{public}s. result is %{public}zd, expected size is %{public}zd",
            operation.c_str(), filePath.c_str(), buf.c_str(), result, expectedSize);
    }
}

ssize_t FileMetadataStream::Write(byte *data, ssize_t size)
{
    if (fp_ == nullptr) {
        HandleFileError("Write", filePath_, -1, -1, size);
        return -1;
    }

    ssize_t result = fileWrapper_->FWrite(data, 1, size, fp_);
    if (result != size || (ferror(fp_) != 0)) {
        HandleFileError("Write", filePath_, (initPath_ == INIT_FROM_FD) ? dupFD_ : -1, result, size);
        return -1;
    }

    return result;
}

ssize_t FileMetadataStream::Read(byte *buf, ssize_t size)
{
    if (fp_ == nullptr) {
        HandleFileError("Read", filePath_, -1, -1, size);
        return -1;
    }
    if (size == 0) {
        return 0;
    }

    ssize_t result = fileWrapper_->FRead(buf, 1, size, fp_);
    if (result == 0 && ferror(fp_) != 0) {
        HandleFileError("Read", filePath_, (initPath_ == INIT_FROM_FD) ? dupFD_ : -1, result, size);
        return -1;
    }

    return result;
}

int FileMetadataStream::ReadByte()
{
    if (fp_ == nullptr) {
        HandleFileError("ReadByte", filePath_, -1, -1, 1);
        return -1;
    }

    int byte = fgetc(fp_);
    if (byte == EOF) {
        HandleFileError("ReadByte", filePath_, (initPath_ == INIT_FROM_FD) ? dupFD_ : -1, byte, 1);
        return -1;
    }

    return byte;
}

long FileMetadataStream::Seek(long offset, SeekPos pos)
{
    if (fp_ == nullptr) {
        HandleFileError("Seek", filePath_, -1, -1, offset);
        return -1;
    }

    int origin;
    switch (pos) {
        case SeekPos::BEGIN:
            origin = SEEK_SET;
            break;
        case SeekPos::CURRENT:
            origin = SEEK_CUR;
            break;
        case SeekPos::END:
            origin = SEEK_END;
            break;
        default:
            return -1;
    }

    int result = fseek(fp_, offset, origin);
    if (result != 0) {
        HandleFileError("Seek", filePath_, (initPath_ == INIT_FROM_FD) ? dupFD_ : -1, result, offset);
        return -1;
    }

    return ftell(fp_);
}

long FileMetadataStream::Tell()
{
    if (fp_ == nullptr) {
        if (initPath_ == INIT_FROM_FD) {
            IMAGE_LOGE("Tell file failed: %{public}d, reason: %{public}s", dupFD_, "fp is nullptr");
        } else if (initPath_ == INIT_FROM_PATH) {
            IMAGE_LOGE("Tell file failed: %{public}s, reason: %{public}s", filePath_.c_str(), "fp is nullptr");
        } else if (initPath_ == INIT_FROM_UNKNOWN) {
            IMAGE_LOGE("Tell file failed: %{public}s, reason: %{public}s", "initPath is INIT_FROM_UNKNOWN",
                "fp is nullptr");
        }
        IMAGE_LOGE("Tell file failed: %{public}s, reason: %{public}s", filePath_.c_str(), "fp is nullptr");
        return -1;
    }

    return ftell(fp_);
}

bool FileMetadataStream::IsEof()
{
    if (fp_ == nullptr) {
        HandleFileError("Check EOF", "", -1, -1, -1);
        return true;
    }

    if (ferror(fp_) != 0) {
        HandleFileError("Check EOF", "", fileno(fp_), -1, -1);
        return true;
    }

    long currentPos = ftell(fp_);
    if (Seek(0, SeekPos::END) == -1) {
        return true;
    }

    long fileSize = ftell(fp_);

    bool isEof = currentPos == fileSize;

    if (Seek(currentPos, SeekPos::BEGIN) == -1) {
        return true;
    }

    return isEof;
}

bool FileMetadataStream::IsOpen()
{
    return fp_ != nullptr;
}

void FileMetadataStream::Close()
{
    ReleaseAddr();

    // If the file is not open, return directly
    if (fp_ != nullptr) {
        fclose(fp_);
        fp_ = nullptr;
    }

    // Close the file
    int tmpFD = dupFD_;
    if (dupFD_ != -1) {
        dupFD_ = -1;
    }

    // Reset all member variables
    if (initPath_ == INIT_FROM_FD) {
        IMAGE_LOGD("File closed: %{public}d", tmpFD);
    } else if (initPath_ == INIT_FROM_PATH) {
        IMAGE_LOGD("File closed: %{public}s", filePath_.c_str());
    }
    initPath_ = INIT_FROM_UNKNOWN;
}

bool FileMetadataStream::OpenFromFD(const char *modeStr)
{
    if (dupFD_ == -1) {
        HandleFileError("Open file", filePath_, -1, -1, -1);
        return false;
    }

    // Decide how to create FILE* fp based on the mode parameter
    fp_ = fdopen(dupFD_, modeStr);
    if (fp_ == NULL || ferror(fp_) != 0) {
        HandleFileError("Open file", filePath_, dupFD_, -1, -1);
        return false;
    }
    IMAGE_LOGD("File opened: %{public}d", dupFD_);

    return true;
}

bool FileMetadataStream::OpenFromPath(const char *modeStr)
{
    IMAGE_LOGD("Open file: %{public}s, modeStr: %{public}s", filePath_.c_str(), modeStr);
    fp_ = fopen(filePath_.c_str(), modeStr);
    if (fp_ == nullptr) {
        HandleFileError("Open file", filePath_, -1, -1, -1);
        return false;
    }
    IMAGE_LOGD("File opened: %{public}s", filePath_.c_str());
    return true;
}

bool FileMetadataStream::Open(OpenMode mode)
{
    if (initPath_ == INIT_FROM_UNKNOWN) {
        IMAGE_LOGE("initPath is INIT_FROM_UNKNOWN. It seems that the file has "
            "been closed before.");
        return false;
    }

    const char *modeStr;
    switch (mode) {
        case OpenMode::Read:
            modeStr = "r";
            break;
        case OpenMode::ReadWrite:
            modeStr = "r+";
            break;
        default:
            return false;
    }

    bool openResult = false;
    if (initPath_ == INIT_FROM_FD) {
        IMAGE_LOGD("initPath is INIT_FROM_FD");
        openResult = OpenFromFD(modeStr);
    }
    if (initPath_ == INIT_FROM_PATH) {
        IMAGE_LOGD("initPath is INIT_FROM_PATH");
        openResult = OpenFromPath(modeStr);
    }

    if (!openResult) {
        return false;
    }

    return true;
}

byte *FileMetadataStream::GetAddr(bool isWriteable)
{
    // If there is already a memory map, return it directly
    if (mappedMemory_ != nullptr) {
        IMAGE_LOGE("mmap: There is already a memory mapping, return it directly");
        return (byte *)mappedMemory_;
    }

    // If the file is not open, open it first
    if (fp_ == nullptr) {
        HandleFileError("Get memory address", filePath_, -1, -1, -1);
        return nullptr;
    }

    // Get the file descriptor from the file pointer
    int fileDescriptor = fileno(fp_);

    // Create a memory map
    mappedMemory_ =
        ::mmap(nullptr, GetSize(), isWriteable ? (PROT_READ | PROT_WRITE) : PROT_READ, MAP_SHARED, fileDescriptor, 0);
    if (mappedMemory_ == (void *)MAP_FAILED) {
        HandleFileError("Create memory mapping", filePath_, fileDescriptor, -1, -1);
        mappedMemory_ = nullptr;
    }
    IMAGE_LOGD("mmap: Memory mapping created: %{public}s, size: %{public}zu", filePath_.c_str(), GetSize());
    return (byte *)mappedMemory_;
}

bool FileMetadataStream::ReleaseAddr()
{
    if (mappedMemory_ == nullptr) {
        return true;
    }

    // Delete the memory map
    if (munmap(mappedMemory_, GetSize()) == -1) {
        // Memory mapping failed
        HandleFileError("Remove memory mapping", filePath_, -1, -1, -1);
        return false;
    }
    IMAGE_LOGD("munmap: Memory mapping removed: %{public}s, size: %{public}zu", filePath_.c_str(), GetSize());

    mappedMemory_ = nullptr;
    return true;
}

bool FileMetadataStream::Flush()
{
    if (fp_ == nullptr) {
        HandleFileError("Flush file", filePath_, -1, -1, -1);
        return false;
    }

    if (fflush(fp_) != 0) {
        HandleFileError("Flush file", filePath_, fileno(fp_), -1, -1);
        return false;
    }

    return true;
}

bool FileMetadataStream::TruncateFile(size_t totalBytesWritten, MetadataStream &src, ssize_t src_cur)
{
    int fileDescriptor = fileno(fp_);
    if (ftruncate(fileDescriptor, totalBytesWritten) == -1) {
        HandleFileError("Truncate file", filePath_, fileDescriptor, -1, totalBytesWritten);
        src.Seek(src_cur, SeekPos::BEGIN); // Restore the position of src
        return false;
    }
    return true;
}

bool FileMetadataStream::CopyDataFromSource(MetadataStream &src, ssize_t &totalBytesWritten)
{
    ssize_t buffer_size = std::min((ssize_t)METADATA_STREAM_COPY_FROM_BUFFER_SIZE, src.GetSize());
    if (buffer_size > METADATA_STREAM_COPY_FROM_BUFFER_SIZE) {
        return false;
    }
    byte *tempBuffer = new (std::nothrow) byte[buffer_size];
    if (tempBuffer == nullptr) {
        // Handle memory allocation failure
        HandleFileError("Memory allocation", filePath_, -1, -1, buffer_size);
        return false;
    }

    Seek(0, SeekPos::BEGIN);
    src.Seek(0, SeekPos::BEGIN); // Set the position of src to 0

    bool result = ReadFromSourceAndWriteToFile(src, tempBuffer, buffer_size, totalBytesWritten);
    delete[] tempBuffer;
    return result;
}

bool FileMetadataStream::ReadFromSourceAndWriteToFile(MetadataStream &src, byte *tempBuffer, ssize_t buffer_size,
    ssize_t &totalBytesWritten)
{
    while (!src.IsEof()) {
        ssize_t bytesRead = src.Read(tempBuffer, buffer_size);
        if (bytesRead > 0) {
            size_t bytesWritten = Write(tempBuffer, bytesRead);
            if (bytesWritten == static_cast<size_t>(-1)) {
                // Write failed
                HandleFileError("Write file", filePath_, fileno(fp_), bytesWritten, bytesRead);
                return false;
            }
            totalBytesWritten += bytesWritten;
        }
        if (bytesRead < 0 && !src.IsEof()) {
            HandleFileError("Read file", filePath_, -1, bytesRead, buffer_size);
            return false;
        }
    }
    return true;
}

bool FileMetadataStream::CopyFrom(MetadataStream &src)
{
    ssize_t oldSize = GetSize();
    if (!src.IsOpen()) {
        IMAGE_LOGE("transfer: Source file is not open");
        return false;
    }

    if (!IsOpen()) {
        IMAGE_LOGE("transfer: File is not open: %{public}s", filePath_.c_str());
        return false;
    }

    ssize_t totalBytesWritten = 0;
    ssize_t src_cur = src.Tell(); // Temporarily store the position of src

    if (!CopyDataFromSource(src, totalBytesWritten)) {
        return false;
    }

    IMAGE_LOGD("transfer: Write file done: %{public}s, size: %{public}zu", filePath_.c_str(), totalBytesWritten);

    // Flush the file
    if (!Flush()) {
        return false;
    }

    // Truncate the file only if totalBytesWritten is less than oldSize
    if (totalBytesWritten < oldSize) {
        if (!TruncateFile(totalBytesWritten, src, src_cur)) {
            return false;
        }
    }

    return true;
}

ssize_t FileMetadataStream::GetSize()
{
    if (fp_ == nullptr) {
        HandleFileError("GetSize", filePath_, -1, -1, -1);
        return -1;
    }
    ssize_t oldPos = Tell();
    if (fseek(fp_, 0, SEEK_END) != 0) {
        std::string errstr(METADATA_STREAM_ERROR_BUFFER_SIZE, '\0');
        strerror_r(errno, &errstr[0], METADATA_STREAM_ERROR_BUFFER_SIZE);
        IMAGE_LOGE("Failed to seek to the end of the file: %{public}s", errstr.c_str());
        return -1;
    }

    ssize_t fileSize = ftell(fp_);

    if (fseek(fp_, oldPos, SEEK_SET) != 0) { // Restore the file pointer to its original position
        std::string errstr(METADATA_STREAM_ERROR_BUFFER_SIZE, '\0');
        strerror_r(errno, &errstr[0], METADATA_STREAM_ERROR_BUFFER_SIZE);
        IMAGE_LOGE("Failed to restore the file position: %{public}s", errstr.c_str());
        return -1;
    }

    return fileSize;
}
} // namespace Media
} // namespace OHOS
