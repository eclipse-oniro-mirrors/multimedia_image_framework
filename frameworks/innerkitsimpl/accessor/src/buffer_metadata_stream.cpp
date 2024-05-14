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
#include <cstring>
#include <fcntl.h>
#include <new>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "buffer_metadata_stream.h"
#include "image_log.h"
#include "metadata_stream.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "BufferMetadataStream"

namespace OHOS {
namespace Media {
BufferMetadataStream::BufferMetadataStream()
{
    buffer_ = nullptr;
    capacity_ = 0;
    bufferSize_ = 0;
    currentOffset_ = 0;
    memoryMode_ = Dynamic;
    originData_ = nullptr;
}

BufferMetadataStream::BufferMetadataStream(byte *originData, size_t size, MemoryMode mode)
{
    buffer_ = originData;
    this->originData_ = originData;
    capacity_ = static_cast<long>(size);
    bufferSize_ = size;
    currentOffset_ = 0;
    memoryMode_ = mode;
}

BufferMetadataStream::~BufferMetadataStream()
{
    Close();
}

ssize_t BufferMetadataStream::Write(uint8_t *data, ssize_t size)
{
    // Check if the new data will fit into the current buffer
    if (currentOffset_ + static_cast<long>(size) > capacity_) {
        if (memoryMode_ == Fix) {
            IMAGE_LOGE("BufferMetadataStream::Write failed, data size exceeds buffer capacity, "
                "currentOffset:%{public}ld, size:%{public}ld, capacity:%{public}ld",
                currentOffset_, static_cast<long>(size), capacity_);
            return -1;
        }

        // Calculate the new capacity, ensuring it is a multiple of
        // BUFFER_IMAGE_STREAM_PAGE_SIZE
        long newCapacity = CalculateNewCapacity(currentOffset_, size);
        if (newCapacity > METADATA_STREAM_MAX_CAPACITY) {
            IMAGE_LOGE("BufferMetadataStream::Write failed, new capacity exceeds maximum capacity, "
                "newCapacity:%{public}ld, maxCapacity:%{public}d",
                newCapacity, METADATA_STREAM_MAX_CAPACITY);
            return -1;
        }

        // Allocate the new buffer
        byte *newBuffer = new (std::nothrow) byte[newCapacity];

        // Check if the allocation was successful
        if (newBuffer == nullptr) {
            IMAGE_LOGE("BufferMetadataStream::Write failed, unable to allocate new buffer");
            return -1;
        }

        // Removed std::fill_n for efficiency. If zero-initialization is needed,
        // consider doing it manually where necessary.
        // If there is existing data, copy it to the new buffer
        if (buffer_ != nullptr) {
            memcpy_s(newBuffer, newCapacity, buffer_, bufferSize_);

            // If the old buffer was not externally allocated, delete it
            if (originData_ != buffer_) {
                delete[] buffer_;
                buffer_ = nullptr;
            }
        }

        // Update the buffer and capacity
        buffer_ = newBuffer;
        capacity_ = newCapacity;

        // Update expansion count
        if (memoryMode_ == Dynamic) {
            expandCount_++;
        }
    }

    // Copy the new data into the buffer
    memcpy_s(buffer_ + currentOffset_, capacity_ - currentOffset_, data, size);

    // Update the current offset and buffer size
    currentOffset_ += size;
    bufferSize_ = std::max(currentOffset_, bufferSize_);

    return size;
}

ssize_t BufferMetadataStream::Read(uint8_t *buf, ssize_t size)
{
    if (currentOffset_ >= bufferSize_) {
        IMAGE_LOGE("BufferMetadataStream::Read failed, current offset exceeds buffer size, "
            "currentOffset:%{public}ld, bufferSize:%{public}ld",
            currentOffset_, bufferSize_);
        return -1;
    }

    long bytesToRead = std::min(static_cast<long>(size), bufferSize_ - currentOffset_);
    memcpy_s(buf, size, buffer_ + currentOffset_, bytesToRead);
    currentOffset_ += bytesToRead;
    return bytesToRead;
}

int BufferMetadataStream::ReadByte()
{
    if (currentOffset_ >= bufferSize_) {
        IMAGE_LOGE("BufferMetadataStream::ReadByte failed, current offset exceeds buffer size, "
            "currentOffset:%{public}ld, bufferSize:%{public}ld",
            currentOffset_, bufferSize_);
        return -1;
    }

    if (currentOffset_ < bufferSize_) {
        return buffer_[currentOffset_++];
    }
    return -1;
}

long BufferMetadataStream::Seek(long offset, SeekPos pos)
{
    switch (pos) {
        case SeekPos::BEGIN:
            currentOffset_ = offset;
            break;
        case SeekPos::CURRENT:
            currentOffset_ += offset;
            break;
        case SeekPos::END:
            currentOffset_ = bufferSize_ + offset;
            break;
        default:
            return -1;
    }

    if (currentOffset_ > bufferSize_) {
        currentOffset_ = bufferSize_;
    }

    return currentOffset_;
}

long BufferMetadataStream::Tell()
{
    return currentOffset_;
}

bool BufferMetadataStream::IsEof()
{
    return currentOffset_ >= bufferSize_;
}

bool BufferMetadataStream::IsOpen()
{
    return true;
}

void BufferMetadataStream::Close()
{
    if (memoryMode_ == Dynamic && buffer_ != originData_ && buffer_ != nullptr) {
        delete[] buffer_;
        buffer_ = nullptr;
    }
    currentOffset_ = 0;
}

bool BufferMetadataStream::Open(OpenMode mode)
{
    return true;
}

bool BufferMetadataStream::Flush()
{
    return true;
}

byte *BufferMetadataStream::GetAddr(bool isWriteable)
{
    return buffer_;
}

bool BufferMetadataStream::CopyFrom(MetadataStream &src)
{
    if (!src.IsOpen()) {
        IMAGE_LOGE("BufferMetadataStream::CopyFrom failed, source stream is not open");
        return false;
    }
    if (src.GetSize() == 0) {
        return true;
    }
    if (memoryMode_ == Fix) {
        if (src.GetSize() > static_cast<ssize_t>(capacity_)) {
            // If the memory is fixed and the source size is too large, do not copy the data
            IMAGE_LOGE("BufferMetadataStream::CopyFrom failed, source size is larger than capacity, "
                "source size:%{public}zu, capacity:%{public}ld",
                src.GetSize(), capacity_);
            return false;
        }
    }

    // Clear the current buffer
    if (memoryMode_ == Dynamic) {
        if (buffer_ != nullptr && buffer_ != originData_) {
            delete[] buffer_;
            buffer_ = nullptr;
        }
        ssize_t estimatedSize = ((src.GetSize() + METADATA_STREAM_PAGE_SIZE - 1) / METADATA_STREAM_PAGE_SIZE) *
            METADATA_STREAM_PAGE_SIZE; // Ensure it is a multiple of 32k
        buffer_ = new (std::nothrow) byte[estimatedSize];
        if (buffer_ == nullptr) {
            IMAGE_LOGE("BufferMetadataStream::CopyFrom failed, insufficient memory for buffer allocation");
            return false;
        }
        capacity_ = estimatedSize;
    }

    currentOffset_ = 0;
    bufferSize_ = 0;

    // Read data from the source ImageStream and write it to the current buffer
    if (!ReadAndWriteData(src)) {
        return false;
    }
    return true;
}

bool BufferMetadataStream::ReadAndWriteData(MetadataStream &src)
{
    src.Seek(0, SeekPos::BEGIN);
    ssize_t buffer_size = std::min((ssize_t)METADATA_STREAM_PAGE_SIZE, src.GetSize());
    if (buffer_size > METADATA_STREAM_PAGE_SIZE) {
        return false;
    }
    byte *tempBuffer = new (std::nothrow) byte[buffer_size];
    if (tempBuffer == nullptr) {
        IMAGE_LOGE("BufferMetadataStream::ReadAndWriteData failed, insufficient memory for temporary buffer");
        return false;
    }
    while (!src.IsEof()) {
        ssize_t bytesRead = src.Read(tempBuffer, buffer_size);
        if (bytesRead > 0) {
            if (Write(tempBuffer, bytesRead) == -1) {
                IMAGE_LOGE("BufferMetadataStream::ReadAndWriteData failed, unable to write to buffer");
                HandleWriteFailure();
                delete[] tempBuffer;
                return false;
            }
        }
    }
    delete[] tempBuffer;
    return true;
}

void BufferMetadataStream::HandleWriteFailure()
{
    if (memoryMode_ == Dynamic && buffer_ != originData_) {
        delete[] buffer_;
        buffer_ = nullptr;
        capacity_ = 0;
    }
    bufferSize_ = 0;
    currentOffset_ = 0;
}

ssize_t BufferMetadataStream::GetSize()
{
    return bufferSize_;
}

byte *BufferMetadataStream::Release()
{
    byte *ret = buffer_;
    buffer_ = nullptr;
    capacity_ = 0;
    bufferSize_ = 0;
    currentOffset_ = 0;
    return ret;
}

long BufferMetadataStream::CalculateNewCapacity(long currentOffset, ssize_t size)
{
    long newCapacity;
    switch (expandCount_) {
        case INITIAL_EXPANSION:
            newCapacity =
                ((currentOffset + size + METADATA_STREAM_INITIAL_CAPACITY - 1) / METADATA_STREAM_INITIAL_CAPACITY) *
                METADATA_STREAM_INITIAL_CAPACITY;
            break;
        case SECOND_EXPANSION:
            newCapacity =
                ((currentOffset + size + METADATA_STREAM_CAPACITY_512KB - 1) / METADATA_STREAM_CAPACITY_512KB) *
                METADATA_STREAM_CAPACITY_512KB;
            break;
        case THIRD_EXPANSION:
            newCapacity = ((currentOffset + size + METADATA_STREAM_CAPACITY_2MB - 1) / METADATA_STREAM_CAPACITY_2MB) *
                METADATA_STREAM_CAPACITY_2MB;
            break;
        case FOURTH_EXPANSION:
            newCapacity = ((currentOffset + size + METADATA_STREAM_CAPACITY_5MB - 1) / METADATA_STREAM_CAPACITY_5MB) *
                METADATA_STREAM_CAPACITY_5MB;
            break;
        case FIFTH_EXPANSION:
            newCapacity = ((currentOffset + size + METADATA_STREAM_CAPACITY_15MB - 1) / METADATA_STREAM_CAPACITY_15MB) *
                METADATA_STREAM_CAPACITY_15MB;
            break;
        default:
            newCapacity = ((currentOffset + size + METADATA_STREAM_CAPACITY_30MB - 1) / METADATA_STREAM_CAPACITY_30MB) *
                METADATA_STREAM_CAPACITY_30MB;
            break;
    }
    return newCapacity;
}
} // namespace Media
} // namespace OHOS
