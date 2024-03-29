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
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "buffer_metadata_stream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "BufferMetadataStream"

namespace OHOS {
namespace Media {
BufferMetadataStream::BufferMetadataStream() : currentOffset_(0) {}

BufferMetadataStream::~BufferMetadataStream()
{
    Close();
}

ssize_t BufferMetadataStream::Write(uint8_t *data, ssize_t size)
{
    if (buffer_.capacity() < static_cast<unsigned int>(currentOffset_ + size)) {
        // Calculate the required memory size, ensuring it is a multiple of 4k
        size_t newCapacity = ((currentOffset_ + size + METADATA_STREAM_PAGE_SIZE - 1) / METADATA_STREAM_PAGE_SIZE)
                             * METADATA_STREAM_PAGE_SIZE;
        buffer_.reserve(newCapacity);
    }

    buffer_.insert(buffer_.end(), data, data + size);
    currentOffset_ += size;
    return size;
}

ssize_t BufferMetadataStream::Read(uint8_t *buf, ssize_t size)
{
    if (buf == nullptr) {
        IMAGE_LOGE("The buffer provided for reading is null. Please provide a valid buffer.");
        return -1;
    }
    ssize_t bytesToRead = std::min(size, static_cast<ssize_t>(buffer_.size() - static_cast<size_t>(currentOffset_)));
    std::copy(buffer_.begin() + currentOffset_, buffer_.begin() + currentOffset_ + bytesToRead, buf);
    currentOffset_ += bytesToRead;
    return bytesToRead;
}

int BufferMetadataStream::ReadByte()
{
    if (static_cast<size_t>(currentOffset_) >= buffer_.size()) {
        return -1;
    }

    return buffer_[currentOffset_++];
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
            currentOffset_ = buffer_.size() + offset;
            break;
        default:
            return -1;
    }

    // If the new current offset is greater than the size of the buffer, set the current offset to the size of the
    // buffer.
    if (static_cast<std::vector<uint8_t>::size_type>(currentOffset_) > buffer_.size()) {
        currentOffset_ = buffer_.size();
    }

    return currentOffset_;
}

long BufferMetadataStream::Tell()
{
    return currentOffset_;
}

bool BufferMetadataStream::IsEof()
{
    return static_cast<size_t>(currentOffset_) >= buffer_.size();
}

bool BufferMetadataStream::IsOpen()
{
    return true;
}

void BufferMetadataStream::Close()
{
    buffer_.clear();
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
    return buffer_.data();
}

bool BufferMetadataStream::CopyFrom(MetadataStream &src)
{
    // Clear the current buffer
    buffer_.clear();
    currentOffset_ = 0;

    // Pre-allocate memory based on the estimated size
    size_t estimatedSize = src.GetSize();

    // Adjust estimatedSize to be a multiple of 4096
    estimatedSize = ((estimatedSize + METADATA_STREAM_PAGE_SIZE - 1) / METADATA_STREAM_PAGE_SIZE)
                    * METADATA_STREAM_PAGE_SIZE;
    buffer_.reserve(estimatedSize);

    // Determine the size of the tempBuffer
    size_t tempBufferSize = std::min<size_t>(estimatedSize, METADATA_STREAM_COPY_FROM_BUFFER_SIZE);
    std::vector<uint8_t> tempBuffer(tempBufferSize, 0);

    // Read data from the source MetadataStream and write it to the current buffer
    src.Seek(0, SeekPos::BEGIN);
    Seek(0, SeekPos::BEGIN);
    while (!src.IsEof()) {
        size_t bytesRead = src.Read(tempBuffer.data(), tempBuffer.size());
        if (bytesRead > 0) {
            buffer_.insert(buffer_.end(), tempBuffer.begin(), tempBuffer.begin() + bytesRead);
        }
    }
    Seek(0, SeekPos::END);
    return true;
}

ssize_t BufferMetadataStream::GetSize()
{
    return buffer_.size();
}
} // namespace Media
} // namespace OHOS
