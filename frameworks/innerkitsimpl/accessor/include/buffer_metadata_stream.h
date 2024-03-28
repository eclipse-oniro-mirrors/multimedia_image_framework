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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <vector>

#include "metadata_stream.h"

namespace OHOS {
namespace Media {
#if defined(FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_TESTS_PRIVATE)
    #define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_PRIVATE_UNLESS_TESTED public
#else
    #define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_PRIVATE_UNLESS_TESTED private
#endif

/**
 * @class BufferMetadataStream
 * @brief A class for handling image streams in memory.
 *
 * This class provides methods for reading from and seeking within an image
 * stream in memory. The maximum size of the stream is limited by
 * std::vector<uint8_t>::size_type, which is 4GB. Although MetadataStream can
 * address a maximum space of 'long', in memory mode, the maximum space is
 * limited by std::vector<uint8_t>::size_type.
 */
class BufferMetadataStream : public MetadataStream {
public:
    /* *
     * @brief Constructs a new BufferMetadataStream object.
     */
    BufferMetadataStream();

    /* *
     * @brief Destructs the BufferMetadataStream object.
     */
    virtual ~BufferMetadataStream();

    /* *
     * @brief Writes data to the BufferMetadataStream.
     * @param data The data to be written.
     * @param size The size of the data. On a 32-bit system, the maximum size
     * that can be written at once is 2GB or 4GB.
     * @return The number of bytes written. Returns -1 if an error occurred
     * during writing.
     */
    virtual ssize_t Write(uint8_t *data, ssize_t size) override;

    /* *
     * @brief Reads data from the BufferMetadataStream.
     * @param buf The buffer to store the data.
     * @param size The size of the data.
     * @return The number of bytes read. Returns -1 if the buffer pointer is null.
     */
    virtual ssize_t Read(uint8_t *buf, ssize_t size) override;

    /* *
     * @brief Reads a byte from the BufferMetadataStream.
     * @return The byte read.
     */
    virtual int ReadByte() override;

    /* *
     * @brief Seeks to a specific position in the image stream.
     * @param offset The offset to seek to. This can be positive or negative.
     * @param pos The position to seek from. This can be the beginning, current position, or end of the stream.
     * @return The new position in the stream. Returns -1 if an invalid seek position is provided.
     */
    virtual long Seek(long offset, SeekPos pos) override;

    /* *
     * @brief Gets the current position in the BufferMetadataStream.
     * @return The current position.
     */
    virtual long Tell() override;

    /* *
     * @brief Checks if the end of the BufferMetadataStream has been reached.
     * @return true if the end has been reached, false otherwise.
     */
    virtual bool IsEof() override;

    /* *
     * @brief Checks if the BufferMetadataStream is open.
     * @return true if it is open, false otherwise.
     */
    virtual bool IsOpen() override;

    /* *
     * For BufferMetadataStream, the Open function with a mode is not applicable,
     * as the data for BufferMetadataStream is already in memory and there are no
     * read-only scenarios.
     *
     * @param mode This parameter is ignored, as there are no read-only
     * scenarios for BufferMetadataStream.
     * @return Returns false, as this function is not applicable for
     * BufferMetadataStream.
     */
    virtual bool Open(OpenMode mode = OpenMode::ReadWrite) override;

    /* *
     * For BufferMetadataStream, the Flush function is not applicable,
     * as the data for BufferMetadataStream is already in memory and there are no
     * write operations that need to be flushed.
     *
     * @return Returns true, as this function is not applicable for
     * BufferMetadataStream, but it is assumed that the data is always "flushed" in
     * memory.
     */
    virtual bool Flush() override;

    /* *
     * Get the memory address of the BufferMetadataStream.
     * Since the data of BufferMetadataStream is stored in a std::vector<uint8_t>,
     * this function directly returns the pointer to the data using the
     * std::vector::data() function. Note that this function ignores the
     * isWriteable parameter, because the data of BufferMetadataStream is always
     * writable.
     *
     * @param isWriteable This parameter is ignored, the data of
     * BufferMetadataStream is always writable.
     * @return Returns a pointer to the data of BufferMetadataStream.
     */
    virtual byte *GetAddr(bool isWriteable = false) override;

    /* *
     * Transfer the content of the source MetadataStream to the current
     * BufferMetadataStream. This function first clears the current buffer and sets
     * the current offset to 0. Then, this function reads data from the source
     * MetadataStream and appends the read data to the current buffer. If an error
     * occurs during the reading process, this function will return immediately
     * and log the error information.
     *
     * @param src The source MetadataStream, this function will read data from this
     * MetadataStream.
     */
    virtual bool CopyFrom(MetadataStream &src) override;

    /* *
     * Get the size sof the BufferMetadataStream.
     *
     * @return Returns the size of the BufferMetadataStream.
     */
    virtual ssize_t GetSize() override;

FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_PRIVATE_UNLESS_TESTED:
    /* *
     * @brief Closes the BufferMetadataStream.
     */
    virtual void Close() override;

    /* *
     * @brief The memory buffer of the BufferMetadataStream.
     */
    std::vector<uint8_t> buffer_;

    /* *
     * @brief The current offset in the BufferMetadataStream.
     */
    long currentOffset_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_BUFFER_METADATA_STREAM_H
