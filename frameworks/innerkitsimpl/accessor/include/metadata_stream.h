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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_STREAM_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_STREAM_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <vector>

namespace OHOS {
namespace Media {
enum SeekPos {
    BEGIN,
    CURRENT,
    END
};

using byte = uint8_t;

enum class OpenMode {
    Read,     // Read mode
    ReadWrite // Read-write mode
};

/**
 * Considering that the size of exif fields often exceeds 4K and is less than 32K,
 * we set the increment of memory to 32K each time to minimize memory allocation.
 */
constexpr int METADATA_STREAM_PAGE_SIZE = 4096 * 8;
constexpr int METADATA_STREAM_ERROR_BUFFER_SIZE = 255;

/**
 * Considering that the circuitry of solid-state storage is of a low-speed multi-concurrent form,
 * we use a larger read/write buffer to activate the potential for concurrent read/write operations of the circuit,
 * thereby increasing I/O throughput.
 */
constexpr int METADATA_STREAM_COPY_FROM_BUFFER_SIZE = 4096 * 32;

/**
 * @class MetadataStream
 * @brief A class for handling image streams.
 *
 * This class provides methods for reading from and seeking within an image stream.
 * The maximum file size that can be handled depends on the system and compiler:
 * - On a 32-bit system, the maximum file size is 2GB.
 * - On a 64-bit system, the maximum file size depends on whether 'long' is compiled as 32-bit or 64-bit.
 * If 'long' is 32-bit, the maximum file size is 2GB.
 * If 'long' is 64-bit, the maximum file size is 8ZB (Zettabytes).
 */
class MetadataStream {
public:
    virtual ~MetadataStream() {}

    /* *
     * Open the image stream with a specific mode.
     * For FileMetadataStream, OpenMode::ReadWrite and OpenMode::Read have distinct behaviors.
     * For BufferMetadataStream, only OpenMode::ReadWrite is applicable. If OpenMode::Read is
     * passed, it will be ignored as there is no specific read-only mode implemented.
     * @param mode The mode to open the image stream.
     * @return true if it opens successfully, false otherwise.
     */
    virtual bool Open(OpenMode mode = OpenMode::ReadWrite) = 0;

    /* *
     * Check if the image stream is open.
     * For FileMetadataStream, this function is meaningful and checks if the file is open.
     * For BufferMetadataStream, this function always returns true.
     * @return true if it is open, false otherwise.
     */
    virtual bool IsOpen() = 0;

    /* *
     * Flush the image stream. For FileMetadataStream, this function is used to clear the buffer and
     * write the buffered data into the file. This operation ensures that all modifications are
     * written to the file, so other FileMetadataStream objects opening the same file can see these
     * modifications. For BufferMetadataStream, this function may not have a specific use as it might
     * only operate data in memory and does not involve any file operations. However, it could still
     * be used to trigger certain behaviors, such as notifying other objects that data has been
     * modified, or releasing resources that are no longer needed.
     * @return true if it flushes successfully, false otherwise
     */
    virtual bool Flush() = 0;

    /* *
     * @brief Writes data to the image stream.
     * @param data The data to be written.
     * @param size The size of the data. The maximum size that can be written
     * at once depends on the implementation. On 32-bit systems and above,
     * a safe value is 2GB.
     * @return The actual size of the data written. Returns -1 if an error
     * occurred during writing.
     */
    virtual ssize_t Write(byte *data, ssize_t size) = 0;

    /* *
     * Read data from the image stream
     * @param buf The buffer to store the data read
     * @param size The size of the data to be read
     * @return The actual size of the data read, or -1 if an error occurred
     */
    virtual ssize_t Read(byte *buf, ssize_t size) = 0;

    /* *
     * @brief Reads a byte from the image stream and moves the pointer to the next position.
     * @return The byte read from the stream as a uint8_t. Returns -1 if an error occurred.
     */
    virtual int ReadByte() = 0;

    /* *
     * Seek a specific position in the image stream
     * @param offset The offset
     * @param pos The starting position of the offset (from the head, current
     * position, or tail)
     * @return The new position. Returns -1 if an error occurred during seeking.
     */
    virtual long Seek(long offset, SeekPos pos) = 0;

    /* *
     * Get the current position in the image stream
     * @return The current position
     */
    virtual long Tell() = 0;

    /* *
     * Check if the end of the image stream has been reached
     * @return true if the end has been reached, false otherwise
     */
    virtual bool IsEof() = 0;

    /* *
     * Create a memory map
     * @param isWriteable If true, the created memory map will be writable;
     * otherwise, the created memory map will be read-only.
     * @return If the memory map is created successfully, return a pointer to
     * the memory map; otherwise, return nullptr.
     */
    virtual byte *GetAddr(bool isWriteable = false) = 0;

    /* *
     * Copy the entire content from the source MetadataStream to the current
     * MetadataStream. After the copy operation, the current position of both the source
     * MetadataStream and the current MetadataStream will be at their respective ends.
     * @param src The source MetadataStream, this function will read data from this
     * MetadataStream.
     * @return true if the copy is successful, false otherwise.
     */
    virtual bool CopyFrom(MetadataStream &src) = 0;

    /* *
     * Get the size of the MetadataStream
     * @return The size of the MetadataStream
     */
    virtual ssize_t GetSize() = 0;

private:
    /* *
     * Close the image stream
     */
    virtual void Close() = 0;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_STREAM_H
