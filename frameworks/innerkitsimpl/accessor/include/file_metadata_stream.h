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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <vector>

#include "metadata_stream.h"

namespace OHOS {
namespace Media {
#if defined(FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_TESTS_PRIVATE)
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_PRIVATE_UNLESS_TESTED public
#else
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_PRIVATE_UNLESS_TESTED private
#endif

/**
 * This is a helper class for FileMetadataStream. It is used for testing whether exceptions are
 * properly handled during file read/write errors.
 */
class FileWrapper {
public:
    virtual ~FileWrapper() {}
    /* *
     * @brief Simulates the fwrite function.
     * @param src Pointer to the array of elements to be written.
     * @param size Size in bytes of each element to be written.
     * @param nmemb Number of elements, each one with a size of 'size' bytes.
     * @param file Pointer to a FILE object that specifies an output stream.
     * @return The total number of elements successfully written.
     */
    virtual ssize_t FWrite(const void *src, size_t size, ssize_t nmemb, FILE *file);

    /* *
     * @brief Simulates the fread function.
     * @param destv Pointer to a block of memory with a size of at least (size*nmemb) bytes.
     * @param size Size in bytes of each element to be read.
     * @param nmemb Number of elements, each one with a size of 'size' bytes.
     * @param file Pointer to a FILE object that specifies an input stream.
     * @return The total number of elements successfully read.
     */
    virtual ssize_t FRead(void *destv, size_t size, ssize_t nmemb, FILE *file);
};

/**
 * @class FileMetadataStream
 * @brief A class that represents a file-based image stream.
 * @note This class is not thread-safe. If you need to use the same FileMetadataStream instance from multiple threads,
 * you must ensure that all access to the instance is properly synchronized.
 */
class FileMetadataStream : public MetadataStream {
public:
    /* *
     * @brief Constructs a new FileMetadataStream object from a file descriptor.
     * @param fileDescriptor The file descriptor.
     */
    FileMetadataStream(int fileDescriptor);

    /* *
     * @brief Constructs a new FileMetadataStream object from a file path.
     * @param filePath The file path.
     */
    FileMetadataStream(const std::string &filePath);

    /* *
     * @brief Destructs the FileMetadataStream object.
     */
    virtual ~FileMetadataStream();

    /* *
     * @brief Writes data to the FileMetadataStream.
     * @param data The data to be written.
     * @param size The size of the data. On a 32-bit system, the maximum size
     * that can be written at once is 2GB. On a 64-bit system, the maximum size
     * depends on the type of ssize_t. If ssize_t is 32-bit, the maximum size
     * is 2GB. If ssize_t is 64-bit, the maximum size is 8ZB.
     * @return The number of bytes written. Returns -1 if an error occurred
     * during writing.
     */
    virtual ssize_t Write(byte *data, ssize_t size) override;

    /* *
     * @brief Reads data from the FileMetadataStream.
     * @param buf The buffer to store the data.
     * @param size The size of the data.
     * @return The number of bytes read. Returns -1 if a read error occurred
     * or the pointer was not initialized.
     */
    virtual ssize_t Read(byte *buf, ssize_t size) override;

    /* *
     * @brief Reads a byte from the FileMetadataStream.
     * @return The byte read.
     */
    virtual int ReadByte() override;

    /* *
     * @brief Seeks to a specific position in the FileMetadataStream.
     * @param offset The offset.
     * @param pos The starting position of the offset.
     * @return The new position in the stream. Returns -1 if an error occurred during seeking.
     */
    virtual long Seek(long offset, SeekPos pos) override;

    /* *
     * @brief Gets the current position in the FileMetadataStream.
     * @return The current position.
     */
    virtual long Tell() override;

    /* *
     * @brief Checks if the end of the FileMetadataStream has been reached.
     * @return true if the end has been reached, false otherwise.
     */
    virtual bool IsEof() override;

    /* *
     * @brief Checks if the FileMetadataStream is open.
     * @return true if it is open, false otherwise.
     */
    virtual bool IsOpen() override;

    /* *
     * @brief Opens the FileMetadataStream with a specific mode.
     * The Open operation will reset the read and write position of the file.
     * A file object can only be opened and closed once.
     * If the file fails to open from the file descriptor or path, it will
     * return false. If it fails to seek to the end of the file or restore
     * the file position, it will return false.
     * @param mode The mode to open the FileMetadataStream. It can be OpenMode::Read
     * or OpenMode::ReadWrite.
     * @return true if it opens successfully, false otherwise.
     */
    virtual bool Open(OpenMode mode = OpenMode::ReadWrite) override;

    /* *
     * @brief Flushes the FileMetadataStream.
     * The scenarios for using Flush are described in MetadataStream::Flush.
     * @return true if it flushes successfully, false otherwise.
     */
    virtual bool Flush() override;

    /* *
     * @brief Creates a memory map of the file.
     * @param isWriteable If true, the created memory map will be writable;
     * otherwise, it will be read-only. Writing to a read-only pointer will
     * result in a segmentation fault.
     * @return A pointer to the memory map if it is created successfully,
     * nullptr otherwise.
     */
    virtual byte *GetAddr(bool isWriteable = false) override;

    /* *
     * @brief Should call Open first. Transfers the content of the source
     * MetadataStream to the current FileMetadataStream.
     * Note the buffer size in CopyFrom is currently 4K. When reading from SSDs,
     * reading only 4K at a time may not fully utilize the IO transfer capabilities.
     * If performance issues are identified in later testing, this can be adjusted
     * to a multiple of 4K.
     * @param src The source MetadataStream.
     */
    bool CopyFrom(MetadataStream &src) override;

    /* *
     * @brief Gets the size of the FileMetadataStream.
     * @return The size of the FileMetadataStream.
     * @note If this function is called frequently, it is recommended to cache the size to improve performance.
     */
    ssize_t GetSize() override;

private:
    /* *
     * @brief Closes the FileMetadataStream.
     */
    virtual void Close() override;

    /* *
     * @brief Releases a memory map.
     * @param mmap The pointer to the memory map that needs to be released.
     * @return true if the memory map is released successfully, false otherwise.
     */
    bool ReleaseAddr();

    /* *
     * @brief Constructs a new FileMetadataStream object from a file path and a
     * file wrapper.
     * @param filePath The file path.
     * @param fileWrapper The file wrapper.
     */
    FileMetadataStream(const std::string &filePath, std::unique_ptr<FileWrapper> fileWrapper);

    /* *
     * @brief Opens the FileMetadataStream from a file descriptor.
     * @param modeStr The mode string.
     * @return true if it opens successfully, false otherwise.
     */
    bool OpenFromFD(const char *modeStr);

    /* *
     * @brief Opens the FileMetadataStream from a file path.
     * @param modeStr The mode string.
     * @return true if it opens successfully, false otherwise.
     */
    bool OpenFromPath(const char *modeStr);

    /* *
     * @brief Copies data from the source MetadataStream to the current file.
     * @param src The source MetadataStream.
     * @param totalBytesWritten The total number of bytes written to the current file.
     * This function reads data from the source MetadataStream and writes it to the current file.
     * It uses a temporary buffer of size min(IMAGE_STREAM_PAGE_SIZE, src.GetSize()).
     * The function continues to read and write data until it reaches the end of the source MetadataStream.
     * If a write operation fails, it handles the error and returns false.
     * If a read operation fails and it's not because of reaching the end of the source MetadataStream,
     * it returns false.
     * @return true if the data is copied successfully, false otherwise.
     */
    bool CopyDataFromSource(MetadataStream &src, ssize_t &totalBytesWritten);

    /* *
     * @brief Handles the error when writing data to the current file fails.
     * @param src The source MetadataStream.
     * @param src_cur The current position of the source MetadataStream.
     */
    void HandleWriteError(MetadataStream &src, ssize_t src_cur);

    /* *
     * @brief Truncates the current file to the specified size.
     * @param totalBytesWritten The new size of the file.
     * @param src The source MetadataStream.
     * @param src_cur The current position of the source MetadataStream.
     * @return true if the file is truncated successfully, false otherwise.
     */
    bool TruncateFile(size_t totalBytesWritten, MetadataStream &src, ssize_t src_cur);
    bool ReadFromSourceAndWriteToFile(MetadataStream &src, byte *tempBuffer, ssize_t buffer_size,
        ssize_t &totalBytesWritten);

    /* *
     * @brief Initializes the FileMetadataStream with a file path and a file descriptor.
     * @param filePath The path of the file to be opened. Default is an empty string.
     * @param fileDescriptor The file descriptor of the file to be opened. Default is -1.
     */
    void Initialize(const std::string &filePath = "", int fileDescriptor = -1);

    FILE *fp_;                                 // File descriptor
    int dupFD_;                                // Duplicated file descriptor
    std::string filePath_;                     // File path
    void *mappedMemory_;                       // Address of memory mapping
    std::unique_ptr<FileWrapper> fileWrapper_; // File wrapper class, used for testing

    enum {
        INIT_FROM_FD,
        INIT_FROM_PATH,
        INIT_FROM_UNKNOWN,
    } initPath_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_FILE_METADATA_STREAM_H
