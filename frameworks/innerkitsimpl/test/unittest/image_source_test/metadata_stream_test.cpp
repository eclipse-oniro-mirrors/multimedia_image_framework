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

#include "gtest/gtest.h"
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>

#include <csetjmp>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gmock/gmock-actions.h>
#include <gmock/gmock-cardinalities.h>
#include <gmock/gmock-spec-builders.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "metadata_stream.h"
#include "buffer_metadata_stream.h"
#include "file_metadata_stream.h"
#include "data_buf.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
const int SIZE_1024 = 1024;
const int SIZE_512 = 512;
const int SIZE_255 = 255;
const int SIZE_20 = 20;
const int SIZE_10 = 10;
const int TEST_DIR_PERMISSIONS = 0777;

class MemoryCheck {
public:
    void Start()
    {
        startVmSize = GetVmSize();
        startVmRSS = GetVmRSS();
        startFdCount = CountOpenFileDescriptors();
    }

    void End()
    {
        endVmSize = GetVmSize();
        endVmRSS = GetVmRSS();
        endFdCount = CountOpenFileDescriptors();
    }

    bool check = true;

    bool Compare() const
    {
        if (check) {
            if (startVmSize != endVmSize || startVmRSS != endVmRSS || startFdCount != endFdCount) {
                std::cout << "Difference in VmSize: " << endVmSize - startVmSize << std::endl;
                std::cout << "Difference in VmRSS: " << endVmRSS - startVmRSS << std::endl;
                std::cout << "Difference in File Descriptors: " << endFdCount - startFdCount << std::endl;
                return false;
            }
        }
        return true;
    }

private:
    long GetVmSize() const
    {
        return GetMemoryInfo("VmSize:");
    }

    long GetVmRSS() const
    {
        return GetMemoryInfo("VmRSS:");
    }

    int CountOpenFileDescriptors() const
    {
        DIR *dir;
        int fdCount = 0;
        std::string dirPath = "/proc/" + std::to_string(getpid()) + "/fd/";
        if ((dir = opendir(dirPath.c_str())) != nullptr) {
            while (readdir(dir) != nullptr) {
                fdCount++;
            }
            closedir(dir);
        } else {
            std::cerr << "Could not open " << dirPath << std::endl;
        }

        return fdCount;
    }

    long GetMemoryInfo(const std::string &name) const
    {
        std::string line;
        std::ifstream statusFile("/proc/self/status");

        while (std::getline(statusFile, line)) {
            if (line.find(name) != std::string::npos) {
                return std::stol(line.substr(name.length()));
            }
        }

        return 0;
    }

    long startVmSize = 0;
    long startVmRSS = 0;
    long endVmSize = 0;
    long endVmRSS = 0;
    int startFdCount = 0;
    int endFdCount = 0;
};

int CountOpenFileDescriptors()
{
    DIR *dir;
    int fdCount = 0;
    std::string dirPath = "/proc/" + std::to_string(getpid()) + "/fd/";
    if ((dir = opendir(dirPath.c_str())) != nullptr) {
        while (readdir(dir) != nullptr) {
            fdCount++;
        }
        closedir(dir);
    } else {
        std::cerr << "Could not open " << dirPath << std::endl;
    }

    return fdCount;
}


void RemoveFile(const std::string &filePath)
{
    int result = remove(filePath.c_str());
    if (result != 0) {
        char errstr[METADATA_STREAM_ERROR_BUFFER_SIZE];
        strerror_r(errno, errstr, sizeof(errstr));
    }
}

std::string CreateIfNotExit(const std::string &filePath)
{
    struct stat buffer;
    if (stat(filePath.c_str(), &buffer) != 0) { // 文件不存在
        std::ofstream file(filePath);
        if (!file) {
            std::cerr << "Failed to create file: " << filePath << std::endl;
        } else {
            file.close();
        }
    }
    return filePath;
}

class MetadataStreamTest : public testing::Test {
public:
    MetadataStreamTest() {}
    ~MetadataStreamTest() override {}
    std::string filePath = "/data/local/tmp/image/testfile.txt";
    std::string filePathSource = "/data/local/tmp/image/test_exif_test.jpg";
    std::string filePathDest = "/data/local/tmp/image/testfile_dest.png";
    std::string backupFilePathSource = "/data/local/tmp/image/test_exif.jpg";
    const ssize_t testSize[4] = {
        1,
        METADATA_STREAM_PAGE_SIZE + 1,
        METADATA_STREAM_PAGE_SIZE,
        METADATA_STREAM_PAGE_SIZE - 1
    };
    MemoryCheck memoryCheck;

    void SetUp() override
    {
        // Create the directory
        std::string dirPath = "/data/local/tmp/image";
        if (access(dirPath.c_str(), F_OK) != 0) {
            int ret = mkdir(dirPath.c_str(), TEST_DIR_PERMISSIONS);
            if (ret != 0) {
                char buf[METADATA_STREAM_ERROR_BUFFER_SIZE];
                strerror_r(errno, buf, sizeof(buf));
                GTEST_LOG_(ERROR) << "Failed to create directory: " << dirPath << ", error: " << buf;
            }
        }

        // Backup the files
        std::filesystem::copy(backupFilePathSource, filePathSource, std::filesystem::copy_options::overwrite_existing);
        memoryCheck.check = true;
        memoryCheck.Start();
    }

    const static std::string tmpDirectory;
    static bool alreadyExist;

    void TearDown() override
    {
        memoryCheck.End();
        memoryCheck.check = false;
        if (!memoryCheck.Compare()) {
            GTEST_LOG_(INFO) << "Memory leak detected";
        }
        RemoveFile(filePath.c_str());
        RemoveFile(filePathDest.c_str());
    }

    static void SetUpTestCase()
    {
        // Create the directory
        if (access(tmpDirectory.c_str(), F_OK) != 0) {
            int ret = mkdir(tmpDirectory.c_str(), TEST_DIR_PERMISSIONS);
            if (ret != 0) {
                char buf[METADATA_STREAM_ERROR_BUFFER_SIZE];
                strerror_r(errno, buf, sizeof(buf));
                GTEST_LOG_(ERROR) << "Failed to create directory: " << tmpDirectory << ", error: " << buf;
            }
            alreadyExist = false;
        } else {
            alreadyExist = true;
        }
    }
    static void TearDownTestCase()
    {
        if (!alreadyExist) {
            rmdir(tmpDirectory.c_str());
        }
    }
};

bool MetadataStreamTest::alreadyExist = false;
const std::string MetadataStreamTest::tmpDirectory = "/data/local/tmp/image";

class MockFileWrapper : public FileWrapper {
public:
    MOCK_METHOD(ssize_t, FWrite, (const void *src, size_t size, ssize_t nmemb, FILE *file), (override));
    MOCK_METHOD(ssize_t, FRead, (void *destv, size_t size, ssize_t nmemb, FILE *file), (override));

    MockFileWrapper()
    {
        // Set the default behavior of write to call the system's write function
        ON_CALL(*this, FWrite(_, _, _, _))
            .WillByDefault(Invoke([](const void *src, size_t size, ssize_t nmemb, FILE *file) {
                size_t result = ::fwrite(src, size, nmemb, file);
                if (result != static_cast<size_t>(nmemb)) {
                    char errstr[METADATA_STREAM_ERROR_BUFFER_SIZE];
                    strerror_r(errno, errstr, sizeof(errstr));
                    std::cerr << "Failed to write to the file: " << errstr << std::endl;
                }
                return result;
            }));
        // Set the default behavior of read to call the system's read function
        ON_CALL(*this, FRead(_, _, _, _)).WillByDefault(Invoke([](void *destv, size_t size, ssize_t nmemb, FILE *file) {
            size_t result = ::fread(destv, size, nmemb, file);
            if (result != static_cast<size_t>(nmemb)) {
                char errstr[METADATA_STREAM_ERROR_BUFFER_SIZE];
                strerror_r(errno, errstr, sizeof(errstr));
                std::cerr << "Failed to read from the file: " << errstr << std::endl;
            }
            return result;
        }));
    }
};

/**
 * @tc.name: FileMetadataStream_Write001
 * @tc.desc: Test the Write function of FileMetadataStream, whether it can write
 * normally and verify the written data
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write001, TestSize.Level3)
{
    // Create a FileMetadataStream object
    FileMetadataStream stream(CreateIfNotExit(filePath));

    // Open the file
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));

    // Create some data to write
    byte data[SIZE_10] = {0};

    ASSERT_EQ(stream.Tell(), 0);

    // Write the data to the file
    size_t bytesWritten = stream.Write(data, sizeof(data));

    // Check that the correct number of bytes were written
    ASSERT_EQ(bytesWritten, sizeof(data));

    // Flush the file
    stream.Flush();

    // Open the file again
    int fileDescriptor = open(filePath.c_str(), O_RDONLY);
    ASSERT_NE(fileDescriptor, -1);

    // Read the data from the file
    byte buffer[SIZE_10];
    ssize_t bytesRead = read(fileDescriptor, buffer, sizeof(buffer));

    // Check that the correct number of bytes were read
    ASSERT_EQ(bytesRead, sizeof(data));

    // Check that the data read is the same as the data written
    ASSERT_EQ(memcmp(data, buffer, sizeof(data)), 0);

    // Close the file
    close(fileDescriptor);
}

/**
 * @tc.name: FileMetadataStream_Write002
 * @tc.desc: Test the Write function of FileMetadataStream when the file is not
 * open
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write002, TestSize.Level3)
{
    FileMetadataStream stream(filePath);
    byte data[SIZE_10] = {0};
    ASSERT_EQ(stream.Write(data, sizeof(data)), -1);
}

/**
 * @tc.name: FileMetadataStream_Write003
 * @tc.desc: Test the Write function of FileMetadataStream when the amount of data
 * written exceeds the remaining space in the file system
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write003, TestSize.Level3)
{
    // This test case requires an MetadataStream object that can simulate a read
    // failure, so mock technology may be needed in actual testing
    auto mockFileWrapper = std::make_unique<MockFileWrapper>();
    // Set the behavior of the write function to always return -1, simulating a
    // write failure
    EXPECT_CALL(*mockFileWrapper.get(), FWrite(_, _, _, _)).WillOnce(Return(-1));

    FileMetadataStream stream(CreateIfNotExit(filePath), std::move(mockFileWrapper));

    // Test the Write function
    byte buffer[SIZE_1024];
    stream.Open(OpenMode::ReadWrite);
    EXPECT_EQ(stream.Write(buffer, sizeof(buffer)), -1);
}

/**
 * @tc.name: FileMetadataStream_Write004
 * @tc.desc: Test the Write function of FileMetadataStream when all data from the
 * source image stream has been read
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write004, TestSize.Level3)
{
    FileMetadataStream stream1(filePathSource);
    FileMetadataStream stream2(CreateIfNotExit(filePathDest));
    ASSERT_TRUE(stream1.Open(OpenMode::ReadWrite));
    ASSERT_TRUE(stream2.Open(OpenMode::ReadWrite));
    // Read all data from stream1
    byte buffer[METADATA_STREAM_PAGE_SIZE];
    while (stream1.Read(buffer, sizeof(buffer)) > 0) {
    }
    // At this point, all data from stream1 has been read, so the write should
    // return 0
    byte *buf = new byte[stream1.GetSize()];
    stream1.Read(buf, stream1.GetSize());
    ASSERT_EQ(stream2.Write(buf, stream1.GetSize()), stream1.GetSize());
    stream1.Flush();
    stream2.Flush();
    delete[] buf;
}

/**
 * @tc.name: FileMetadataStream_Write005
 * @tc.desc: Test the Write function of FileMetadataStream when reading data from
 * the source image stream fails
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write005, TestSize.Level3)
{
    // This test case requires an MetadataStream object that can simulate a read
    // failure, so mock technology may be needed in actual testing
    auto mockSourceFileWrapper = std::make_unique<MockFileWrapper>();
    auto mockDestFileWrapper = std::make_unique<MockFileWrapper>();

    // Set the behavior of the write function to always return -1, simulating a
    // write failure
    EXPECT_CALL(*mockDestFileWrapper.get(), FWrite(_, _, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockSourceFileWrapper.get(), FRead(_, _, _, _)).WillOnce(Return(-1));

    FileMetadataStream sourceStream(filePathSource, std::move(mockSourceFileWrapper));
    FileMetadataStream destStream(filePath, std::move(mockDestFileWrapper));

    // Test the Write function
    sourceStream.Open();
    destStream.Open();
    byte *buf = new byte[sourceStream.GetSize()];
    EXPECT_EQ(sourceStream.Read(buf, sourceStream.GetSize()), -1);
    delete[] buf;
}

/**
 * @tc.name: FileMetadataStream_Write006
 * @tc.desc: Test the Write function of FileMetadataStream when the amount of data
 * written exceeds the remaining space in the file system
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write006, TestSize.Level3)
{
    // This test case requires a nearly full file system, so it may be difficult
    // to implement in actual testing
    auto mockFileWrapper = std::make_unique<MockFileWrapper>();
    FileMetadataStream stream(filePath, std::move(mockFileWrapper));
}

/**
 * @tc.name: FileMetadataStream_Write001
 * @tc.desc: Test the Write function of FileMetadataStream, whether it can write
 * normally and verify the written data
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Write007, TestSize.Level3)
{
    // Create a FileMetadataStream object
    FileMetadataStream stream(CreateIfNotExit(filePath));

    // Open the file
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));

    // Create some data to write
    std::string data = "1Hello, world!";

    ASSERT_EQ(stream.Seek(0, SeekPos::BEGIN), 0);
    ASSERT_EQ(stream.Tell(), 0);
    // Write the data to the file
    ASSERT_EQ(stream.Write((byte *)data.c_str(), data.size()), data.size());
    ASSERT_EQ(stream.Tell(), data.size());
    // Flush the file
    stream.Flush();

    // Open the file again
    int fileDescriptor = open(filePath.c_str(), O_RDONLY);
    ASSERT_NE(fileDescriptor, -1);

    // Read the data from the file
    byte buffer[SIZE_20];
    read(fileDescriptor, buffer, sizeof(buffer));

    // Check that the data read is the same as the data written
    ASSERT_EQ(memcmp(data.c_str(), buffer, data.size()), 0);

    // Close the file
    close(fileDescriptor);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_Write008, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePath);
        FileMetadataStream stream(CreateIfNotExit(filePath));
        ASSERT_TRUE(stream.Open());
        byte *buf = new byte[size](); // Dynamically allocate the buffer with the current test size
        ASSERT_EQ(stream.Write(buf, size), size);
        ASSERT_EQ(stream.Flush(), true);
        ASSERT_EQ(stream.GetSize(), size);

        // Open the file in binary mode and move the file pointer to the end to get the file size
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        ASSERT_TRUE(file.is_open());

        // Get the file size
        std::streamsize fileSize = file.tellg();
        file.close();

        // Compare the file size with the current test size
        ASSERT_EQ(fileSize, size);

        delete[] buf; // Don't forget to delete the dynamically allocated buffer
    }
}

/**
 * @tc.name: FileMetadataStream_Open001
 * @tc.desc: Test the Open function of FileMetadataStream when the file path does
 * not exist
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Open001, TestSize.Level3)
{
    // Test the case where the file path does not exist
    std::string nonExistFilePath = "/data/local/tmp/image/non_exist_file.txt";
    RemoveFile(nonExistFilePath.c_str());
    FileMetadataStream stream1(CreateIfNotExit(nonExistFilePath));
    ASSERT_TRUE(stream1.Open());
    std::string sourceData = "Hello, world!";
    stream1.Write((byte *)sourceData.c_str(), sourceData.size());
    // Read data from stream1
    byte buffer[SIZE_255];
    stream1.Seek(0, SeekPos::BEGIN);
    ssize_t bytesRead = stream1.Read(buffer, sourceData.size());
    ASSERT_EQ(bytesRead, sourceData.size());
    buffer[bytesRead] = '\0'; // Add string termination character
    // Check if the read data is the same as the written data
    ASSERT_STREQ((char *)buffer, sourceData.c_str());
    ASSERT_TRUE(stream1.Flush());
    RemoveFile(nonExistFilePath.c_str());
}

/**
 * @tc.name: FileMetadataStream_Open002
 * @tc.desc: Test the Open function of FileMetadataStream when the file path exists
 * but is not writable
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Open002, TestSize.Level3)
{
    // Get the username of the current user
    uid_t uid = getuid();
    struct passwd *passwordEntry = getpwuid(uid);
    if (passwordEntry == nullptr) {
        perror("getpwuid");
        return;
    }
    std::string username(passwordEntry->pw_name);

    // Test the case where the file path exists but is not writable
    std::string nonWritableFilePath = "/data/local/tmp/image/non_writable_file.txt";
    close(open(nonWritableFilePath.c_str(), O_CREAT, S_IRUSR));
    FileMetadataStream stream2(nonWritableFilePath);
    if (username == "root") {
        // If the current user is root, then it can be opened successfully
        ASSERT_TRUE(stream2.Open());
    } else {
        // If the current user is not root, then it cannot be opened
        ASSERT_FALSE(stream2.Open());
    }
    RemoveFile(nonWritableFilePath.c_str());
}

/**
 * @tc.name: FileMetadataStream_Open003
 * @tc.desc: Test the Open function of FileMetadataStream when the file is already
 * open
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Open003, TestSize.Level3)
{
    // Test the case where the file is already open
    FileMetadataStream stream3(CreateIfNotExit(filePath));
    ASSERT_TRUE(stream3.Open());
    ASSERT_TRUE(stream3.Open());
    ASSERT_TRUE(stream3.Flush());
}

/**
 * @tc.name: FileMetadataStream_Open004
 * @tc.desc: Test the Open function of FileMetadataStream when the file does not
 * exist
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Open004, TestSize.Level3)
{
    // Test the case where the file does not exist
    const char *nonExistentFilePath = "/path/to/nonexistent/file";
    FileMetadataStream stream(nonExistentFilePath);
    ASSERT_FALSE(stream.Open(OpenMode::Read));
}

/**
 * @tc.name: FileMetadataStream_Open005
 * @tc.desc: Test the Open twice
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Open005, TestSize.Level3)
{
    FileMetadataStream stream(filePathSource);
    ASSERT_TRUE(stream.Open(OpenMode::Read));
    ASSERT_TRUE(stream.Open(OpenMode::Read));
}

/**
 * @tc.name: FileMetadataStream_Read001
 * @tc.desc: Test the Read function of FileMetadataStream, reading 512 bytes
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Read001, TestSize.Level3)
{
    FileMetadataStream stream(filePathSource);
    byte buffer[SIZE_1024];
    stream.Open(OpenMode::ReadWrite);
    // Simulate reading 512 bytes
    ssize_t bytesRead = stream.Read(buffer, SIZE_512);
    EXPECT_EQ(SIZE_512, bytesRead);
}

/**
 * @tc.name: FileMetadataStream_Read002
 * @tc.desc: Test the Read function of FileMetadataStream, trying to read from a
 * file that has not been opened
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Read002, TestSize.Level3)
{
    FileMetadataStream stream(filePathSource);
    byte buffer[SIZE_1024];
    // Flush the stream to simulate an unopened file
    ASSERT_FALSE(stream.Flush());
    ssize_t bytesRead = stream.Read(buffer, SIZE_512);
    EXPECT_EQ(-1, bytesRead);
}

// Define a global jmp_buf variable
static sigjmp_buf g_jmpBuf;

// Define a signal handler function
static void HandleSigsegv(int sig)
{
    siglongjmp(g_jmpBuf, 1);
}

/**
 * @tc.name: FileMetadataStream_MMap001
 * @tc.desc: Test the MMap function of FileMetadataStream, trying to write to a
 * memory-mapped file that is not writable
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_MMap001, TestSize.Level3)
{
    memoryCheck.check = false; // This test is expected to crash, so memory leak
                               // check is not needed
    // Assume there is an appropriate way to create or obtain the resources
    // needed for the test YourResource test_resource; Test the behavior of the
    // MMap function when isWriteable is false
    FileMetadataStream stream(filePathSource);
    byte *result = stream.GetAddr(false);
    // Assume that checking whether result is not nullptr, or there is another
    // appropriate verification method
    ASSERT_EQ(result, nullptr);
    stream.Open(OpenMode::ReadWrite);
    result = stream.GetAddr(false);
    ASSERT_NE(result, nullptr);

    // Set the signal handler function
    signal(SIGSEGV, HandleSigsegv);

    // Try to write data
    if (sigsetjmp(g_jmpBuf, 1) == 0) {
        result[0] = 0;
        // If no segmentation fault is triggered, then this is an error
        FAIL() << "Expected a segmentation fault";
    }
}

/**
 * @tc.name: FileMetadataStream_MMap002
 * @tc.desc: Test the MMap function of FileMetadataStream, trying to write to a
 * memory-mapped file that is writable
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_MMap002, TestSize.Level3)
{
    // Test the behavior of the MMap function when isWriteable is true
    FileMetadataStream stream(filePathSource);
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
    byte *result = stream.GetAddr(true);
    ASSERT_NE(result, nullptr);
    // Try to write data
    result[0] = 123;

    // Read the data and check if it is the same as the written data
    ASSERT_EQ(result[0], 123);
}

/**
 * @tc.name: FileMetadataStream_MMap003
 * @tc.desc: Test whether the MMap function of FileMetadataStream can actually
 * modify the content of the file
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_MMap003, TestSize.Level3)
{
    // Test whether MMap can actually modify the content of the file
    FileMetadataStream stream(filePathSource);
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
    byte *result = stream.GetAddr(true);
    ASSERT_NE(result, nullptr);

    // Try to write data
    result[0] = 123;

    stream.Seek(0, SeekPos::BEGIN);
    byte buffer[1];
    ASSERT_EQ(stream.Read(buffer, 1), 1);
    ASSERT_EQ(buffer[0], 123);

    // Flush stream
    ASSERT_TRUE(stream.Flush());
    FileMetadataStream checkStream(filePathSource);
    checkStream.Open(OpenMode::ReadWrite);
    byte checkBuffer[1];
    ASSERT_EQ(checkStream.Read(checkBuffer, 1), 1);

    // Check if the data in the file is the same as the data written
    ASSERT_EQ(checkBuffer[0], 123);
}

/**
 * @tc.name: FileMetadataStream_CopyFrom001
 * @tc.desc: Test the CopyFrom function of FileMetadataStream, copying data from
 * one stream to another
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom001, TestSize.Level3)
{
    FileMetadataStream src(filePathSource);
    FileMetadataStream dest(CreateIfNotExit(filePathDest));

    src.Open();
    // Write some known data to src
    std::string data = "Hello, world!";
    ASSERT_EQ(src.Tell(), 0);
    ASSERT_GE(src.Write((byte *)data.c_str(), data.size()), 0);
    ASSERT_TRUE(src.Flush());
    // Call the Transfer function to transfer data from src to dest
    dest.Open();
    ASSERT_TRUE(dest.CopyFrom(src));
    // Read data from dest and verify that it is the same as the data written to
    // src
    byte buffer[SIZE_255] = {0};

    ASSERT_EQ(dest.Seek(0, SeekPos::BEGIN), 0);
    ASSERT_EQ(dest.Read(buffer, data.size()), data.size());
    ASSERT_EQ(std::string(buffer, buffer + data.size()), data);

    // Verify that src is empty
    ASSERT_EQ(dest.GetSize(), src.GetSize());
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom002, TestSize.Level3)
{
    BufferMetadataStream src;
    FileMetadataStream dest(CreateIfNotExit(filePathDest));
    ASSERT_TRUE(src.Open());
    ASSERT_EQ(dest.Open(), true);
    src.Write((byte *)"Hello, world!", 13);
    char bufSrc[14] = {0};
    src.Seek(0, SeekPos::BEGIN);
    src.Read((byte *)bufSrc, 13);
    ASSERT_STREQ(bufSrc, "Hello, world!");
    ASSERT_TRUE(dest.CopyFrom(src));
    dest.Seek(0, SeekPos::BEGIN);
    char buf[14] = {0};
    dest.Read((byte *)buf, 13);
    ASSERT_STREQ(buf, "Hello, world!");
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), 13), 0);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom003, TestSize.Level3)
{
    BufferMetadataStream src;
    FileMetadataStream dest(CreateIfNotExit(filePathDest));
    src.Open();
    dest.Open();
    char buff[METADATA_STREAM_PAGE_SIZE + 1] = {0};
    src.Write((byte *)buff, sizeof(buff));
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), 4097), 0);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom004, TestSize.Level3)
{
    BufferMetadataStream src;
    FileMetadataStream dest(CreateIfNotExit(filePathDest));
    src.Open();
    dest.Open();
    char buff[METADATA_STREAM_PAGE_SIZE - 1] = {0};
    src.Write((byte *)buff, sizeof(buff));
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom005, TestSize.Level3)
{
    RemoveFile(filePath.c_str());
    FileMetadataStream src(CreateIfNotExit(filePathDest));
    BufferMetadataStream dest;
    src.Open();
    dest.Open();
    char buff[METADATA_STREAM_PAGE_SIZE - 1] = {0};
    ASSERT_EQ(src.Write((byte *)buff, sizeof(buff)), sizeof(buff));
    ASSERT_TRUE(src.Flush());
    ASSERT_EQ(src.Tell(), sizeof(buff));
    ASSERT_EQ(src.GetSize(), sizeof(buff));
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom006, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePathDest.c_str());
        FileMetadataStream src(CreateIfNotExit(filePathDest));
        BufferMetadataStream dest;
        src.Open();
        dest.Open();
        byte *buf = new byte[size]();
        ASSERT_EQ(src.Write(buf, size), size);
        ASSERT_TRUE(src.Flush());
        ASSERT_EQ(src.Tell(), size);
        ASSERT_EQ(src.GetSize(), size);
        ASSERT_TRUE(dest.CopyFrom(src));
        ASSERT_EQ(src.GetSize(), dest.GetSize());
        ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
        delete[] buf;
    }
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom007, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePath.c_str());
        FileMetadataStream dest(CreateIfNotExit(filePathDest));
        BufferMetadataStream src;
        src.Open();
        dest.Open();
        byte *buf = new byte[size]();
        ASSERT_EQ(src.Write(buf, size), size);
        ASSERT_TRUE(src.Flush());
        ASSERT_EQ(src.Tell(), size);
        ASSERT_EQ(src.GetSize(), size);
        ASSERT_TRUE(dest.CopyFrom(src));
        ASSERT_EQ(src.GetSize(), dest.GetSize());
        ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
        delete[] buf;
    }
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom008, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePathDest.c_str());
        RemoveFile(filePathSource.c_str());
        FileMetadataStream src(CreateIfNotExit(filePathSource));
        FileMetadataStream dest(CreateIfNotExit(filePathDest));
        src.Open();
        dest.Open();
        byte *buf = new byte[size]();
        ASSERT_EQ(src.Write(buf, size), size);
        ASSERT_TRUE(src.Flush());
        ASSERT_EQ(src.Tell(), size);
        ASSERT_EQ(src.GetSize(), size);
        ASSERT_TRUE(dest.CopyFrom(src));
        ASSERT_EQ(src.GetSize(), dest.GetSize());
        ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
        delete[] buf;
    }
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom009, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePath.c_str());
        BufferMetadataStream src;
        BufferMetadataStream dest;
        src.Open();
        dest.Open();
        byte *buf = new byte[size]();
        ASSERT_EQ(src.Write(buf, size), size);
        ASSERT_TRUE(src.Flush());
        ASSERT_EQ(src.Tell(), size);
        ASSERT_EQ(src.GetSize(), size);
        ASSERT_TRUE(dest.CopyFrom(src));
        ASSERT_EQ(src.GetSize(), dest.GetSize());
        ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
        delete[] buf;
    }
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CopyFrom010, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        RemoveFile(filePathDest.c_str());
        std::filesystem::copy(backupFilePathSource, filePathSource, std::filesystem::copy_options::overwrite_existing);
        FileMetadataStream src(CreateIfNotExit(filePathDest));
        FileMetadataStream dest(CreateIfNotExit(filePathSource));
        src.Open();
        dest.Open();
        byte *buf = new byte[size]();
        ASSERT_EQ(src.Write(buf, size), size);
        ASSERT_TRUE(src.Flush());
        ASSERT_EQ(src.Tell(), size);
        ASSERT_EQ(src.GetSize(), size);
        ASSERT_TRUE(dest.CopyFrom(src));
        ASSERT_EQ(src.GetSize(), dest.GetSize());
        ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
        delete[] buf;
    }
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_IsEof001, TestSize.Level3)
{
    FileMetadataStream src(filePathSource);
    src.Open();
    byte buffer[1];
    ASSERT_EQ(src.Seek(0, SeekPos::BEGIN), 0);
    src.Read(buffer, sizeof(buffer));
    ASSERT_FALSE(src.IsEof());
    ASSERT_EQ(src.Seek(0, SeekPos::END), src.GetSize());
    src.Read(buffer, sizeof(buffer));
    ASSERT_TRUE(src.IsEof());
}

/**
 * @tc.name: FileMetadataStream_ReadByte001
 * @tc.desc: Test the ReadByte function of FileMetadataStream, comparing its output
 * with the Read function
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_ReadByte001, TestSize.Level3)
{
    FileMetadataStream stream(filePathSource);
    stream.Open(OpenMode::ReadWrite);

    // Read 10 bytes using Read function
    byte buffer[SIZE_10];
    stream.Read(buffer, SIZE_10);

    // Reset the file offset
    stream.Seek(0, SeekPos::BEGIN);

    // Read 10 bytes using ReadByte function
    byte byteBuffer[SIZE_10];
    for (int i = 0; i < SIZE_10; i++) {
        byteBuffer[i] = stream.ReadByte();
    }

    // Compare the results
    for (int i = 0; i < SIZE_10; i++) {
        EXPECT_EQ(buffer[i], byteBuffer[i]);
    }
}

/**
 * @tc.name: FileMetadataStream_ReadByte002
 * @tc.desc: Test the ReadByte function of FileMetadataStream, trying to read
 * beyond the end of the file
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_ReadByte002, TestSize.Level3)
{
    FileMetadataStream stream(filePathSource);
    stream.Open(OpenMode::ReadWrite);

    // Set the file offset to the end of the file
    EXPECT_EQ(stream.Seek(0, SeekPos::END), stream.GetSize());

    // Try to read one more byte
    int result = stream.ReadByte();

    // Check if the result is -1
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: FileMetadataStream_CONSTRUCTOR001
 * @tc.desc: Test the constructor of FileMetadataStream, checking if it can
 * correctly initialize a stream from an existing file pointer
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_CONSTRUCTOR001, TestSize.Level3)
{
    FileMetadataStream stream(CreateIfNotExit(filePath));
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
    std::string sourceData = "Hello, world!";
    ASSERT_EQ(stream.Seek(5, SeekPos::BEGIN), 5);
    ASSERT_EQ(stream.Write((byte *)sourceData.c_str(), sourceData.size()), sourceData.size());

    FileMetadataStream cloneStream(fileno(stream.fp_));
    ASSERT_TRUE(stream.Flush());
    ASSERT_TRUE(cloneStream.Open(OpenMode::ReadWrite));
    // Read the data from cloneStream
    byte buffer[SIZE_255];
    cloneStream.Seek(5, SeekPos::BEGIN);
    ssize_t bytesRead = cloneStream.Read(buffer, sourceData.size());
    ASSERT_EQ(bytesRead, sourceData.size());
    buffer[bytesRead] = '\0'; // Add string termination character

    // Check if the read data is the same as the data in the source file
    ASSERT_STREQ((char *)buffer, sourceData.c_str());

    // Write some new data to cloneStream
    std::string newData = "New data";
    cloneStream.Write((byte *)newData.c_str(), newData.size());

    // Read the data from cloneStream again
    cloneStream.Seek(0, SeekPos::BEGIN);
    bytesRead = cloneStream.Read(buffer, sizeof(buffer) - 1);
    buffer[bytesRead] = '\0'; // Add string termination character

    // Check if the read data contains the new data
    ASSERT_STRNE((char *)buffer, newData.c_str());
}

/**
 * @tc.name: FileMetadataStream_CONSTRUCTOR002
 * @tc.desc: Test the constructor of FileMetadataStream, checking if it can
 * correctly initialize a stream from an existing file descriptor
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_CONSTRUCTOR002, TestSize.Level3)
{
    // Create and open a temporary file
    std::string tempFile = tmpDirectory + "/testfile";
    int fileDescription = open(tempFile.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fileDescription, -1);

    // Use the file descriptor to create a new FileMetadataStream object
    FileMetadataStream stream(fileDescription);
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
    ASSERT_NE(stream.dupFD_, -1);
    // Check the state of the FileMetadataStream object
    ASSERT_TRUE(stream.fp_ != nullptr);
    ASSERT_EQ(stream.mappedMemory_, nullptr);
    ASSERT_EQ(stream.Tell(), 0);

    // Write data
    byte writeData[SIZE_10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    ssize_t bytesWritten = stream.Write(writeData, sizeof(writeData));
    ASSERT_EQ(bytesWritten, sizeof(writeData));

    // Reset the file pointer to the beginning of the file
    stream.Seek(0, SeekPos::BEGIN);

    // Read data
    byte readData[SIZE_10] = {0};
    ssize_t bytesRead = stream.Read(readData, sizeof(readData));
    ASSERT_EQ(bytesRead, sizeof(readData));

    // Check if the read data is the same as the written data
    for (size_t i = 0; i < sizeof(writeData); ++i) {
        ASSERT_EQ(writeData[i], readData[i]);
    }

    // Close the file
    close(fileDescription);
    RemoveFile(tempFile.c_str());
}

/**
 * @tc.name: FileMetadataStream_CONSTRUCTOR003
 * @tc.desc: Test the constructor of FileMetadataStream, checking if it can
 * correctly initialize a stream from an existing file descriptor and handle
 * file operations
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_CONSTRUCTOR003, TestSize.Level3)
{
    int fdCount = CountOpenFileDescriptors();
    std::string tempFile = tmpDirectory + "/testfile";
    int fileDescriptor = open(tempFile.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_EQ(fdCount + 1, CountOpenFileDescriptors());
    int dupFD = dup(fileDescriptor);
    ASSERT_EQ(fdCount + 2, CountOpenFileDescriptors());
    ASSERT_NE(fileDescriptor, -1);
    FILE *fileStream = fdopen(dupFD, "r+"); // Change "rb" to "wb" for writing in binary mode
    ASSERT_EQ(fdCount + 2, CountOpenFileDescriptors());
    ;
    ASSERT_NE(fileStream, nullptr);
    std::string text = "Hello, world!";
    ssize_t result = fwrite(text.c_str(), sizeof(char), text.size(),
        fileStream); // Use sizeof(char) as the second argument
    ASSERT_EQ(ferror(fileStream), 0);
    ASSERT_EQ(result, text.size());

    // Reset the file pointer to the beginning of the file
    rewind(fileStream);

    ASSERT_EQ(fdCount + 2, CountOpenFileDescriptors());
    fileno(fileStream);
    ASSERT_EQ(fdCount + 2, CountOpenFileDescriptors());

    // Read and verify the data
    char buffer[SIZE_255];
    result = fread(buffer, sizeof(char), text.size(), fileStream);
    ASSERT_EQ(result, text.size());
    buffer[result] = '\0'; // Add string termination character
    ASSERT_STREQ(buffer, text.c_str());

    fclose(fileStream);
    ASSERT_EQ(fdCount + 1, CountOpenFileDescriptors());
    close(fileDescriptor);
    ASSERT_EQ(fdCount, CountOpenFileDescriptors());
}

/**
 * @tc.name: FileMetadataStream_CONSTRUCTOR004
 * @tc.desc: Test the constructor of FileMetadataStream, checking if it can
 * correctly initialize a stream from an existing file descriptor and handle
 * file operations using the stream's file pointer
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_CONSTRUCTOR004, TestSize.Level3)
{
    std::string tempFile = tmpDirectory + "/testfile";
    int fileDescriptor = open(tempFile.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    FileMetadataStream stream(fileDescriptor);
    int dupFD = stream.dupFD_;
    ASSERT_NE(fileDescriptor, -1);
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
    FILE *fileStream = stream.fp_; // Change "rb" to "wb" for writing in binary mode
    // binary mode
    ASSERT_NE(fileStream, nullptr);
    std::string text = "Hello, world!";
    ssize_t result = fwrite(text.c_str(), sizeof(char), text.size(),
        fileStream); // Use sizeof(char) as the second argument
    ASSERT_EQ(ferror(fileStream), 0);
    ASSERT_EQ(result, text.size());

    // Reset the file pointer to the beginning of the file
    rewind(fileStream);

    // Read and verify the data
    char buffer[SIZE_255];
    result = fread(buffer, sizeof(char), text.size(), fileStream);
    ASSERT_EQ(result, text.size());
    buffer[result] = '\0'; // Add string termination character
    ASSERT_STREQ(buffer, text.c_str());

    fclose(fileStream);
    close(dupFD);
    close(fileDescriptor);
}

HWTEST_F(MetadataStreamTest, FileMetadataStream_CONSTRUCTOR005, TestSize.Level3)
{
    int fileDescriptor = open(filePathSource.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    FileMetadataStream *stream = new FileMetadataStream(fileDescriptor);
    ASSERT_FALSE(stream->IsOpen());
    ASSERT_TRUE(stream->Open());
    delete stream;
    stream = new FileMetadataStream(fileDescriptor);
    ASSERT_TRUE(stream->Open());
    delete stream;
}

/**
 * @tc.name: FileMetadataStream_DESTRUCTOR001
 * @tc.desc: Test the destructor of FileMetadataStream, checking if it can
 * correctly handle the deletion of a non-existing file
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_DESTRUCTOR001, TestSize.Level3)
{
    FileMetadataStream *stream = new FileMetadataStream("/data/fileNotExist");
    ASSERT_FALSE(stream->Open());
    ASSERT_EQ(stream->Write((byte *)"Hello, the world", 16), -1);
    stream->GetAddr();
    ASSERT_FALSE(stream->Flush());
    delete stream;
}

/**
 * @tc.name: FileMetadataStream_Seek001
 * @tc.desc: Test the Seek function of FileMetadataStream, checking if it can
 * correctly change the position of the file pointer
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, FileMetadataStream_Seek001, TestSize.Level3)
{
    RemoveFile(filePath.c_str());
    FileMetadataStream stream(CreateIfNotExit(filePath));
    stream.Open(OpenMode::ReadWrite);
    std::string sourceData = "Hello, world!";
    ASSERT_EQ(stream.Tell(), 0);
    stream.Write((byte *)sourceData.c_str(), sourceData.size());
    ASSERT_EQ(stream.Tell(), sourceData.size());
    stream.Seek(2, SeekPos::BEGIN);
    ASSERT_EQ(stream.Tell(), 2);
    byte buffer[SIZE_255];
    ssize_t bytesRead = stream.Read(buffer, 1);
    buffer[bytesRead] = '\0'; // Add string termination character
    ASSERT_STREQ((char *)buffer, "l");
    ASSERT_EQ(stream.Tell(), 3);
    stream.Seek(3, SeekPos::CURRENT);
    ASSERT_EQ(stream.Tell(), 6);
    bytesRead = stream.Read(buffer, 1);
    buffer[bytesRead] = '\0'; // Add string termination character
    ASSERT_STREQ((char *)buffer, " ");
    stream.Seek(0, SeekPos::END);
    ASSERT_EQ(stream.Tell(), sourceData.size());
}

/**
 * @tc.name: BufferMetadataStream_Open001
 * @tc.desc: Test the Open function of BufferMetadataStream, checking if it can
 * correctly open a stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Open001, TestSize.Level3)
{
    BufferMetadataStream stream;
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));
}

/**
 * @tc.name: BufferMetadataStream_Read001
 * @tc.desc: Test the Read function of BufferMetadataStream, checking if it can
 * correctly read data from the stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Read001, TestSize.Level3)
{
    BufferMetadataStream stream;
    ASSERT_TRUE(stream.Open(OpenMode::ReadWrite));

    // Write a string
    std::string sourceData = "Hello, world!";
    ASSERT_EQ(stream.Tell(), 0);
    stream.Write((byte *)sourceData.c_str(), sourceData.size());

    // Read the string
    byte buffer[SIZE_255];
    stream.Seek(0, SeekPos::BEGIN);
    size_t bytesRead = stream.Read(buffer, sourceData.size());
    buffer[bytesRead] = '\0'; // Add string termination character

    // Compare the read string with the written string
    ASSERT_STREQ((char *)buffer, sourceData.c_str());
}

/**
 * @tc.name: BufferMetadataStream_Write001
 * @tc.desc: Test the Write function of BufferMetadataStream, checking if it can
 * correctly write data to the stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write001, TestSize.Level3)
{
    BufferMetadataStream stream;
    byte data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    stream.Open(OpenMode::ReadWrite);
    size_t size = sizeof(data) / sizeof(data[0]);
    int offset = 0;
    stream.Seek(0, SeekPos::BEGIN);
    ssize_t bytesWritten = stream.Write(data, size);
    ASSERT_EQ(bytesWritten, size);
    offset = stream.Tell();
    ASSERT_EQ(stream.Tell(), size);
    ASSERT_NE(offset, 0);
    byte readData[10] = {0};
    stream.Seek(0, SeekPos::BEGIN);
    ASSERT_EQ(stream.Tell(), 0);
    ssize_t bytesRead = stream.Read(readData, size);
    ASSERT_EQ(bytesRead, size);

    for (size_t i = 0; i < size; ++i) {
        ASSERT_EQ(data[i], readData[i]);
    }
}

/**
 * @tc.name: BufferMetadataStream_Write002
 * @tc.desc: Test the Write function of BufferMetadataStream, checking if it can
 * correctly write a string to the stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write002, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Open(OpenMode::ReadWrite);
    stream.Write((byte *)"Hello, world!", 13);
    ASSERT_EQ(stream.capacity_, METADATA_STREAM_PAGE_SIZE);
    ASSERT_EQ(stream.Tell(), 13);
}

/**
 * @tc.name: BufferMetadataStream_Write003
 * @tc.desc: Test the Write function of BufferMetadataStream, checking if it can
 * correctly handle large data
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write003, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Open(OpenMode::ReadWrite);
    byte data[METADATA_STREAM_PAGE_SIZE + 1] = {0};  // Create a 4097-byte data
    stream.Write(data, METADATA_STREAM_PAGE_SIZE + 1); // Write 4097 bytes of data
    ASSERT_GE(stream.capacity_,
        METADATA_STREAM_PAGE_SIZE + 1);                      // Check if the buffer capacity is at least 4097
    ASSERT_EQ(stream.Tell(), METADATA_STREAM_PAGE_SIZE + 1); // Check if the write position is correct
}

/**
 * @tc.name: BufferImageStream_Write004
 * @tc.desc: Test the Write function of BufferImageStream, checking if it can
 * correctly handle data of the exact buffer capacity
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Write004, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Open();

    byte data[METADATA_STREAM_PAGE_SIZE] = {0};  // Create a 4096-byte data
    stream.Write(data, METADATA_STREAM_PAGE_SIZE); // Write 4096 bytes of data
    ASSERT_EQ(stream.capacity_,
        METADATA_STREAM_PAGE_SIZE); // Check if the buffer capacity is 4096
    ASSERT_EQ(stream.Tell(),
        METADATA_STREAM_PAGE_SIZE); // Check if the write position is correct
}

/**
 * @tc.name: BufferImageStream_Write005
 * @tc.desc: Test the Write function of BufferImageStream, checking if it can
 * correctly handle fixed buffer size
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Write005, TestSize.Level3)
{
    char text[] = "Hello, world!";
    BufferMetadataStream stream((byte *)text, sizeof(text), BufferMetadataStream::Fix);
    ASSERT_TRUE(stream.Open());
    ASSERT_EQ(stream.Write((byte *)"Hi", 2), 2);
    ASSERT_EQ(stream.Tell(), 2);
    ASSERT_STREQ(text, "Hillo, world!");
    ASSERT_EQ(stream.Write((byte *)"this is a very long text", 24), -1);
    ASSERT_STREQ(text, "Hillo, world!");
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write006, TestSize.Level3)
{
    for (ssize_t size : testSize) {
        BufferMetadataStream stream;
        ASSERT_TRUE(stream.Open());
        byte *buf = new byte[size](); // Dynamically allocate the buffer with the current test size
        ASSERT_EQ(stream.Write(buf, size), size);
        ASSERT_EQ(stream.GetSize(), size);

        delete[] buf; // Don't forget to delete the dynamically allocated buffer
    }
}

/**
 * @tc.name: BufferImageStream_Write006
 * @tc.desc: Test the Write function of BufferImageStream, checking if it can
 * correctly handle dynamic buffer size
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write007, TestSize.Level3)
{
    char text[] = "Hello, world!";
    BufferMetadataStream stream((byte *)text, sizeof(text), BufferMetadataStream::Dynamic);
    ASSERT_TRUE(stream.Open());
    ASSERT_EQ(stream.Write((byte *)"Hi", 2), 2);
    ASSERT_EQ(stream.Tell(), 2);
    ASSERT_STREQ(text, "Hillo, world!");
    stream.Seek(0, SeekPos::BEGIN);
    ASSERT_EQ(stream.Write((byte *)"this is a very long text", 25), 25);
    ASSERT_STREQ((char *)stream.GetAddr(false), "this is a very long text");
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write008, TestSize.Level3)
{
    BufferMetadataStream stream;
    byte *buf = new byte[14];
    ASSERT_TRUE(stream.Open());
    stream.Write((uint8_t *)"Hello, world!", 13);
    stream.Seek(4, SeekPos::BEGIN);
    stream.Write((uint8_t *)"a", 1);
    stream.Write((uint8_t *)"b", 1);
    stream.Seek(0, SeekPos::BEGIN);
    stream.Read(buf, 13);
    ASSERT_STREQ((char *)buf, "Hellab world!");
    delete[] buf;
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_Write009, TestSize.Level3)
{
    BufferMetadataStream stream;
    byte *buf = new byte[2000];
    byte *buf2 = new byte[500];
    ASSERT_TRUE(stream.Open());
    stream.Write(buf, 2000);
    stream.Write(buf2, 500);
    stream.Write(buf2, 500);
    ASSERT_EQ(stream.GetSize(), 3000);
    ASSERT_EQ(stream.capacity_, 32768);
    delete[] buf;
    delete[] buf2;
}

/**
 * @tc.name: BufferMetadataStream_Close001
 * @tc.desc: Test the Close function of BufferMetadataStream with an empty stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Close001, TestSize.Level3)
{
    BufferMetadataStream stream;
}

/**
 * @tc.name: BufferMetadataStream_Close002
 * @tc.desc: Test the Close function of BufferMetadataStream after writing to the
 * stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Close002, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Write((byte *)"Hello, world!", 13);
}

/**
 * @tc.name: BufferImageStream_Close003
 * @tc.desc: Test the Close function of BufferImageStream after releasing the
 * stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Close003, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Write((byte *)"Hello, world!", 13);
    delete[] stream.Release();
}

/**
 * @tc.name: BufferMetadataStream_Close004
 * @tc.desc: Test the Close function of BufferMetadataStream after closing the
 * stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferMetadataStream_Close004, TestSize.Level3)
{
    BufferMetadataStream stream;
    stream.Write((byte *)"Hello, world!", 13);
    stream.Close();
}

/**
 * @tc.name: BufferImageStream_Close005
 * @tc.desc: Test the Close function of BufferImageStream with a fixed size
 * buffer
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Close005, TestSize.Level3)
{
    char text[] = "Hello, world!";
    BufferMetadataStream stream((byte *)text, sizeof(text), BufferMetadataStream::Fix);
}

/**
 * @tc.name: BufferImageStream_Close006
 * @tc.desc: Test the Close function of BufferImageStream with a fixed size
 * buffer after releasing the stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Close006, TestSize.Level3)
{
    char text[] = "Hello, world!";
    BufferMetadataStream stream((byte *)text, sizeof(text), BufferMetadataStream::Fix);
    stream.Release();
}

/**
 * @tc.name: BufferImageStream_Close007
 * @tc.desc: Test the Close function of BufferImageStream with a dynamic size
 * buffer after writing and releasing the stream
 * @tc.type: FUNC
 */
HWTEST_F(MetadataStreamTest, BufferImageStream_Close007, TestSize.Level3)
{
    char text[] = "Hello, world!";
    BufferMetadataStream stream((byte *)text, sizeof(text), BufferMetadataStream::Dynamic);
    stream.Write((byte *)"this is a very very long text", 28);
    delete[] stream.Release();

    DataBuf dataBuf(10);
    dataBuf.WriteUInt8(0, 123);
    EXPECT_EQ(dataBuf.ReadUInt8(0), 123);
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_CopyFrom001, TestSize.Level3)
{
    FileMetadataStream src(filePathSource);
    BufferMetadataStream dest;
    src.Open();
    dest.Open();
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_CopyFrom002, TestSize.Level3)
{
    BufferMetadataStream src;
    BufferMetadataStream dest;
    src.Open();
    dest.Open();
    src.Write((byte *)"Hello, world!", 13);
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_CopyFrom003, TestSize.Level3)
{
    BufferMetadataStream src;
    BufferMetadataStream dest;
    src.Open();
    dest.Open();
    char buff[METADATA_STREAM_PAGE_SIZE + 1] = {0};
    src.Write((byte *)buff, METADATA_STREAM_PAGE_SIZE + 1);
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_CopyFrom004, TestSize.Level3)
{
    BufferMetadataStream src;
    BufferMetadataStream dest;
    src.Open();
    dest.Open();
    char buff[METADATA_STREAM_PAGE_SIZE - 1] = {0};
    src.Write((byte *)buff, METADATA_STREAM_PAGE_SIZE - 1);
    ASSERT_TRUE(dest.CopyFrom(src));
    ASSERT_EQ(src.GetSize(), dest.GetSize());
    ASSERT_EQ(memcmp(src.GetAddr(), dest.GetAddr(), src.GetSize()), 0);
}

HWTEST_F(MetadataStreamTest, BufferMetadataStream_CopyFrom005, TestSize.Level3)
{
    BufferMetadataStream temp;
    temp.Open();
    temp.Write((uint8_t*)"Hello, world", 13);
    BufferMetadataStream src(temp.GetAddr(), temp.GetSize(), BufferMetadataStream::Dynamic);
    FileMetadataStream dest(filePathSource);
    src.Open();
    dest.Open();
    src.CopyFrom(dest);
}

} // namespace Media
} // namespace OHOS