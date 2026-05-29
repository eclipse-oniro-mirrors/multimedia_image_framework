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

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "XMP_Const.h"
#include "xmp_buffer_io.h"
#include "xmp_fd_io.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
// Constants for test data sizes and offsets to avoid magic numbers
constexpr size_t TEST_DATA_ABCDE_LEN = 5;
constexpr size_t TEST_DATA_ABC_LEN = 3;
constexpr size_t SEEK_OFFSET_0 = 0;
constexpr size_t SEEK_OFFSET_1 = 1;
constexpr size_t SEEK_OFFSET_3 = 3;
constexpr size_t SEEK_OFFSET_4 = 4;
constexpr size_t READ_SIZE_2 = 2;
constexpr size_t READ_SIZE_3 = 3;
constexpr size_t READ_SIZE_4 = 4;
constexpr size_t WRITE_SIZE_1 = 1;
constexpr size_t SMALL_BUF_SIZE = 8;
constexpr size_t READ_BUFFER_SIZE = 128;
constexpr size_t ZERO_SIZE = 0;
constexpr int INVALID_FD = -1;
constexpr int INVALID_SEEK_MODE = 999;
constexpr XMP_Int64 NEGATIVE_TRUNCATE_LEN = -1;
bool CreateTempFileInDir(const std::string &dir, int &fd, std::string &path)
{
    if (dir.empty()) {
        return false;
    }
    std::string tempPath = dir;
    if (tempPath.back() != '/') {
        tempPath += '/';
    }
    tempPath += "xmp_io_test_XXXXXX";

    std::vector<char> mutablePath(tempPath.begin(), tempPath.end());
    mutablePath.push_back('\0');

    fd = mkstemp(mutablePath.data());
    if (fd < 0) {
        return false;
    }

    path = mutablePath.data();
    return true;
}

class ScopedTempFile {
public:
    ScopedTempFile()
    {
        std::vector<std::string> candidates;
        const char *tmpDir = getenv("TMPDIR");
        if (tmpDir != nullptr && tmpDir[0] != '\0') {
            candidates.emplace_back(tmpDir);
        }
        candidates.emplace_back("/data/local/tmp");
        candidates.emplace_back("/data/tmp");
        candidates.emplace_back(".");

        for (const auto &dir : candidates) {
            if (CreateTempFileInDir(dir, fd_, path_)) {
                break;
            }
        }

        EXPECT_GE(fd_, 0) << "mkstemp failed, errno=" << errno << ", msg=" << strerror(errno);
    }

    ~ScopedTempFile()
    {
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
        if (!path_.empty()) {
            unlink(path_.c_str());
        }
    }

    int GetFd() const
    {
        return fd_;
    }

    const std::string &GetPath() const
    {
        return path_;
    }

    void CloseFd()
    {
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
    std::string path_;
};

bool WriteAll(int fd, const std::string &content)
{
    if (fd < 0) {
        return false;
    }
    size_t written = 0;
    while (written < content.size()) {
        ssize_t rc = write(fd, content.data() + written, content.size() - written);
        if (rc <= 0) {
            return false;
        }
        written += static_cast<size_t>(rc);
    }
    return true;
}

std::string ReadAllFromPath(const std::string &path)
{
    std::string out;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return out;
    }
    char buf[READ_BUFFER_SIZE] = {0};
    for (ssize_t rc = read(fd, buf, sizeof(buf)); rc > 0; rc = read(fd, buf, sizeof(buf))) {
        out.append(buf, static_cast<size_t>(rc));
    }
    close(fd);
    return out;
}
} // namespace

class XmpBufferIOTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

class XmpFdIOTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: XMPBufferIOReadTest001
 * @tc.desc: Verify read returns expected bytes after positioning.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOReadTest001, TestSize.Level1)
{
    XMPBuffer_IO io;
    const char *data = "abcde";
    io.Write(data, TEST_DATA_ABCDE_LEN);
    EXPECT_EQ(io.Length(), static_cast<XMP_Int64>(TEST_DATA_ABCDE_LEN));

    EXPECT_EQ(io.Seek(SEEK_OFFSET_1, kXMP_SeekFromStart), static_cast<XMP_Int64>(SEEK_OFFSET_1));
    char readBuf[READ_SIZE_4] = {0};
    EXPECT_EQ(io.Read(readBuf, READ_SIZE_3, true), READ_SIZE_3);
    EXPECT_STREQ(readBuf, "bcd");
}

/**
 * @tc.name: XMPBufferIOReadTest002
 * @tc.desc: Verify readAll=true throws when requested bytes are not available.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOReadTest002, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    uint8_t out[SMALL_BUF_SIZE] = {0};
    try {
        (void)io.Read(out, READ_SIZE_4, true);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_EnforceFailure);
    }
}

/**
 * @tc.name: XMPBufferIOWriteTest001
 * @tc.desc: Verify write is rejected on read-only memory stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOWriteTest001, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    const uint8_t in[] = {9};

    try {
        io.Write(in, WRITE_SIZE_1);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_FilePermission);
    }
}

/**
 * @tc.name: XMPBufferIOTruncateTest001
 * @tc.desc: Verify truncate is rejected on read-only memory stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOTruncateTest001, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    try {
        io.Truncate(WRITE_SIZE_1);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_FilePermission);
    }
}

/**
 * @tc.name: XMPBufferIOAbsorbTempTest001
 * @tc.desc: Verify AbsorbTemp writes derived temporary content into main stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOAbsorbTempTest001, TestSize.Level1)
{
    XMPBuffer_IO io;
    XMP_IO *tempBase = io.DeriveTemp();
    EXPECT_NE(tempBase, nullptr);
    EXPECT_EQ(io.DeriveTemp(), tempBase);

    XMPBuffer_IO *temp = static_cast<XMPBuffer_IO *>(tempBase);
    const char *text = "temp";
    constexpr size_t textTempLen = 4;
    temp->Write(text, textTempLen);

    io.AbsorbTemp();
    EXPECT_EQ(io.Length(), static_cast<XMP_Int64>(textTempLen));
    EXPECT_EQ(io.Seek(SEEK_OFFSET_0, kXMP_SeekFromStart), static_cast<XMP_Int64>(SEEK_OFFSET_0));

    char out[textTempLen + 1] = {0};
    EXPECT_EQ(io.Read(out, textTempLen, true), textTempLen);
    EXPECT_STREQ(out, "temp");
}

/**
 * @tc.name: XMPFdIOReadTest001
 * @tc.desc: Verify read returns expected bytes from writable fd stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOReadTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        ASSERT_TRUE(WriteAll(temp.GetFd(), "abcde"));
        ASSERT_GE(lseek(temp.GetFd(), 0, SEEK_SET), 0);

        XMPFd_IO io(temp.GetFd(), false, false);
        EXPECT_TRUE(io.IsValid());

        char firstTwo[READ_SIZE_2 + 1] = {0};
        EXPECT_EQ(io.Read(firstTwo, READ_SIZE_2, true), READ_SIZE_2);
        EXPECT_STREQ(firstTwo, "ab");
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOWriteTest001
 * @tc.desc: Verify write is rejected on read-only fd stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOWriteTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        ASSERT_TRUE(WriteAll(temp.GetFd(), "abc"));
        ASSERT_GE(lseek(temp.GetFd(), 0, SEEK_SET), 0);

        int rdOnlyFd = open(temp.GetPath().c_str(), O_RDONLY);
        ASSERT_GE(rdOnlyFd, 0);
        XMPFd_IO rdOnlyIo(rdOnlyFd, true, true);

        const char one = 'Z';
        try {
            rdOnlyIo.Write(&one, WRITE_SIZE_1);
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_FilePermission);
        }

    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOAbsorbTempTest001
 * @tc.desc: Verify AbsorbTemp writes temporary fd content back to origin file.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOAbsorbTempTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        ASSERT_TRUE(WriteAll(temp.GetFd(), "hello"));
        ASSERT_GE(lseek(temp.GetFd(), 0, SEEK_SET), 0);

        XMPFd_IO io(temp.GetFd(), false, false);
        XMP_IO *tempBase = io.DeriveTemp();
        ASSERT_NE(tempBase, nullptr);
        EXPECT_EQ(io.DeriveTemp(), tempBase);

        XMPFd_IO *tempIo = static_cast<XMPFd_IO *>(tempBase);
        const char *newData = "XYZ";
        tempIo->Write(newData, READ_SIZE_3);

        io.AbsorbTemp();
        EXPECT_EQ(io.Seek(SEEK_OFFSET_0, kXMP_SeekFromStart), static_cast<XMP_Int64>(SEEK_OFFSET_0));
        char out[READ_SIZE_3 + 1] = {0};
        EXPECT_EQ(io.Read(out, READ_SIZE_3, true), READ_SIZE_3);
        EXPECT_STREQ(out, "XYZ");

        io.DeleteTemp();
        EXPECT_EQ(ReadAllFromPath(temp.GetPath()), "XYZ");
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOCtorTest001
 * @tc.desc: Verify constructor rejects invalid file descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOCtorTest001, TestSize.Level1)
{
    try {
        XMPFd_IO invalid(INVALID_FD, true, false);
        (void)invalid;
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPBufferIOCtorTest002
 * @tc.desc: Verify constructor rejects null buffer and zero size for external stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOCtorTest002, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    try {
        XMPBuffer_IO io(nullptr, TEST_DATA_ABC_LEN, true);
        (void)io;
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
    }

    try {
        XMPBuffer_IO io(src, ZERO_SIZE, true);
        (void)io;
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
    }
}

/**
 * @tc.name: XMPBufferIOReadTest003
 * @tc.desc: Verify null buffer is rejected by Read.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOReadTest003, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    try {
        (void)io.Read(nullptr, WRITE_SIZE_1, false);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
    }
}

/**
 * @tc.name: XMPBufferIOReadTest004
 * @tc.desc: Verify EOF behavior for Read with readAll false and true.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOReadTest004, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    EXPECT_EQ(io.Seek(SEEK_OFFSET_3, kXMP_SeekFromStart), static_cast<XMP_Int64>(SEEK_OFFSET_3));

    uint8_t out[READ_SIZE_2] = {0};
    EXPECT_EQ(io.Read(out, WRITE_SIZE_1, false), 0);
    try {
        (void)io.Read(out, WRITE_SIZE_1, true);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_EnforceFailure);
    }
}

/**
 * @tc.name: XMPBufferIOSeekTest001
 * @tc.desc: Verify invalid seek mode is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOSeekTest001, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    try {
        (void)io.Seek(SEEK_OFFSET_0, static_cast<SeekMode>(INVALID_SEEK_MODE));
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
    }
}

/**
 * @tc.name: XMPBufferIOSeekTest002
 * @tc.desc: Verify read-only seek beyond EOF is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOSeekTest002, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    try {
        (void)io.Seek(SEEK_OFFSET_4, kXMP_SeekFromStart);
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_EnforceFailure);
    }
}

/**
 * @tc.name: XMPBufferIODeriveTempTest001
 * @tc.desc: Verify DeriveTemp is rejected on read-only stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIODeriveTempTest001, TestSize.Level1)
{
    const uint8_t src[] = {1, 2, 3};
    XMPBuffer_IO io(src, TEST_DATA_ABC_LEN, true);
    try {
        (void)io.DeriveTemp();
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_InternalFailure);
    }
}

/**
 * @tc.name: XMPBufferIOAbsorbTempTest002
 * @tc.desc: Verify AbsorbTemp fails when no temp stream exists.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIOAbsorbTempTest002, TestSize.Level1)
{
    XMPBuffer_IO io;
    try {
        io.AbsorbTemp();
        FAIL() << "Expected XMP_Error";
    } catch (const XMP_Error &e) {
        EXPECT_EQ(e.GetID(), kXMPErr_InternalFailure);
    }
}

/**
 * @tc.name: XMPBufferIODeleteTempTest001
 * @tc.desc: Verify DeleteTemp is idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(XmpBufferIOTest, XMPBufferIODeleteTempTest001, TestSize.Level1)
{
    XMPBuffer_IO io;
    EXPECT_NO_THROW(io.DeleteTemp());
    EXPECT_NO_THROW(io.DeleteTemp());
}

/**
 * @tc.name: XMPFdIOReadTest002
 * @tc.desc: Verify fd stream Read rejects null buffer.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOReadTest002, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        ASSERT_TRUE(WriteAll(temp.GetFd(), "abc"));
        ASSERT_GE(lseek(temp.GetFd(), 0, SEEK_SET), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        try {
            (void)io.Read(nullptr, WRITE_SIZE_1, false);
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOWriteTest002
 * @tc.desc: Verify fd stream Write rejects null buffer.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOWriteTest002, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        try {
            io.Write(nullptr, WRITE_SIZE_1);
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOSeekTest001
 * @tc.desc: Verify invalid seek mode is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOSeekTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        try {
            (void)io.Seek(SEEK_OFFSET_0, static_cast<SeekMode>(INVALID_SEEK_MODE));
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOTruncateTest001
 * @tc.desc: Verify negative length is rejected by Truncate.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOTruncateTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        try {
            io.Truncate(NEGATIVE_TRUNCATE_LEN);
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_BadParam);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIOAbsorbTempTest002
 * @tc.desc: Verify AbsorbTemp fails when no temp stream exists.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIOAbsorbTempTest002, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        try {
            io.AbsorbTemp();
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_InternalFailure);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIODeleteTempTest001
 * @tc.desc: Verify DeleteTemp is idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIODeleteTempTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        XMPFd_IO io(temp.GetFd(), false, false);
        io.DeleteTemp();
        io.DeleteTemp();
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}

/**
 * @tc.name: XMPFdIODeriveTempTest001
 * @tc.desc: Verify DeriveTemp is rejected on read-only stream.
 * @tc.type: FUNC
 */
HWTEST_F(XmpFdIOTest, XMPFdIODeriveTempTest001, TestSize.Level1)
{
    try {
        ScopedTempFile temp;
        ASSERT_GE(temp.GetFd(), 0);
        int rdOnlyFd = open(temp.GetPath().c_str(), O_RDONLY);
        ASSERT_GE(rdOnlyFd, 0);
        XMPFd_IO rdOnlyIo(rdOnlyFd, true, true);
        try {
            (void)rdOnlyIo.DeriveTemp();
            FAIL() << "Expected XMP_Error";
        } catch (const XMP_Error &e) {
            EXPECT_EQ(e.GetID(), kXMPErr_FilePermission);
        }
    } catch (const XMP_Error &e) {
        FAIL() << "Unexpected XMP_Error, id=" << e.GetID() << ", msg=" << e.GetErrMsg();
    } catch (...) {
        FAIL() << "Unexpected non-XMP exception";
    }
}
} // namespace Media
} // namespace OHOS
