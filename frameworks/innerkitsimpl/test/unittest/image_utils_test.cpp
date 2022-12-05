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

#include <gtest/gtest.h>
#include <fcntl.h>
#include <fstream>
#include "image_utils.h"
#include "image_trace.h"
#include "source_stream.h"
#include "istream_source_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";

class ImageUtilsTest : public testing::Test {
public:
    ImageUtilsTest() {}
    ~ImageUtilsTest() {}
};

/**
 * @tc.name: ImageTraceTest001
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, ImageTraceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest001 start";
    const std::string title = "title";
    ImageTrace imagetrace(title);
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest001 end";
}

/**
 * @tc.name: ImageTraceTest002
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, ImageTraceTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest002 start";
    const char *fmt = nullptr;
    ImageTrace imagetrace(fmt);
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest002 end";
}

/**
 * @tc.name: ImageTraceTest003
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, ImageTraceTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest003 start";
    const char *fmt = "mytrace";
    ImageTrace imagetrace(fmt);
    GTEST_LOG_(INFO) << "ImageUtilsTest: ImageTraceTest003 end";
}

/**
 * @tc.name: GetFileSize001
 * @tc.desc: ImageUtils::GetFileSize(const string &pathName, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize001 start";
    ImageUtils imageUtils;
    size_t size;
    imageUtils.GetFileSize(IMAGE_INPUT_JPEG_PATH, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize001 end";
}

/**
 * @tc.name: GetFileSize002
 * @tc.desc: ImageUtils::GetFileSize(const string &pathName, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize002 start";
    ImageUtils imageUtils;
    size_t size;
    const std::string path = "";
    imageUtils.GetFileSize(path, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize002 end";
}

/**
 * @tc.name: GetFileSize003
 * @tc.desc: ImageUtils::GetFileSize(const string &pathName, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize003 start";
    ImageUtils imageUtils;
    size_t size;
    const std::string path = "test/aaa";
    imageUtils.GetFileSize(path, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize003 end";
}

/**
 * @tc.name: GetFileSize004
 * @tc.desc: bool ImageUtils::GetFileSize(const int fd, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize004 start";
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ImageUtils imageUtils;
    size_t size;
    imageUtils.GetFileSize(fd, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize004 end";
}

/**
 * @tc.name: GetFileSize005
 * @tc.desc: bool ImageUtils::GetFileSize(const int fd, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize005 start";
    const int fd = -1;
    ImageUtils imageUtils;
    size_t size;
    imageUtils.GetFileSize(fd, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize005 end";
}

/**
 * @tc.name: GetFileSize006
 * @tc.desc: bool ImageUtils::GetFileSize(const int fd, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetFileSize006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize006 start";
    const int fd = 100;
    ImageUtils imageUtils;
    size_t size;
    imageUtils.GetFileSize(fd, size);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetFileSize006 end";
}

/**
 * @tc.name: GetPixelBytes001
 * @tc.desc: bool ImageUtils::GetInputStreamSize(istream &inputStream, size_t &size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, GetPixelBytes001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetPixelBytes001 start";
    ImageUtils::GetPixelBytes(PixelFormat::RGB_888);
    ImageUtils::GetPixelBytes(PixelFormat::RGBA_F16);
    ImageUtils::GetPixelBytes(PixelFormat::NV12);
    GTEST_LOG_(INFO) << "ImageUtilsTest: GetPixelBytes001 end";
}

/**
 * @tc.name: PathToRealPath001
 * @tc.desc: PathToRealPath
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, PathToRealPath001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: PathToRealPath001 start";
    const string path = "";
    string realPath;
    ImageUtils::PathToRealPath(path, realPath);
    GTEST_LOG_(INFO) << "ImageUtilsTest: PathToRealPath001 end";
}

/**
 * @tc.name: PathToRealPath002
 * @tc.desc: PathToRealPath
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, PathToRealPath002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: PathToRealPath002 start";
    char buffer[PATH_MAX+1] = {'\0'};
    for (int i = 0; i <= PATH_MAX; i++) {
        buffer[i] = i;
    }
    const string path = buffer;
    string realPath;
    ImageUtils::PathToRealPath(path, realPath);
    GTEST_LOG_(INFO) << "ImageUtilsTest: PathToRealPath002 end";
}

/**
 * @tc.name: IsValidImageInfo001
 * @tc.desc: IsValidImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, IsValidImageInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: IsValidImageInfo001 start";
    ImageInfo info;
    ImageUtils::IsValidImageInfo(info);
    info.size.width = 0;
    info.size.height = 0;
    ImageUtils::IsValidImageInfo(info);
    info.size.width = 100;
    info.size.height = 10;
    ImageUtils::IsValidImageInfo(info);
    GTEST_LOG_(INFO) << "ImageUtilsTest: IsValidImageInfo001 end";
}

/**
 * @tc.name: CheckMulOverflow001
 * @tc.desc: CheckMulOverflow
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, CheckMulOverflow001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: CheckMulOverflow001 start";
    int32_t width = 0;
    int32_t height = 0;
    int32_t bytesPerPixel = 0;
    ImageUtils::CheckMulOverflow(width, height, bytesPerPixel);
    GTEST_LOG_(INFO) << "ImageUtilsTest: CheckMulOverflow001 end";
}
}
}