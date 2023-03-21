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
static constexpr int32_t LENGTH = 8;
constexpr int32_t RGB_888_PIXEL_BYTES = 3;
constexpr int32_t RGBA_F16_PIXEL_BYTES = 8;
constexpr int32_t NV12_PIXEL_BYTES = 2;
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
    bool res = imageUtils.GetFileSize(IMAGE_INPUT_JPEG_PATH, size);
    ASSERT_EQ(res, true);
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
    bool res = imageUtils.GetFileSize(path, size);
    ASSERT_EQ(res, false);
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
    bool res = imageUtils.GetFileSize(path, size);
    ASSERT_EQ(res, false);
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
    bool res = imageUtils.GetFileSize(fd, size);
    ASSERT_EQ(res, true);
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
    bool res = imageUtils.GetFileSize(fd, size);
    ASSERT_EQ(res, false);
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
    bool res = imageUtils.GetFileSize(fd, size);
    ASSERT_EQ(res, false);
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
    int32_t res1 = ImageUtils::GetPixelBytes(PixelFormat::RGB_888);
    ASSERT_EQ(res1, RGB_888_PIXEL_BYTES);
    int32_t res2 = ImageUtils::GetPixelBytes(PixelFormat::RGBA_F16);
    ASSERT_EQ(res2, RGBA_F16_PIXEL_BYTES);
    int32_t res3 = ImageUtils::GetPixelBytes(PixelFormat::NV12);
    ASSERT_EQ(res3, NV12_PIXEL_BYTES);
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
    bool res = ImageUtils::PathToRealPath(path, realPath);
    ASSERT_EQ(res, false);
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
    bool res = ImageUtils::PathToRealPath(path, realPath);
    ASSERT_EQ(res, false);
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
    bool res1 = ImageUtils::IsValidImageInfo(info);
    ASSERT_EQ(res1, false);
    info.size.width = 0;
    info.size.height = 0;
    bool res2 = ImageUtils::IsValidImageInfo(info);
    ASSERT_EQ(res2, false);
    info.size.width = 100;
    info.size.height = 10;
    bool res3 = ImageUtils::IsValidImageInfo(info);
    ASSERT_EQ(res3, false);
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
    bool res = ImageUtils::CheckMulOverflow(width, height, bytesPerPixel);
    ASSERT_EQ(res, true);
    GTEST_LOG_(INFO) << "ImageUtilsTest: CheckMulOverflow001 end";
}

/**
 * @tc.name: BGRAToARGB001
 * @tc.desc: BGRAToARGB
 * @tc.type: FUNC
 */
HWTEST_F(ImageUtilsTest, BGRAToARGB001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageUtilsTest: BGRAToARGB001 start";
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dst[LENGTH] = {0};
    ImageUtils::BGRAToARGB(src, dst, LENGTH);
    for (int i = 0; i < LENGTH; i++) {
        GTEST_LOG_(INFO) << "BGRAToARGB" << "i:" << i << " " \
            << static_cast<int>(src[i]) << "," << static_cast<int>(dst[i]);
    }

    uint8_t src2[LENGTH] = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t dst2[LENGTH] = {0};
    ImageUtils::ARGBToBGRA(src2, dst2, LENGTH);
    for (int i = 0; i < LENGTH; i++) {
        GTEST_LOG_(INFO) << "ARGBToBGRA" << "i:" << i << " " \
            << static_cast<int>(src2[i]) << "," << static_cast<int>(dst2[i]);
    }
    EXPECT_NE(dst2, nullptr);
    uint8_t src3[] = {0x01, 0x02};
    ImageUtils::ARGBToBGRA(src3, dst2, LENGTH);
    ImageUtils::BGRAToARGB(src3, dst, LENGTH);
    GTEST_LOG_(INFO) << "ImageUtilsTest: BGRAToARGB001 end";
}
}
}