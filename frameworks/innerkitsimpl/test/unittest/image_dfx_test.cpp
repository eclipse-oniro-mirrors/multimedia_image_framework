/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <memory>
#include <string>
#include "image_dfx.h"

extern "C++" {
namespace OHOS {
namespace Media {
std::string GetInvokeTypeStr(uint16_t invokeType);
}
}
}

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

class ImageDfxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: getInvokeTypeTest001
 * @tc.desc: Verify ImageEvent::getInvokeType returns correct string according to invokeType.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, getInvokeTypeTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "ImageDfxTest: getInvokeTypeTest001 start";
    std::shared_ptr<Media::ImageEvent> imageEvent = std::make_shared<Media::ImageEvent>();
    imageEvent->options_.invokeType = Media::JS_INTERFACE;
    auto ret = imageEvent->getInvokeType();
    EXPECT_EQ(ret, "js_interface");

    imageEvent->options_.invokeType =  Media::C_INTERFACE;
    ret = imageEvent->getInvokeType();
    EXPECT_EQ(ret, "c_interface");
    GTEST_LOG_(INFO) << "ImageDfxTest: getInvokeTypeTest001 end";
}

/**
 * @tc.name: GetInvokeTypeStrTest001
 * @tc.desc: Verify that GetInvokeTypeStr returns correct string for all invoke types.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, GetInvokeTypeStrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: GetInvokeTypeStrTest001 start";
    EXPECT_EQ(OHOS::Media::GetInvokeTypeStr(Media::JS_INTERFACE), "js_interface");

    EXPECT_EQ(OHOS::Media::GetInvokeTypeStr(Media::C_INTERFACE), "c_interface");
    GTEST_LOG_(INFO) << "ImageDfxTest: GetInvokeTypeStrTest001 end";
}

/**
 * @tc.name: DecodeInfoOptionsDefaultValueTest001
 * @tc.desc: Verify the default value of the decode info fields added for dfx reporting.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, DecodeInfoOptionsDefaultValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeInfoOptionsDefaultValueTest001 start";
    Media::ImageEvent imageEvent;
    Media::DecodeInfoOptions &options = imageEvent.GetDecodeInfoOptions();
    EXPECT_EQ(options.sourceSize, static_cast<uint64_t>(0));
    EXPECT_EQ(options.sourceColorSpace, -1);
    EXPECT_EQ(options.sourceYuvSampling, "unknown");
    EXPECT_TRUE(options.sourceFileExtension.empty());
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeInfoOptionsDefaultValueTest001 end";
}

/**
 * @tc.name: DecodeInfoOptionsSetValueTest001
 * @tc.desc: Verify SetDecodeInfoOptions keeps the newly added source fields.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, DecodeInfoOptionsSetValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeInfoOptionsSetValueTest001 start";
    Media::ImageEvent imageEvent;
    Media::DecodeInfoOptions options = {};
    options.sourceSize = 2048;
    options.sourceColorSpace = 2;
    options.sourceYuvSampling = "4:2:0";
    options.sourceFileExtension = "png";
    imageEvent.SetDecodeInfoOptions(options);

    Media::DecodeInfoOptions &reportOptions = imageEvent.GetDecodeInfoOptions();
    EXPECT_EQ(reportOptions.sourceSize, static_cast<uint64_t>(2048));
    EXPECT_EQ(reportOptions.sourceColorSpace, 2);
    EXPECT_EQ(reportOptions.sourceYuvSampling, "4:2:0");
    EXPECT_EQ(reportOptions.sourceFileExtension, "png");
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeInfoOptionsSetValueTest001 end";
}

/**
 * @tc.name: GetImageFileExtensionTest001
 * @tc.desc: Verify only a bounded lowercase extension is returned, never a path or invalid suffix.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, GetImageFileExtensionTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: GetImageFileExtensionTest001 start";
    EXPECT_EQ(Media::GetImageFileExtension("/data/private/photo.JPEG"), "jpeg");
    EXPECT_EQ(Media::GetImageFileExtension("C:\\private\\photo.HeIf"), "heif");
    EXPECT_EQ(Media::GetImageFileExtension("/data/a.b/photo"), "unknown");
    EXPECT_EQ(Media::GetImageFileExtension("/data/.hidden"), "unknown");
    EXPECT_EQ(Media::GetImageFileExtension("/data/photo."), "unknown");
    EXPECT_EQ(Media::GetImageFileExtension("/data/photo.averyverylongextension"), "unknown");
    EXPECT_EQ(Media::GetImageFileExtension("/data/pho to.png"), "png");
    EXPECT_EQ(Media::GetImageFileExtension(""), "unknown");
    EXPECT_EQ(Media::GetImageFileExtension("", -1), "unknown");
    GTEST_LOG_(INFO) << "ImageDfxTest: GetImageFileExtensionTest001 end";
}

/**
 * @tc.name: GetImageFileExtensionFdTest001
 * @tc.desc: Verify the fd path resolves the extension through /proc/self/fd.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, GetImageFileExtensionFdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: GetImageFileExtensionFdTest001 start";
    std::string path = "/data/local/tmp/dfx_ext_test.JPEG";
    int fd = open(path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        path = "./dfx_ext_test.JPEG";
        fd = open(path.c_str(), O_CREAT | O_RDWR, 0600);
    }
    if (fd < 0) {
        GTEST_LOG_(INFO) << "ImageDfxTest: skip fd extension test, open failed";
        return;
    }
    EXPECT_EQ(Media::GetImageFileExtension("", fd), "jpeg");
    close(fd);
    unlink(path.c_str());
    GTEST_LOG_(INFO) << "ImageDfxTest: GetImageFileExtensionFdTest001 end";
}

/**
 * @tc.name: DecodeEventStateTest001
 * @tc.desc: Verify ImageEvent result, point and validity state transitions.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, DecodeEventStateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeEventStateTest001 start";
    Media::ImageEvent imageEvent;
    EXPECT_EQ(imageEvent.result_, Media::DecodeResult::FAILURE);
    EXPECT_EQ(imageEvent.point_, Media::DecodePoint::NORMAL);
    EXPECT_EQ(imageEvent.error_, Media::DecodeError::UNKNOWN);
    EXPECT_FALSE(imageEvent.optionsValid_);
    EXPECT_FALSE(imageEvent.contextValid_);

    imageEvent.SetDecodeResult(Media::DecodeResult::SUCCESS);
    EXPECT_EQ(imageEvent.result_, Media::DecodeResult::SUCCESS);
    EXPECT_EQ(imageEvent.error_, Media::DecodeError::NONE);

    imageEvent.SetDecodePoint(Media::DecodePoint::HEADER);
    EXPECT_EQ(imageEvent.point_, Media::DecodePoint::HEADER);

    imageEvent.SetDecodeContextValid();
    EXPECT_TRUE(imageEvent.contextValid_);

    Media::DecodeInfoOptions options = {};
    imageEvent.SetDecodeInfoOptions(options);
    EXPECT_TRUE(imageEvent.optionsValid_);
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeEventStateTest001 end";
}

/**
 * @tc.name: DecodeEventStateTest002
 * @tc.desc: Verify error message and incremental flags drive the event state.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, DecodeEventStateTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeEventStateTest002 start";
    Media::ImageEvent imageEvent;
    imageEvent.SetDecodeErrorMsg("decode failed");
    EXPECT_EQ(imageEvent.options_.errorMsg, "decode failed");
    EXPECT_EQ(imageEvent.result_, Media::DecodeResult::FAILURE);
    EXPECT_EQ(imageEvent.error_, Media::DecodeError::DECODE);

    imageEvent.SetIncrementalDecode();
    EXPECT_TRUE(imageEvent.options_.isIncrementalDecode);
    EXPECT_EQ(imageEvent.point_, Media::DecodePoint::INCREMENTAL);

    imageEvent.SetPluginType("ext");
    EXPECT_EQ(imageEvent.options_.pluginType, "ext");

    imageEvent.SetHeifGridTileSize(512, 256);
    EXPECT_EQ(imageEvent.options_.heifGridWidth, 512);
    EXPECT_EQ(imageEvent.options_.heifGridHeight, 256);
    GTEST_LOG_(INFO) << "ImageDfxTest: DecodeEventStateTest002 end";
}

/**
 * @tc.name: EncodeInfoOptionsTest001
 * @tc.desc: Verify encode info defaults and that reporting does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, EncodeInfoOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: EncodeInfoOptionsTest001 start";
    Media::EncodeInfoOptions options;
    EXPECT_TRUE(options.mimeType.empty());
    EXPECT_EQ(options.pixelFormat, 0);
    EXPECT_EQ(options.quality, 0);
    EXPECT_EQ(options.outputSize, static_cast<uint64_t>(0));
    EXPECT_EQ(options.costTime, static_cast<uint64_t>(0));
    EXPECT_FALSE(options.isHardware);

    options.mimeType = "image/jpeg";
    options.pixelFormat = 3;
    options.quality = 95;
    options.outputSize = 2048;
    options.costTime = 12;
    options.isHardware = true;
    Media::ReportEncodeInfo(options);
    GTEST_LOG_(INFO) << "ImageDfxTest: EncodeInfoOptionsTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS