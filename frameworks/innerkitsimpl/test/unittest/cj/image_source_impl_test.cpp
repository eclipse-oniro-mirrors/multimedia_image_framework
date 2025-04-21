/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "image_source_impl.h"

namespace OHOS {
namespace Multimedia {
using namespace testing::ext;
using namespace OHOS::Media;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";

class ImageSourceImplTest : public testing::Test {
public:
    ImageSourceImplTest() {}
    ~ImageSourceImplTest() {}
};

/**
 * @tc.name: ImageSourceImplTest001
 * @tc.desc: test ImageSourceImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceImplTest, ImageSourceImplTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest001 start";
    std::string uri = "";
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSourceImpl::CreateImageSource(uri, &errCode);
    ASSERT_EQ(imageSource, nullptr);
    SourceOptions opts;
    imageSource = ImageSourceImpl::CreateImageSourceWithOption(uri, opts, &errCode);
    ASSERT_EQ(imageSource, nullptr);
    int fd = 0;
    imageSource = ImageSourceImpl::CreateImageSource(fd, &errCode);
    ASSERT_EQ(imageSource, nullptr);
    imageSource = ImageSourceImpl::CreateImageSourceWithOption(fd, opts, &errCode);
    ASSERT_EQ(imageSource, nullptr);
    int32_t offset = 0;
    int32_t length = 0;
    imageSource = ImageSourceImpl::CreateImageSource(fd, offset, length, opts, errCode);
    ASSERT_EQ(imageSource, nullptr);
    const uint32_t size = 10;
    uint8_t data[size] = {0};
    imageSource = ImageSourceImpl::CreateImageSource(&data[0], size, &errCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource = ImageSourceImpl::CreateImageSourceWithOption(&data[0], size, opts, &errCode);
    ASSERT_NE(imageSource, nullptr);
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest001 end";
}

/**
 * @tc.name: ImageSourceImplTest002
 * @tc.desc: test ImageSourceImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceImplTest, ImageSourceImplTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest002 start";
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, 0);
    ImageSourceImpl imageSourceImpl(std::move(imageSource));
    ImageInfo imageInfo;
    imageSourceImpl.GetImageInfo(0, imageInfo);
    std::set<std::string> formats{};
    imageSourceImpl.GetSupportedFormats(formats);
    std::string key = "key";
    std::string value = "value";
    imageSourceImpl.GetImageProperty(key, 0, value);
    key = "BitsPerSample";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "Orientation";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "ImageLength";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "ImageWidth";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "GPSLatitude";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "GPSLongitude";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "GPSLatitudeRef";
    imageSourceImpl.ModifyImageProperty(key, value);
    key = "GPSLongitudeRef";
    imageSourceImpl.ModifyImageProperty(key, value);
    imageSourceImpl.SetPathName(IMAGE_JPEG_PATH);
    imageSourceImpl.ModifyImageProperty(key, value);
    imageSourceImpl.SetFd(0);
    imageSourceImpl.ModifyImageProperty(key, value);
    uint8_t data = 0;
    imageSourceImpl.SetBuffer(&data, 1);
    imageSourceImpl.ModifyImageProperty(key, value);
    imageSourceImpl.GetFrameCount(errorCode);
    imageSourceImpl.UpdateData(nullptr, 0, false);
    DecodeOptions decodeOpts;
    imageSourceImpl.CreatePixelMap(0, decodeOpts, errorCode);
    imageSourceImpl.CreatePixelMapList(0, decodeOpts, &errorCode);
    imageSourceImpl.GetDelayTime(&errorCode);
    imageSourceImpl.Release();
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest002 end";
}

/**
 * @tc.name: ImageSourceImplTest003
 * @tc.desc: test ImageSourceImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceImplTest, ImageSourceImplTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest003 start";
    ImageSourceImpl imageSourceImplNull(nullptr);
    ImageInfo imageInfo;
    imageSourceImplNull.GetImageInfo(0, imageInfo);
    std::set<std::string> formats{};
    imageSourceImplNull.GetSupportedFormats(formats);
    uint32_t errorCode = 0;
    imageSourceImplNull.GetFrameCount(errorCode);
    imageSourceImplNull.UpdateData(nullptr, 0, false);
    DecodeOptions decodeOpts;
    imageSourceImplNull.CreatePixelMap(0, decodeOpts, errorCode);
    imageSourceImplNull.CreatePixelMapList(0, decodeOpts, &errorCode);
    imageSourceImplNull.GetDelayTime(&errorCode);
    imageSourceImplNull.SetPathName("");
    imageSourceImplNull.SetFd(0);
    imageSourceImplNull.SetBuffer(nullptr, 0);
    imageSourceImplNull.Release();
    GTEST_LOG_(INFO) << "ImageSourceImplTest: ImageSourceImplTest003 end";
}
}
}