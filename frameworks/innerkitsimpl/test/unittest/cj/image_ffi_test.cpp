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
#include "image_ffi.h"

namespace OHOS {
namespace Multimedia {
using namespace testing::ext;
using namespace OHOS::Media;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const char* KEY = "key";
static const char* VALUE = "value";

class ImageFfiTest : public testing::Test {
public:
    ImageFfiTest() {}
    ~ImageFfiTest() {}
};

/**
 * @tc.name: ImageFfiTest001
 * @tc.desc: test ImageSourceImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageFfiTest, ImageFfiTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest001 start";
    std::string invalidPath = "";
    uint32_t errCode;
    int64_t imageSourceId = FfiOHOSCreateImageSourceByPath(const_cast<char*>(invalidPath.c_str()), &errCode);
    FfiOHOSImageSourceGetImageInfo(imageSourceId, 0, &errCode);
    FfiOHOSGetSupportedFormats(imageSourceId, &errCode);
    FfiOHOSGetImageProperty(imageSourceId, const_cast<char*>(KEY), 0, const_cast<char*>(VALUE), &errCode);
    FfiOHOSModifyImageProperty(imageSourceId, const_cast<char*>(KEY), const_cast<char*>(VALUE));
    FfiOHOSGetFrameCount(imageSourceId);
    CSourceOptions opts;
    imageSourceId = FfiOHOSCreateImageSourceByPathWithOption(const_cast<char*>(invalidPath.c_str()), opts, &errCode);
    int fd = 0;
    imageSourceId = FfiOHOSCreateImageSourceByFd(fd, &errCode);
    imageSourceId = FfiOHOSCreateImageSourceByFdWithOption(fd, opts, &errCode);
    const uint32_t size = 10;
    uint8_t data[size] = {0};
    imageSourceId = FfiOHOSCreateImageSourceByBuffer(&data[0], size, &errCode);
    imageSourceId = FfiOHOSCreateImageSourceByRawFile(fd, 0, 0, opts, &errCode);
    imageSourceId = FfiOHOSCreateImageSourceByBufferWithOption(&data[0], size, opts, &errCode);
    imageSourceId = FfiOHOSCreateIncrementalSource(&data[0], size, opts, &errCode);
    UpdateDataInfo info;
    FfiOHOSUpdateData(imageSourceId, info);
    CDecodingOptions decodeOpts;
    FfiOHOSImageSourceCreatePixelMap(imageSourceId, 0, decodeOpts);
    FfiOHOSImageSourceGetDelayTime(imageSourceId, &errCode);
    FfiOHOSRelease(imageSourceId);
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest001 end";
}

/**
 * @tc.name: ImageFfiTest002
 * @tc.desc: test ImageSourceImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageFfiTest, ImageFfiTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest002 start";
    uint32_t errCode;
    char* jpgPath = const_cast<char*>(IMAGE_JPEG_PATH.c_str());
    int64_t imageSourceId = FfiOHOSCreateImageSourceByPath(jpgPath, &errCode);
    FfiOHOSImageSourceGetImageInfo(imageSourceId, 0, &errCode);
    FfiOHOSGetSupportedFormats(imageSourceId, &errCode);
    FfiOHOSGetImageProperty(imageSourceId, const_cast<char*>(KEY), 0, const_cast<char*>(VALUE), &errCode);
    FfiOHOSModifyImageProperty(imageSourceId, const_cast<char*>(KEY), const_cast<char*>(VALUE));
    FfiOHOSGetFrameCount(imageSourceId);
    CDecodingOptions decodeOpts;
    FfiOHOSImageSourceCreatePixelMap(imageSourceId, 0, decodeOpts);
    FfiOHOSImageSourceGetDelayTime(imageSourceId, &errCode);
    CSourceOptions opts;
    imageSourceId = FfiOHOSCreateImageSourceByPathWithOption(jpgPath, opts, &errCode);
    UpdateDataInfo info;
    FfiOHOSUpdateData(imageSourceId, info);
    FfiOHOSRelease(imageSourceId);
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest002 end";
}

/**
 * @tc.name: ImageFfiTest003
 * @tc.desc: test ImageReceiverImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageFfiTest, ImageFfiTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest003 start";
    int64_t imageReceiverId = FfiOHOSCreateImageReceiver(0, 0, 0, 0);
    CSize size;
    FfiOHOSReceiverGetSize(imageReceiverId, &size);
    int32_t capacity;
    FfiOHOSReceiverGetCapacity(imageReceiverId, &capacity);
    int32_t format;
    FfiOHOSReceiverGetFormat(imageReceiverId, &format);
    FfiOHOSGetReceivingSurfaceId(imageReceiverId);
    int64_t imageId = FfiOHOSReadNextImage(imageReceiverId);
    imageId = FfiOHOSReadLatestImage(imageReceiverId);
    CRegion region;
    FfiOHOSImageGetClipRect(imageId, &region);
    FfiOHOSImageGetSize(imageId, &size);
    FfiOHOSImageGetFormat(imageId, &format);
    CRetComponent component;
    FfiOHOSGetComponent(imageId, 0, &component);
    FfiOHOSImageRelease(imageId);
    FfiOHOSReceiverRelease(imageReceiverId);
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest003 end";
}

/**
 * @tc.name: ImageFfiTest004
 * @tc.desc: test ImageReceiverImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageFfiTest, ImageFfiTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest004 start";
    int64_t imageReceiverId = FfiOHOSCreateImageReceiver(100, 100, 2000, 8);
    CSize size;
    FfiOHOSReceiverGetSize(imageReceiverId, &size);
    int32_t capacity;
    FfiOHOSReceiverGetCapacity(imageReceiverId, &capacity);
    int32_t format;
    FfiOHOSReceiverGetFormat(imageReceiverId, &format);
    FfiOHOSGetReceivingSurfaceId(imageReceiverId);
    int64_t imageId = FfiOHOSReadNextImage(imageReceiverId);
    imageId = FfiOHOSReadLatestImage(imageReceiverId);
    CRegion region;
    FfiOHOSImageGetClipRect(imageId, &region);
    FfiOHOSImageGetSize(imageId, &size);
    FfiOHOSImageGetFormat(imageId, &format);
    CRetComponent component;
    FfiOHOSGetComponent(imageId, 0, &component);
    FfiOHOSImageRelease(imageId);
    FfiOHOSReceiverRelease(imageReceiverId);
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest004 end";
}

/**
 * @tc.name: ImageFfiTest005
 * @tc.desc: test ImageReceiverImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageFfiTest, ImageFfiTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest005 start";
    int64_t imageCreatorId = FFiOHOSImageCreatorConstructor(0, 0, 0, 0);
    FFiOHOSImageCreatorGetCapacity(imageCreatorId);
    FFiOHOSImageCreatorGetformat(imageCreatorId);
    uint32_t errCode;
    FFiOHOSImageCreatorDequeueImage(imageCreatorId, &errCode);
    FFiOHOSImageCreatorQueueImage(imageCreatorId, 0);
    FFiOHOSImageCreatorRelease(imageCreatorId);
    imageCreatorId = FFiOHOSImageCreatorConstructor(100, 100, 2000, 8);
    FFiOHOSImageCreatorGetCapacity(imageCreatorId);
    FFiOHOSImageCreatorGetformat(imageCreatorId);
    FFiOHOSImageCreatorDequeueImage(imageCreatorId, &errCode);
    FFiOHOSImageCreatorQueueImage(imageCreatorId, 0);
    FFiOHOSImageCreatorRelease(imageCreatorId);
    GTEST_LOG_(INFO) << "ImageFfiTest: ImageFfiTest005 end";
}
}
}