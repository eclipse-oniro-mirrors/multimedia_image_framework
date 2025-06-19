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
#define private public
#define protected public
#include <gtest/gtest.h>
#include <fstream>
#include "image_source.h"
#include "image_source_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "pixel_map.h"
#include "post_proc.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_JPG_PATH_EXACTSIZE = "/data/local/tmp/image/800-500.jpg";
static constexpr int32_t IMAGE_INPUT_JPG_WIDTH = 800;
static constexpr int32_t IMAGE_INPUT_JPG_HEIGHT = 500;
static const int32_t NUM_1 = 1;
static const int32_t NUM_2 = 2;
static const int32_t NUM_NEGATIVE_1 = -1;

class PostProcTest : public testing::Test {
public:
    PostProcTest() {}
    ~PostProcTest() {}
};

/**
 * @tc.name: PostProcTest001
 * @tc.desc: test DecodePostProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest001 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::NO_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest001 end";
}

/**
 * @tc.name: PostProcTest003
 * @tc.desc: test DecodePostProc ROTATE_CHANGE
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest003 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::ROTATE_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest003 end";
}

/**
 * @tc.name: PostProcTest004
 * @tc.desc: test DecodePostProc SIZE_CHANGE
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest004 start";

    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::SIZE_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest004 end";
}

/**
 * @tc.name: PostProcTest005
 * @tc.desc: test DecodePostProc DENSITY_CHANGE
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest005 start";

    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::DENSITY_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest005 end";
}

/**
 * @tc.name: PostProcTest08
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest008 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 100;
    targetSize.height = 200;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest008 end";
}

/**
 * @tc.name: PostProcTest009
 * @tc.desc: test CenterScale size is 0 or -1
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest009 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 0;
    targetSize.height = -1;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_NE(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest009 end";
}

/**
 * @tc.name: PostProcTest0010
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0010 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 200;
    targetSize.height = 400;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0010 end";
}

/**
 * @tc.name: PostProcTest0011
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0011 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 600;
    targetSize.height = 900;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0011 end";
}

/**
 * @tc.name: PostProcTest0012
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0012 start";
    int32_t width = 200;
    int32_t height = 300;
    InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 400;
    targetSize.height = 600;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0012 end";
}

/**
 * @tc.name: PostProcTest0013
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0013 start";
    int32_t width = 200;
    int32_t height = 300;
    InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 100;
    targetSize.height = 600;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0013 end";
}

/**
 * @tc.name: PostProcTest0014
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0014 start";
    int32_t width = 200;
    int32_t height = 300;
    InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    Size targetSize;
    targetSize.width = 400;
    targetSize.height = 200;
    bool ret = postProc.CenterScale(targetSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0014 end";
}

/**
 * @tc.name: PostProcTest0016
 * @tc.desc: test ConvertProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0016 start";
    Rect cropRect;
    cropRect.top = 3;
    cropRect.width = 100;
    cropRect.left = 3;
    cropRect.height = 200;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    ImageInfo srcImageInfo;
    ImageInfo dstImageInfo;
    pixelMap->GetImageInfo(srcImageInfo);
    uint32_t ret = postProc.ConvertProc(cropRect, dstImageInfo, *pixelMap, srcImageInfo);
    ASSERT_NE(ret, -1);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0016 end";
}

/**
 * @tc.name: PostProcTest0017
 * @tc.desc: test ConvertProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0016 start";
    Rect cropRect;
    cropRect.top = 0;
    cropRect.width = 100;
    cropRect.left = 0;
    cropRect.height = 200;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 0;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 0;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 100;
    decodeOpts.desiredSize.height = 200;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    ImageInfo srcImageInfo;
    ImageInfo dstImageInfo;
    pixelMap->GetImageInfo(srcImageInfo);
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    uint32_t ret = postProc.ConvertProc(cropRect, dstImageInfo, *pixelMap, srcImageInfo);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0016 end";
}

/**
 * @tc.name: PostProcTest0018
 * @tc.desc: test ConvertProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0018 start";
    Rect cropRect;
    cropRect.top = 0;
    cropRect.width = 100;
    cropRect.left = 0;
    cropRect.height = 200;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 100;
    decodeOpts.desiredSize.height = 200;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    ImageInfo srcImageInfo;
    ImageInfo dstImageInfo;
    pixelMap->GetImageInfo(srcImageInfo);
    srcImageInfo.pixelFormat = PixelFormat::RGB_888;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    uint32_t ret = postProc.ConvertProc(cropRect, dstImageInfo, *pixelMap, srcImageInfo);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0018 end";
}

/**
 * @tc.name: PostProcTest0027
 * @tc.desc:RotatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0027 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    bool ret = postProc.RotatePixelMap(decodeOpts.rotateDegrees, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0027 end";
}

/**
 * @tc.name: PostProcTest0028
 * @tc.desc:ScalePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0028 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    bool ret = postProc.ScalePixelMap(decodeOpts.desiredSize, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0028 end";
}

HWTEST_F(PostProcTest, PostProcTest0030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0030 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    float scaleX = 1.0;
    float scaleY = 1.0;
    bool ret = postProc.ScalePixelMap(scaleX, scaleY, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0030 end";
}

/**
 * @tc.name: PostProcTest0031
 * @tc.desc: test ScalePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0031 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    float scaleX = 0.1;
    float scaleY = 0.1;
    bool ret = postProc.ScalePixelMap(scaleX, scaleY, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0031 end";
}

/**
 * @tc.name: PostProcTest0032
 * @tc.desc: test TranslatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0032start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    PostProc postProc;
    float tX = 3.0;
    float tY = 1.0;
    bool ret = postProc.TranslatePixelMap(tX, tY, *pixelMap);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0032 end";
}

/**
 * @tc.name: PostProcTest0033
 * @tc.desc: test DecodePostProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0033 start";
    DecodeOptions decodeOpts;
    PixelMap pixelMap;
    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::NO_CHANGE;
    uint32_t errorCode = postProc.DecodePostProc(decodeOpts, pixelMap, finalOutputStep);
    ASSERT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0033 end";
}

/**
 * @tc.name: PostProcTest0034
 * @tc.desc: test DecodePostProc MemoryUsagePreference is LOW_RAM
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0034 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.preference = MemoryUsagePreference::LOW_RAM;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    imageInfo.baseDensity = 1;
    imageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    pixelMap->SetImageInfo(imageInfo);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::DENSITY_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0034 end";
}

/**
 * @tc.name: PostProcTest0035
 * @tc.desc: test DecodePostProc MemoryUsagePreference is DEFAULT
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0035 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    imageInfo.baseDensity = 1;
    imageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    pixelMap->SetImageInfo(imageInfo);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::DENSITY_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0035 end";
}

/**
 * @tc.name: PostProcTest0036
 * @tc.desc: test DecodePostProc AlphaType is IMAGE_ALPHA_TYPE_UNPREMUL
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0036 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    imageInfo.baseDensity = 1;
    imageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    pixelMap->SetImageInfo(imageInfo);

    PostProc postProc;
    FinalOutputStep finalOutputStep = FinalOutputStep::DENSITY_CHANGE;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), finalOutputStep);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0036 end";
}

/**
 * @tc.name: PostProcTest0037
 * @tc.desc: test CenterScale
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0037 start";
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    pixelMap->imageInfo_.size.width = 1;
    pixelMap->imageInfo_.size.height = 1;
    pixelMap->isAstc_ = true;

    PostProc postProc;
    Size size;
    size.width = 2;
    size.height = 2;
    bool ret = postProc.CenterScale(size, *(pixelMap.get()));
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0037 end";
}

/**
 * @tc.name: PostProcTest0038
 * @tc.desc: test CheckScanlineFilter
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0038 start";
    Rect cropRect;
    ImageInfo dstImageInfo;
    PixelMap pixelMap;
    int32_t pixelBytes = 0;
    ScanlineFilter scanlineFilter;
    PostProc postProc;
    postProc.decodeOpts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    uint32_t ret = postProc.CheckScanlineFilter(cropRect, dstImageInfo, pixelMap, pixelBytes, scanlineFilter);
    ASSERT_EQ(ret, ERR_IMAGE_CROP);
    postProc.decodeOpts_.allocatorType = AllocatorType::DEFAULT;
    dstImageInfo.size.width = 0;
    ret = postProc.CheckScanlineFilter(cropRect, dstImageInfo, pixelMap, pixelBytes, scanlineFilter);
    ASSERT_EQ(ret, ERR_IMAGE_CROP);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0038 end";
}

/**
 * @tc.name: PostProcTest0039
 * @tc.desc: test PixelConvertProc
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PostProcTest0039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0039 start";
    ImageInfo dstImageInfo;
    PixelMap pixelMap;
    ImageInfo srcImageInfo;
    PostProc postProc;
    dstImageInfo.pixelFormat = PixelFormat::UNKNOWN;
    uint32_t ret = postProc.PixelConvertProc(dstImageInfo, pixelMap, srcImageInfo);
    ASSERT_EQ(ret, ERR_IMAGE_CROP);
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    dstImageInfo.size.width = 1;
    dstImageInfo.size.height = 1;
    srcImageInfo.pixelFormat = PixelFormat::UNKNOWN;
    postProc.decodeOpts_.allocatorType = AllocatorType::HEAP_ALLOC;
    ret = postProc.PixelConvertProc(dstImageInfo, pixelMap, srcImageInfo);
    ASSERT_EQ(ret, ERR_IMAGE_CROP);
    GTEST_LOG_(INFO) << "PostProcTest: PostProcTest0039 end";
}

/**
 * @tc.name: CenterDisplayTest001
 * @tc.desc: test CenterDisplay
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, CenterDisplayTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: CenterDisplayTest001 start";
    PostProc postProc;
    PixelMap pixelMap;
    int32_t srcWidth = 0;
    int32_t srcHeight = 0;
    int32_t targetWidth = 0;
    int32_t targetHeight = 0;
    bool ret = postProc.CenterDisplay(pixelMap, srcWidth, srcHeight, targetWidth, targetHeight);
    ASSERT_EQ(ret, false);
    targetWidth = 1;
    targetHeight = 1;
    pixelMap.imageInfo_.pixelFormat = PixelFormat::ALPHA_8;
    pixelMap.allocatorType_ =  AllocatorType::HEAP_ALLOC;
    ret = postProc.CenterDisplay(pixelMap, srcWidth, srcHeight, targetWidth, targetHeight);
    ASSERT_EQ(ret, true);
    pixelMap.allocatorType_ =  AllocatorType::DMA_ALLOC;
    ret = postProc.CenterDisplay(pixelMap, srcWidth, srcHeight, targetWidth, targetHeight);
    ASSERT_EQ(ret, true);
    pixelMap.allocatorType_ =  AllocatorType::DEFAULT;
    ret = postProc.CenterDisplay(pixelMap, srcWidth, srcHeight, targetWidth, targetHeight);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PostProcTest: CenterDisplayTest001 end";
}

/**
 * @tc.name: TransformTest001
 * @tc.desc: test Transform
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, TransformTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: TransformTest001 start";
    PostProc postProc;
    BasicTransformer trans;
    PixmapInfo input;
    PixelMap pixelMap;
    pixelMap.isTransformered_ = true;
    bool ret = postProc.Transform(trans, input, pixelMap);
    ASSERT_EQ(ret, false);
    pixelMap.isTransformered_ = false;
    postProc.decodeOpts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    ret = postProc.Transform(trans, input, pixelMap);
    ASSERT_EQ(ret, false);
    postProc.decodeOpts_.allocatorType = AllocatorType::HEAP_ALLOC;
    ret = postProc.Transform(trans, input, pixelMap);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PostProcTest: TransformTest001 end";
}

/**
 * @tc.name: ScalePixelMapExTest001
 * @tc.desc: test ScalePixelMapEx
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, ScalePixelMapExTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: ScalePixelMapExTest001 start";
    PostProc postProc;
    Size desiredSize;
    PixelMap pixelMap;
    AntiAliasingOption option = AntiAliasingOption::NONE;
    pixelMap.imageInfo_.size.width = 0;
    pixelMap.imageInfo_.size.height = 0;
    bool ret = postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    ASSERT_EQ(ret, false);
    pixelMap.imageInfo_.size.width = 1;
    pixelMap.imageInfo_.size.height = 1;
    pixelMap.data_ = new uint8_t;
    ret = postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    ASSERT_EQ(ret, false);
    pixelMap.imageInfo_.pixelFormat = PixelFormat::ALPHA_8;
    pixelMap.allocatorType_ = AllocatorType::CUSTOM_ALLOC;
    ret = postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    ASSERT_EQ(ret, false);
    pixelMap.allocatorType_ = AllocatorType::SHARE_MEM_ALLOC;
    AbsMemory absMemory;
    absMemory.data.data = new uint8_t;
    ret = postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    ASSERT_EQ(ret, false);
    delete pixelMap.data_;
    GTEST_LOG_(INFO) << "PostProcTest: ScalePixelMapExTest001 end";
}

/**
 * @tc.name: DecodePostProc001
 * @tc.desc: Vertify that DecodePostProc when cropAndScaleStrategy is scale first.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, DecodePostProc001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: DecodePostProc001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = Size{.width = IMAGE_INPUT_JPG_WIDTH, .height = IMAGE_INPUT_JPG_HEIGHT};
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;

    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;

    PostProc postProc;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), FinalOutputStep::NO_CHANGE);
    ASSERT_EQ(errorCode, ERR_IMAGE_TRANSFORM);
    GTEST_LOG_(INFO) << "PostProcTest: DecodePostProc001 end";
}

/**
 * @tc.name: DecodePostProc002
 * @tc.desc: Vertify that DecodePostProc when finalOutputStep is DENSITY_CHANGE.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, DecodePostProc002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: DecodePostProc002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = Size{.width = IMAGE_INPUT_JPG_WIDTH, .height = IMAGE_INPUT_JPG_HEIGHT};
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;

    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    decodeOpts.desiredSize = Size{};
    decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::CROP_FIRST;
    pixelMap->imageInfo_.baseDensity = NUM_2;

    PostProc postProc;
    errorCode = postProc.DecodePostProc(decodeOpts, *(pixelMap.get()), FinalOutputStep::DENSITY_CHANGE);
    ASSERT_EQ(errorCode, ERR_IMAGE_TRANSFORM);
    GTEST_LOG_(INFO) << "PostProcTest: DecodePostProc002 end";
}

/**
 * @tc.name: GetDstImageInfo001
 * @tc.desc: Vertify that GetDstImageInfo when preference is LOW_RAW and alphaType is IMAGE_ALPHA_TYPE_OPAQUE.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, GetDstImageInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: GetDstImageInfo001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = Size{.width = IMAGE_INPUT_JPG_WIDTH, .height = IMAGE_INPUT_JPG_HEIGHT};
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;

    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);

    decodeOpts.desiredPixelFormat = PixelFormat::UNKNOWN;
    decodeOpts.preference = MemoryUsagePreference::LOW_RAM;

    ImageInfo srcImageInfo, dstImageInfo;
    pixelMap->GetImageInfo(srcImageInfo);
    srcImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    pixelMap->imageInfo_.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;

    PostProc postProc;
    postProc.GetDstImageInfo(decodeOpts, *(pixelMap.get()), srcImageInfo, dstImageInfo);
    ASSERT_EQ(dstImageInfo.pixelFormat, PixelFormat::RGB_565);
    ASSERT_EQ(dstImageInfo.alphaType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    GTEST_LOG_(INFO) << "PostProcTest: GetDstImageInfo001 end";
}

/**
 * @tc.name: CenterScaleTest001
 * @tc.desc: Test CenterScale when targetWidth and targetHeight are valid or not.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, CenterScaleTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: CenterScaleTest001 start";
    Size size;
    PixelMap pixelMap;
    pixelMap.imageInfo_.size.height = NUM_1;
    pixelMap.imageInfo_.size.width = NUM_1;
    size.width = 0;
    size.height = 0;
    PostProc postProc;

    bool ret = postProc.CenterScale(size, pixelMap);
    EXPECT_FALSE(ret);

    size.width = NUM_1;
    size.height = 0;
    ret = postProc.CenterScale(size, pixelMap);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "PostProcTest: CenterScaleTest001 end";
}

/**
 * @tc.name: PixelConvertProcTest001
 * @tc.desc: Test PixelConvertProc when pixelBytes is 0.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PixelConvertProcTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PixelConvertProcTest001 start";
    ImageInfo dstImageInfo;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    ImageInfo srcImageInfo;
    srcImageInfo.size.height = NUM_1;
    srcImageInfo.size.width = NUM_1;
    srcImageInfo.pixelFormat = PixelFormat::UNKNOWN;
    PixelMap pixelMap;
    PostProc postProc;
    postProc.decodeOpts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;

    uint32_t ret = postProc.PixelConvertProc(dstImageInfo, pixelMap, srcImageInfo);
    EXPECT_EQ(ret, ERR_IMAGE_CROP);
    GTEST_LOG_(INFO) << "PostProcTest: PixelConvertProcTest001 end";
}

/**
 * @tc.name: PixelConvertProcTest002
 * @tc.desc: Test PixelConvertProc when pixelMap SetImageInfo failed.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, PixelConvertProcTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: PixelConvertProcTest002 start";
    ImageInfo dstImageInfo;
    dstImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    ImageInfo srcImageInfo;
    srcImageInfo.size.height = NUM_1;
    srcImageInfo.size.width = NUM_1;
    srcImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    PixelMap pixelMap;
    pixelMap.pixelBytes_ = 0;
    PostProc postProc;
    postProc.decodeOpts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;

    uint32_t ret = postProc.PixelConvertProc(dstImageInfo, pixelMap, srcImageInfo);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PostProcTest: PixelConvertProcTest002 end";
}

/**
 * @tc.name: ValidCropValueTest001
 * @tc.desc: Test ValidCropValue when reset the width and height of rect success or not.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, ValidCropValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: ValidCropValueTest001 start";
    Size size;
    size.height = NUM_NEGATIVE_1;
    size.width = NUM_NEGATIVE_1;
    Rect rect;
    rect.top = NUM_1;
    rect.left = NUM_1;

    PostProc postProc;
    CropValue ret = postProc.ValidCropValue(rect, size);
    EXPECT_EQ(ret, CropValue::INVALID);

    size.height = NUM_1;
    size.width = NUM_1;
    rect.height = NUM_NEGATIVE_1;
    rect.width = NUM_NEGATIVE_1;
    ret = postProc.ValidCropValue(rect, size);
    EXPECT_EQ(ret, CropValue::INVALID);
    GTEST_LOG_(INFO) << "PostProcTest: ValidCropValueTest001 end";
}

/**
 * @tc.name: GetScaleFormatTest001
 * @tc.desc: Test GetScaleFormat when didn't find formatPair in PIXEL_FORMAT_MAP.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, GetScaleFormatTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: GetScaleFormatTest001 start";
    PostProc postProc;
    Size desiredSize;
    PixelMap pixelMap;
    pixelMap.imageInfo_.size.height = NUM_1;
    pixelMap.imageInfo_.size.width = NUM_1;
    pixelMap.data_ = new uint8_t;
    pixelMap.imageInfo_.pixelFormat = PixelFormat::EXTERNAL_MAX;
    AntiAliasingOption option = AntiAliasingOption::NONE;
    bool ret  = postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    ASSERT_EQ(ret, false);
    delete pixelMap.data_;
    GTEST_LOG_(INFO) << "PostProcTest: GetScaleFormatTest001 end";
}

/**
 * @tc.name: CheckPixelMapSLRTest001
 * @tc.desc: Test CheckPixelMapSLR when pixelFormat is not RGBA_8888 or desiredSize is same as srcSize or not.
 * @tc.type: FUNC
 */
HWTEST_F(PostProcTest, CheckPixelMapSLRTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PostProcTest: CheckPixelMapSLRTest001 start";
    Size desiredSize;
    PixelMap pixelMap;
    pixelMap.imageInfo_.pixelFormat = PixelFormat::ALPHA_8;
    pixelMap.pixelBytes_ = 0;
    PostProc postProc;

    bool ret = postProc.ScalePixelMapWithSLR(desiredSize, pixelMap, false);
    EXPECT_FALSE(ret);

    pixelMap.imageInfo_.size.width = NUM_1;
    pixelMap.imageInfo_.size.height = NUM_1;
    desiredSize.width = NUM_1;
    desiredSize.height = NUM_1;
    ret = postProc.ScalePixelMapWithSLR(desiredSize, pixelMap, false);
    EXPECT_FALSE(ret);

    desiredSize.width = NUM_2;
    desiredSize.height = NUM_1;
    ret = postProc.ScalePixelMapWithSLR(desiredSize, pixelMap, false);
    EXPECT_FALSE(ret);

    desiredSize.width = NUM_1;
    desiredSize.height = NUM_2;
    ret = postProc.ScalePixelMapWithSLR(desiredSize, pixelMap, false);
    EXPECT_FALSE(ret);

    desiredSize.width = NUM_2;
    desiredSize.height = NUM_2;
    ret = postProc.ScalePixelMapWithSLR(desiredSize, pixelMap, false);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "PostProcTest: CheckPixelMapSLRTest001 end";
}
}
}