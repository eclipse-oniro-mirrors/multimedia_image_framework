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
#include <fstream>
#include "post_proc.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "hilog/log.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
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
}
}