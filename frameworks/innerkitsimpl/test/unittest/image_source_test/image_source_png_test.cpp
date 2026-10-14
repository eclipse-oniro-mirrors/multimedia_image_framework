/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <vector>
#include <fstream>
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_source_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourcePngTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;
namespace OHOS {
namespace Multimedia {

class ImageSourcePngTest : public testing::Test {
public:
    ImageSourcePngTest() {}
    ~ImageSourcePngTest() {}
};

void SampleDecodePngTest(int sampleSize)
{
    if (sampleSize == 0) {
        IMAGE_LOGI("invalid sampleSize");
        ASSERT_EQ(false, true);
    }
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImageInfo imageInfo;
    errorCode = imageSource->GetImageInfo(imageInfo);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = imageInfo.size.width / sampleSize;
    decodeOpts.desiredSize.height = imageInfo.size.height / sampleSize;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map res=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
}

/**
 * @tc.name: PngImageDecode001
 * @tc.desc: Decode png image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct png file path and png format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to png file.
     * @tc.expected: step3. pack pixel map success and the png compress file size equals to PNG_PACK_SIZE.
     */
    int64_t packSize = PackImage("/data/local/tmp/image/test_file.png", std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: PngImageDecode003
 * @tc.desc: Create image source by correct png file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct png file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: PngImageDecode004
 * @tc.desc: Create image source by wrong png file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by wrong png file path and default format hit.
     * @tc.expected: step1. create image source error.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/png/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: PngImageDecode005
 * @tc.desc: Decode png image from buffer source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize("/data/local/tmp/image/test.png", bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = ReadFileToBuffer("/data/local/tmp/image/test.png", buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ImagePacker imagePacker;
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to PNG_PACK_SIZE.
     */
    int64_t packSize = PackImage("/data/local/tmp/image/test_file.jpg", std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: PngImageDecode006
 * @tc.desc: Decode png image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to png file.
     * @tc.expected: step3. pack pixel map success and the png compress file size equals to PNG_PACK_SIZE.
     */
    int64_t packSize = PackImage("/data/test_istream.png", std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: PngImageDecode008
 * @tc.desc: Decode png image multiple times from one ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageDecode008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by png file path.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap1 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1.get(), nullptr);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options again.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    std::unique_ptr<PixelMap> pixelMap2 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1.get(), nullptr);
    /**
     * @tc.steps: step4. compress the pixlel map to jpeg file.
     * @tc.expected: step4. pack pixel map success and the jpeg compress file size equals to PNG_PACK_SIZE.
     */
    int64_t packSize = PackImage("/data/local/tmp/image/test_png_file1.jpg", std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    packSize = PackImage("/data/local/tmp/image/test_png_file2.jpg", std::move(pixelMap2));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: PngImageCrop001
 * @tc.desc: Crop png image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngImageCrop001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create png image source by istream source stream and default format hit
     * @tc.expected: step1. create png image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. crop png image source to pixel map crop options
     * @tc.expected: step2. crop png image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 200;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 40;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(200, pixelMap->GetWidth());
    EXPECT_EQ(40, pixelMap->GetHeight());
}
/**
 * @tc.name: PngNinePatch001
 * @tc.desc: Decoding nine-patch picture
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngNinePatch001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create png image source by istream source stream and default format hit
     * @tc.expected: step1. create png image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.9.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode png image source to pixel map
     * @tc.expected: step2. decode png image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);

    /**
     * @tc.steps: step3. get png nine patch info
     * @tc.expected: step3. get png nine patch info success.
     */
    const NinePatchInfo &ninePatch = imageSource->GetNinePatchInfo();
    ASSERT_EQ(ninePatch.ninePatch, nullptr);
}

/**
 * @tc.name: PngNinePatch002
 * @tc.desc: Decoding non-nine-patch picture
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngNinePatch002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create png image source by istream source stream and default format hit
     * @tc.expected: step1. create png image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode png image source to pixel map
     * @tc.expected: step2. decode png image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);

    /**
     * @tc.steps: step3. get png nine patch info
     * @tc.expected: step3. get png nine patch info failed.
     */
    const NinePatchInfo &ninePatch = imageSource->GetNinePatchInfo();
    ASSERT_EQ(ninePatch.ninePatch, nullptr);
}

/**
 * @tc.name: PngNinePatch003
 * @tc.desc: Decoding nine-patch picture with scale and pixelformat convert
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngNinePatch003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create png image source by istream source stream and default format hit
     * @tc.expected: step1. create png image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.9.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. scale and convert pixelformat png image source to pixel map
     * @tc.expected: step2. scale and convert pixelformat png image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = { 186, 160 };
    decodeOpts.desiredPixelFormat = PixelFormat::RGB_565;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);

    /**
     * @tc.steps: step3. get png nine patch info
     * @tc.expected: step3. get png nine patch info success.
     */
    const NinePatchInfo &ninePatch = imageSource->GetNinePatchInfo();
    ASSERT_EQ(ninePatch.ninePatch, nullptr);
}

/**
 * @tc.name: PngGetEncodedFormat001
 * @tc.desc: Decoding non-nine-patch picture
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngGetEncodedFormat001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create png image source by istream source stream and default format hit
     * @tc.expected: step1. create png image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get imageInfo encodedformat from imageSource.
     * @tc.expected: step2. get imageInfo encodedformat success.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    EXPECT_EQ(imageinfo1.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourcePngTest: PngGetEncodedFormat001 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. get imageInfo encodedformat success.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourcePngTest: PngGetEncodedFormat001 imageinfo2:" << imageinfo2.encodedFormat;
}

/**
 * @tc.name: PngSampleDecodeTest001
 * @tc.desc: test sample decode png
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngSampleDecodeTest001, TestSize.Level3)
{
    SampleDecodePngTest(1);
}

/**
 * @tc.name: PngSampleDecodeTest002
 * @tc.desc: test sample decode png
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngSampleDecodeTest002, TestSize.Level3)
{
    SampleDecodePngTest(2);
}

/**
 * @tc.name: PngSampleDecodeTest003
 * @tc.desc: test sample decode png
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngSampleDecodeTest003, TestSize.Level3)
{
    SampleDecodePngTest(4);
}

/**
 * @tc.name: PngSampleDecodeTest004
 * @tc.desc: test sample decode png
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngSampleDecodeTest004, TestSize.Level3)
{
    SampleDecodePngTest(8);
}

/**
 * @tc.name: PngDecodeCompletedIncrementalSource
 * @tc.desc: Decode a complete image supplied in chunks without legacy incremental decoding.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePngTest, PngDecodeCompletedIncrementalSource, TestSize.Level3)
{
    size_t bufferSize = 0;
    ASSERT_TRUE(ImageUtils::GetFileSize("/data/local/tmp/image/test.png", bufferSize));
    ASSERT_GT(bufferSize, 1U);
    std::vector<uint8_t> buffer(bufferSize);
    ASSERT_TRUE(ReadFileToBuffer("/data/local/tmp/image/test.png", buffer.data(), buffer.size()));

    uint32_t errorCode = SUCCESS;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    auto imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);
    const size_t firstChunkSize = buffer.size() / 2;
    ASSERT_EQ(imageSource->UpdateData(buffer.data(), firstChunkSize, false), SUCCESS);
    ASSERT_EQ(imageSource->UpdateData(buffer.data() + firstChunkSize,
        buffer.size() - firstChunkSize, true), SUCCESS);

    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    auto referenceSource = ImageSource::CreateImageSource("/data/local/tmp/image/test.png", SourceOptions(), errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(referenceSource, nullptr);
    auto referencePixelMap = referenceSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(referencePixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetWidth(), referencePixelMap->GetWidth());
    EXPECT_EQ(pixelMap->GetHeight(), referencePixelMap->GetHeight());
    EXPECT_EQ(pixelMap->GetPixelFormat(), referencePixelMap->GetPixelFormat());
}

} // namespace Multimedia
} // namespace OHOS