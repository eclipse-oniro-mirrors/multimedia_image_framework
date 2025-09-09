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
#define private public
#define protected public
#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>
#include "image/abs_image_decoder.h"
#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_source_util.h"
#include "incremental_source_stream.h"
#include "istream_source_stream.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "source_stream.h"
#include "image_source.h"
#include "buffer_source_stream.h"
#include "file_source_stream.h"
#include "memory_manager.h"
#include "mock_data_stream.h"
#include "mock_abs_image_decoder.h"
#include "exif_metadata.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_OUTPUT_JPEG_PATH = "/data/local/tmp/image/test_out.jpg";
static const std::string IMAGE_INPUT_ICO_PATH = "/data/local/tmp/image/test.ico";
static const std::string IMAGE_INPUT_HEIF_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_INPUT_JPEG_HDR_PATH = "/data/local/tmp/image/hdr.jpg";
static const std::string IMAGE_INPUT_JPEG_BROKEN_ONE = "/data/local/tmp/image/test_jpeg_broken_one.jpg";
static const std::string IMAGE_INPUT_JPEG_BROKEN_TWO = "/data/local/tmp/image/test_jpeg_broken_two.jpg";
static const std::string IMAGE_URL_PREFIX = "data:image/";
static const std::string IMAGE_INPUT_JPG_PATH_EXACTSIZE = "/data/local/tmp/image/800-500.jpg";
static const std::string IMAGE_JPG_THREE_GAINMAP_HDR_PATH = "/data/local/tmp/image/three_gainmap_hdr.jpg";
static const std::string IMAGE_HEIC_THREE_GAINMAP_HDR_PATH = "/data/local/tmp/image/three_gainmap_hdr.heic";
static const std::string IMAGE_GIF_LARGE_SIZE_PATH = "/data/local/tmp/image/fake_large_size_test.gif";  // 50000x50000
static const std::string IMAGE_JPG_LARGE_SIZE_PATH = "/data/local/tmp/image/fake_large_size_test.jpg";  // 30000x30000
static const int32_t DECODE_DESIRED_WIDTH = 7500;
static const int32_t DECODE_DESIRED_HEIGHT = 7500;
static const int32_t DESIRED_REGION_WIDTH = 4096;
static const int32_t DESIRED_REGION_HEIGHT = 4096;
static const int32_t DEFAULT_DMA_SIZE = 512 * 512;
static const int32_t NUM_1_MINUS = -1;
static const int32_t IMAGE_INPUT_JPG_WIDTH = 800;
static const int32_t IMAGE_INPUT_JPG_HEIGHT = 500;
static const uint32_t MAX_SOURCE_SIZE = 300 * 1024 * 1024;
static const uint32_t NUM_1 = 1;
static const uint32_t NUM_2 = 2;
static const uint32_t NUM_10 = 10;
static const uint32_t NUM_64 = 64;
static const uint32_t TRUE_SETTING = 0;
static const uint32_t HDR_USE_SHAREMEM = 1;
static const uint32_t SDR_SET_ARGB8888_DMA = 2;
static const uint32_t SCALE_FIRST_SETTING = 1;
static const uint32_t CROP_FIRST_SETTING = 2;
static const uint32_t ASTC_SETTING = 3;

class ImageSourceTest : public testing::Test {
public:
    ImageSourceTest() {}
    ~ImageSourceTest() {}
    void InitDecodeContextTest(PixelFormat srcFormat, PixelFormat desiredFormat);
    void CreatePixelMapUseInvalidOptsTest(uint32_t isAllocatorTypeValid, uint32_t isCropRectValid,
        uint32_t desiredErrorCode = ERR_MEDIA_INVALID_OPERATION);
    void SetAllocatorTypeByParam(uint32_t param, ImageSource* imageSource, DecodeOptions& decodeOpts);
    void SetCropRectByParam(uint32_t param, ImageSource* imageSource, DecodeOptions& decodeOpts);
};

class MockAbsImageFormatAgent : public ImagePlugin::AbsImageFormatAgent {
public:
    MockAbsImageFormatAgent() = default;
    virtual ~MockAbsImageFormatAgent() {}

    std::string GetFormatType() override
    {
        return returnString_;
    }
    uint32_t GetHeaderSize() override
    {
        return returnValue_;
    }
    bool CheckFormat(const void *headerData, uint32_t dataSize) override
    {
        return returnBool_;
    }
private:
    std::string returnString_ = "";
    uint32_t returnValue_ = 0;
    bool returnBool_ = false;
};

class MockDecodeListener : public DecodeListener {
public:
    MockDecodeListener() = default;
    ~MockDecodeListener() {}

    void OnEvent(int event) override
    {
        returnVoid_ = event;
    }
private:
    int returnVoid_;
};

class MockPeerListener : public PeerListener {
public:
    MockPeerListener() = default;
    ~MockPeerListener() {}

    void OnPeerDestory() override
    {
        returnVoid_ = 0;
    }
private:
    int returnVoid_;
};

void ImageSourceTest::InitDecodeContextTest(PixelFormat srcFormat, PixelFormat desiredFormat)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::HEAP_ALLOC;
    decodeOpts.isAppUseAllocator = false;
    decodeOpts.desiredPixelFormat = srcFormat;

    ImageInfo imageInfo;
    ImagePlugin::PlImageInfo plImageInfo;
    imageSource->sourceHdrType_ = ImageHdrType::HDR_VIVID_SINGLE;
    auto ret = imageSource->InitDecodeContext(decodeOpts, imageInfo, imageSource->preference_,
        false, plImageInfo);
    ASSERT_EQ(ret.pixelFormat, desiredFormat);
}

void ImageSourceTest::SetAllocatorTypeByParam(uint32_t param, ImageSource* imageSource, DecodeOptions& decodeOpts)
{
    switch (param) {
        case TRUE_SETTING:
            imageSource->sourceHdrType_ = ImageHdrType::SDR;
            decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
            decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
            break;
        case HDR_USE_SHAREMEM:
            decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
            decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
            decodeOpts.isAppUseAllocator = true;
            break;
        case SDR_SET_ARGB8888_DMA:
            imageSource->sourceHdrType_ = ImageHdrType::SDR;
            decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
            decodeOpts.desiredPixelFormat = PixelFormat::ARGB_8888;
            break;
        default:
            break;
    };
}

void ImageSourceTest::SetCropRectByParam(uint32_t param, ImageSource* imageSource, DecodeOptions& decodeOpts)
{
    switch (param) {
        case TRUE_SETTING:
            decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::DEFAULT;
            break;
        case SCALE_FIRST_SETTING:
            decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;
            decodeOpts.desiredSize.width = NUM_1;
            break;
        case CROP_FIRST_SETTING:
            decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::CROP_FIRST;
            decodeOpts.CropRect.top = -NUM_1_MINUS;
            decodeOpts.CropRect.left = -NUM_1_MINUS;
            break;
        case ASTC_SETTING:
            imageSource->sourceInfo_.encodedFormat = "image/astc";
            break;
        default:
            break;
    };
}

void ImageSourceTest::CreatePixelMapUseInvalidOptsTest(uint32_t isAllocatorTypeValid,
    uint32_t isCropRectValid, uint32_t desiredErrorCode)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    SetAllocatorTypeByParam(isAllocatorTypeValid, imageSource.get(), decodeOpts);
    SetCropRectByParam(isCropRectValid, imageSource.get(), decodeOpts);

    auto ret = imageSource->CreatePixelMap(0, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, desiredErrorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSupportedFormats001
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSupportedFormats001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: GetSupportedFormats002
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSupportedFormats002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: GetSupportedFormats003
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSupportedFormats003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/test.nrw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::set<std::string> formats;
    if (imageSource != nullptr) {
        uint32_t ret = imageSource->GetSupportedFormats(formats);
        ASSERT_EQ(ret, SUCCESS);
    }
}

/**
 * @tc.name: CreateImageSource003
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const uint8_t *data = nullptr;
    uint32_t size = 1;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    ASSERT_EQ(imageSource, nullptr);
}

/**
 * @tc.name: CreateImageSource004
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource004, TestSize.Level3)
{
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t size = 0;
    uint32_t errorCode = 0;
    const SourceOptions opts;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(buffer, size, opts, errorCode);
    ASSERT_EQ(creimagesource, nullptr);
}

/**
 * @tc.name: CreateImageSource005
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string pathName = IMAGE_INPUT_JPEG_PATH;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    ASSERT_NE(creimagesource, nullptr);
}

/**
 * @tc.name: CreateImageSource006
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource006, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string pathName = "a";
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    ASSERT_EQ(creimagesource, nullptr);
}

/**
 * @tc.name: CreateImageSource007
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource007, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_NE(creimagesource, nullptr);
}

/**
 * @tc.name: CreateImageSource008
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource008, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = 0;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_EQ(creimagesource, nullptr);
}

/**
 * @tc.name: CreateIncrementalImageSource001
 * @tc.desc: test CreateIncrementalImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateIncrementalImageSource001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const IncrementalSourceOptions opts;
    std::unique_ptr<ImageSource> img = ImageSource::CreateIncrementalImageSource(opts, errorCode);
    ASSERT_NE(img, nullptr);
}

/**
 * @tc.name: CreatePixelMapEx001
 * @tc.desc: test CreatePixelMapEx
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapEx001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmapex = imageSource->CreatePixelMapEx(index, opts, errorCode);
    ASSERT_EQ(crepixelmapex, nullptr);
}

/**
 * @tc.name: CreatePixelMapEx002
 * @tc.desc: test CreatePixelMapEx
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapEx002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opt;
    std::unique_ptr<PixelMap> crepixelmapex = imageSource->CreatePixelMapEx(index, opt, errorCode);
    ASSERT_EQ(crepixelmapex, nullptr);
}

/**
 * @tc.name: CreatePixelMapEx003
 * @tc.desc: test CreatePixelMapEx of ico picture resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapEx003, TestSize.Level3)
{
    uint32_t res = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_ICO_PATH, sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
    uint32_t index = 1;
    const DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> crepixelmapex = imageSource->CreatePixelMapEx(index, decodeOpts, res);
    ASSERT_NE(imageSource, nullptr);
}

/**
 * @tc.name: CreatePixelMap001
 * @tc.desc: test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMap001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmap = imageSource->CreatePixelMap(index, opts, errorCode);
    ASSERT_EQ(crepixelmap, nullptr);
}

/**
 * @tc.name: CreatePixelMap002
 * @tc.desc: test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMap002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmap = imageSource->CreatePixelMap(index, opts, errorCode);
    ASSERT_EQ(crepixelmap, nullptr);
}

/**
 * @tc.name: CreateIncrementalPixelMap001
 * @tc.desc: test CreateIncrementalPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateIncrementalPixelMap001, TestSize.Level3)
{
    size_t bufferSize = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    fileRet = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    ASSERT_NE(incPixelMap, nullptr);
}

/**
 * @tc.name: CreateIncrementalPixelMap002
 * @tc.desc: test CreateIncrementalPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateIncrementalPixelMap002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t info = 100;
    DecodeOptions op;
    op.sampleSize = 1;
    std::unique_ptr<PixelMap> incPixelMap = imageSource->CreatePixelMap(info, op, errorCode);
    ASSERT_EQ(incPixelMap, nullptr);
    info = -1;
    op.sampleSize = 0;
    incPixelMap = imageSource->CreatePixelMap(info, op, errorCode);
    ASSERT_EQ(incPixelMap, nullptr);
}

/**
 * @tc.name: UpdateData001
 * @tc.desc: test UpdateData
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, UpdateData001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    DecodeOptions decodeOpts;
    size_t bufferSize = 0;
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    ASSERT_NE(incPixelMap, nullptr);
    uint32_t updateSize = 0;
    srand(time(nullptr));
    bool isCompleted = false;
    while (updateSize < bufferSize) {
        uint32_t updateOnceSize = rand() % 1024;
        if (updateSize + updateOnceSize > bufferSize) {
            updateOnceSize = bufferSize - updateSize;
            isCompleted = true;
        }
        uint32_t ret = imageSource->UpdateData(buffer + updateSize, updateOnceSize, isCompleted);
        ASSERT_EQ(ret, SUCCESS);
        uint8_t decodeProgress = 0;
        incPixelMap->PromoteDecoding(decodeProgress);
        updateSize += updateOnceSize;
    }
}

 /**
  * @tc.name: GetImageInfo001
  * @tc.desc: test GetImageInfo
  * @tc.type: FUNC
  */
HWTEST_F(ImageSourceTest, GetImageInfo001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    ImageInfo imageInfo;
    uint32_t index = 1;
    uint32_t ret = imageSource->GetImageInfo(index, imageInfo);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);
}

 /**
  * @tc.name: GetImageInfo002
  * @tc.desc: test GetImageInfo
  * @tc.type: FUNC
  */
HWTEST_F(ImageSourceTest, GetImageInfo002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    ImageInfo imageInfo;
    uint32_t index = 1;
    uint32_t ret = imageSource->GetImageInfo(index, imageInfo);
    ASSERT_NE(ret, SUCCESS);
}

 /**
  * @tc.name: GetImageInfo003
  * @tc.desc: test GetImageInfo
  * @tc.type: FUNC
  */
HWTEST_F(ImageSourceTest, GetImageInfo003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/jpeg";
    opts.formatHint = IMAGE_ENCODEDFORMAT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    ImageInfo imageInfo;
    uint32_t index = 1;
    imageSource->GetImageInfo(index, imageInfo);
    ASSERT_NE(imageInfo.encodedFormat, IMAGE_ENCODEDFORMAT);
}

/**
 * @tc.name: GetSourceInfo001
 * @tc.desc: test GetSourceInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSourceInfo001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    SourceInfo sourceInfo = imageSource->GetSourceInfo(errorCode);
    ASSERT_NE(&sourceInfo, nullptr);
}

/**
 * @tc.name: RegisterListener001
 * @tc.desc: test RegisterListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RegisterListener001, TestSize.Level3)
{
    PeerListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->RegisterListener(listener);
    ASSERT_EQ(imageSource->listeners_.size(), 0);
}

/**
 * @tc.name: UnRegisterListener001
 * @tc.desc: test UnRegisterListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, UnRegisterListener001, TestSize.Level3)
{
    std::shared_ptr<MockPeerListener> mockPeerListener = std::make_shared<MockPeerListener>();
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->listeners_.insert(mockPeerListener.get());
    ASSERT_EQ(imageSource->listeners_.size(), 1);
    imageSource->UnRegisterListener(mockPeerListener.get());
    ASSERT_EQ(imageSource->listeners_.size(), 0);
}

/**
 * @tc.name: GetDecodeEvent001
 * @tc.desc: test GetDecodeEvent
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetDecodeEvent001, TestSize.Level3)
{
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    imageSource->GetDecodeEvent();
}

/**
 * @tc.name: AddDecodeListener001
 * @tc.desc: test AddDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, AddDecodeListener001, TestSize.Level3)
{
    DecodeListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->AddDecodeListener(listener);
    ASSERT_EQ(imageSource->decodeListeners_.size(), 0);
}

/**
 * @tc.name: RemoveDecodeListener001
 * @tc.desc: test RemoveDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RemoveDecodeListener001, TestSize.Level3)
{
    std::shared_ptr<MockDecodeListener> mockDecodeListener = std::make_shared<MockDecodeListener>();
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->decodeListeners_.insert(mockDecodeListener.get());
    ASSERT_EQ(imageSource->decodeListeners_.size(), 1);
    imageSource->RemoveDecodeListener(mockDecodeListener.get());
    ASSERT_EQ(imageSource->decodeListeners_.size(), 0);
}

/**
 * @tc.name: IsIncrementalSource001
 * @tc.desc: test IsIncrementalSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsIncrementalSource001, TestSize.Level3)
{
    bool isIncrementalSource = false;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    isIncrementalSource = imageSource->IsIncrementalSource();
    ASSERT_EQ(isIncrementalSource, false);
}

/**
 * @tc.name: GetImagePropertyInt001
 * @tc.desc: test GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyInt001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key = "ImageWidth";
    imageSource->GetImagePropertyInt(index, key, value);

    ASSERT_EQ(value, 3456);
}

/**
 * @tc.name: GetImagePropertyInt002
 * @tc.desc: test GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyInt002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 0;
    int32_t value = 0;
    std::string key;
    uint32_t ret = imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: GetImagePropertyString001
 * @tc.desc: test GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyString001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    std::string key = "ImageWidth";
    std::string value;
    imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(value, "3456");
}

/**
 * @tc.name: GetImagePropertyString002
 * @tc.desc: test GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyString002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    std::string key = "";
    std::string value;
    uint32_t ret = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: ModifyImageProperty001
 * @tc.desc: test ModifyImageProperty(index, key, value, path)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    std::string value = "13,4,3";
    std::string key = "GPSLatitude";
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: ModifyImageProperty002
 * @tc.desc: test ModifyImageProperty(index, key, value, fd)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    std::string value;
    std::string key;
    int fd = open("/data/receiver/Receiver_buffer7.jpg", std::fstream::binary | std::fstream::in);
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: ModifyImageProperty003
 * @tc.desc: test ModifyImageProperty(index, key, value, data, size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    uint32_t index = 0;
    std::string value;
    uint8_t *data = nullptr;
    uint32_t size = 0;

    std::string key;
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: GetNinePatchInfo001
 * @tc.desc: test GetNinePatchInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetNinePatchInfo001, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);

    const NinePatchInfo &ninePatch = imageSource->GetNinePatchInfo();
    ASSERT_EQ(ninePatch.ninePatch, nullptr);
}

/**
 * @tc.name: SetMemoryUsagePreference001
 * @tc.desc: test SetMemoryUsagePreference
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, SetMemoryUsagePreference001, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    MemoryUsagePreference preference = MemoryUsagePreference::LOW_RAM;
    imageSource->SetMemoryUsagePreference(preference);
}

/**
 * @tc.name: GetMemoryUsagePreference001
 * @tc.desc: test GetMemoryUsagePreference
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetMemoryUsagePreference001, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    imageSource->GetMemoryUsagePreference();
}

/**
 * @tc.name: GetFilterArea001
 * @tc.desc: test GetFilterArea(filterType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFilterArea001, TestSize.Level3)
{
    int filterType = 0;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(filterType, ranges);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: CreateImageSource001
 * @tc.desc: test CreateImageSource is
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource001, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
}

/**
 * @tc.name: CreateImageSource002
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource002, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.size.width = -1;
    opts.size.height = -1;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
}

/**
 * @tc.name: CreateImageSource009
 * @tc.desc: test CreateImageSource buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource009, TestSize.Level3)
{
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = nullptr;

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: CreateImageSource0010
 * @tc.desc: test CreateImageSource size is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0010, TestSize.Level3)
{
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);

    uint32_t size = 0;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, size, opts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: CreateImageSource0011
 * @tc.desc: test CreateImageSource size is 0 and buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0011, TestSize.Level3)
{
    uint8_t *buffer = nullptr;

    uint32_t size = 0;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, size, opts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: CreateImageSource0012
 * @tc.desc: test CreateImageSource correct fd, file offset and size
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0012, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test_exif.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    off_t fSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    auto filePtr = ImageSource::CreateImageSource(fd, 0, fSize, opts, errorCode);
    ASSERT_NE(filePtr, nullptr);
    close(fd);
}

/**
 * @tc.name: CreateImageSource0013
 * @tc.desc: test CreateImageSource correct fd and file size is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0013, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test_exif.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    auto filePtr = ImageSource::CreateImageSource(fd, 0, 0, opts, errorCode);
    ASSERT_NE(filePtr, nullptr);
    close(fd);
}

/**
 * @tc.name: CreateImageSource0014
 * @tc.desc: test CreateImageSource correct fd and file offset is -1
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0014, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test_exif.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    off_t fSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    const int offset = -1;
    auto filePtr = ImageSource::CreateImageSource(fd, offset, fSize, opts, errorCode);
    ASSERT_EQ(filePtr, nullptr);
    close(fd);
}

/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test CreateImageSource correct fd and file size is 100
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0015, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test_exif.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    const int fSize = 100;
    auto filePtr = ImageSource::CreateImageSource(fd, 0, fSize, opts, errorCode);
    ASSERT_NE(filePtr, nullptr);
    close(fd);
}

/**
 * @tc.name: CreateImageSource0016
 * @tc.desc: test CreateImageSource fd is -1
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource0016, TestSize.Level3)
{
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = -1;
    auto filePtr = ImageSource::CreateImageSource(fd, 0, 100, opts, errorCode);
    ASSERT_EQ(filePtr, nullptr);
}

/**
 * @tc.name: CreateImageSource017
 * @tc.desc: test CreateImageSource of ico picture resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource017, TestSize.Level3)
{
    uint32_t res = 0;
    const SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_ICO_PATH, sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
}

#ifdef IMAGE_PURGEABLE_PIXELMAP
/**
 * @tc.name: CreateImageSource0011
 * @tc.desc: test GetSourceSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSourceSize001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);

    size_t ret = imageSource->GetSourceSize();
    ASSERT_NE(ret, 0);
}
#endif

/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test GetSourceDecodingState
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSourceDecodingState, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    bool isAcquiredImageNum = true;
    imageSource->decodeState_ = SourceDecodingState::SOURCE_ERROR;
    auto ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    imageSource->decodeState_ = SourceDecodingState::UNKNOWN_FORMAT;
    ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, ERR_IMAGE_UNKNOWN_FORMAT);
    imageSource->decodeState_ = SourceDecodingState::UNSUPPORTED_FORMAT;
    ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, ERR_IMAGE_PLUGIN_CREATE_FAILED);
    imageSource->decodeState_ = SourceDecodingState::FILE_INFO_ERROR;
    ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);
}

/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test GetData
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetData001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ImagePlugin::DataStreamBuffer outData;
    size_t size = 0;
    imageSource->sourceStreamPtr_ = nullptr;
    auto ret = imageSource->GetData(outData, size);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test GetData
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetData002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ImagePlugin::DataStreamBuffer outData;
    size_t size = 0;
    auto ret = imageSource->GetData(outData, size);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test GetFormatExtended
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFormatExtended, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    string format = "";
    auto ret = imageSource->GetFormatExtended(format);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test DecodeSourceInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeSourceInfo, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    bool  isAcquiredImageNum = false;
    imageSource->decodeState_ = SourceDecodingState::FILE_INFO_DECODED;
    auto ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, SUCCESS);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test DecodeSourceInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeSourceInfo002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    bool  isAcquiredImageNum = false;
    imageSource->decodeState_ = SourceDecodingState::FORMAT_RECOGNIZED;
    SourceInfo sourceInfo;
    sourceInfo.encodedFormat = "image/astc";
    auto ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_NE(ret, SUCCESS);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test InitMainDecoder
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, InitMainDecoder, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    auto ret = imageSource->InitMainDecoder();
    ASSERT_NE(ret, SUCCESS);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test AddIncrementalContextteDecoder
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, AddIncrementalContext, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    PixelMap pixelMap;
    ImageSource::IncrementalRecordMap::iterator iterator;
    auto ret = imageSource->AddIncrementalContext(pixelMap, iterator);
    ASSERT_NE(ret, SUCCESS);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test ImageSizeChange
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ImageSizeChange, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    int32_t width = 0;
    int32_t height = 0;
    int32_t desiredWidth = 0;
    int32_t desiredHeight = 0;
    bool ret = imageSource->ImageSizeChange(width, height, desiredHeight, desiredWidth);
    ASSERT_EQ(ret, false);
}
/**
 * @tc.name: CreateImageSource0015
 * @tc.desc: test IsASTC
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsASTC, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    const uint8_t *fileData = nullptr;
    size_t fileSize = 10;
    bool ret = imageSource->IsASTC(fileData, fileSize);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CreateImageSourceTest001
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSourceTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    const std::string pathName;
    std::unique_ptr<ImageSource> ret = ImageSource::CreateImageSource(pathName, opts, errorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: CreateImageSourceTest002
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSourceTest002, TestSize.Level3)
{
    const int fd = -1;
    const SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> ret = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetValidImageStatusTest001
 * @tc.desc: test GetValidImageStatus
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetValidImageStatusTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 0;
    ImageDecodingStatus imageDecodingStatus1;
    ImageDecodingStatus imageDecodingStatus2;
    imageSource->imageStatusMap_.insert(std::make_pair(0, imageDecodingStatus1));
    imageSource->imageStatusMap_.insert(std::make_pair(1, imageDecodingStatus2));
    ImageSource::ImageStatusMap::iterator ret = imageSource->GetValidImageStatus(index, errorCode);
    ASSERT_EQ(ret, imageSource->imageStatusMap_.end());
}

/**
 * @tc.name: GetFilterAreaTest002
 * @tc.desc: test GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFilterAreaTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    int privacyType = 0;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    ImageDecodingStatus imageDecodingStatus1;
    ImageDecodingStatus imageDecodingStatus2;
    imageSource->imageStatusMap_.insert(std::make_pair(0, imageDecodingStatus1));
    imageSource->imageStatusMap_.insert(std::make_pair(1, imageDecodingStatus2));
    uint32_t ret = imageSource->GetFilterArea(privacyType, ranges);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);
}

/**
 * @tc.name: GetFinalOutputStepTest001
 * @tc.desc: test GetFinalOutputStep
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFinalOutputStepTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    DecodeOptions opt;
    PixelMap pixelMap;
    bool hasNinePatch = true;
    opt.desiredPixelFormat = PixelFormat::ARGB_8888;
    opt.rotateDegrees = 1;
    FinalOutputStep ret = imageSource->GetFinalOutputStep(opt, pixelMap, hasNinePatch);
    ASSERT_EQ(ret, FinalOutputStep::ROTATE_CHANGE);
    opt.rotateDegrees = 0;
    ret = imageSource->GetFinalOutputStep(opt, pixelMap, hasNinePatch);
    ASSERT_EQ(ret, FinalOutputStep::CONVERT_CHANGE);
}

/**
 * @tc.name: GetFinalOutputStepTest002
 * @tc.desc: test GetFinalOutputStep
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFinalOutputStepTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    DecodeOptions opt;
    PixelMap pixelMap;
    bool hasNinePatch = true;
    opt.desiredPixelFormat = PixelFormat::ARGB_8888;
    pixelMap.imageInfo_.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    pixelMap.imageInfo_.size.height = 1;
    pixelMap.imageInfo_.size.width = 1;
    opt.desiredSize.width = 2;
    opt.desiredSize.height = 2;
    FinalOutputStep ret = imageSource->GetFinalOutputStep(opt, pixelMap, hasNinePatch);
    ASSERT_EQ(ret, FinalOutputStep::SIZE_CHANGE);
    pixelMap.imageInfo_.size.height = 0;
    pixelMap.imageInfo_.size.width = 0;
    opt.desiredSize.width = 0;
    opt.desiredSize.height = 0;
    hasNinePatch = false;
    pixelMap.imageInfo_.baseDensity = 1;
    opt.fitDensity = 2;
    ret = imageSource->GetFinalOutputStep(opt, pixelMap, hasNinePatch);
    ASSERT_EQ(ret, FinalOutputStep::DENSITY_CHANGE);
}

/**
 * @tc.name: ImageConverChangeTest001
 * @tc.desc: test ImageConverChange
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ImageConverChangeTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    Rect cropRect;
    ImageInfo desImageInfo;
    ImageInfo srcImageInfo;
    desImageInfo.pixelFormat = PixelFormat::ARGB_8888;
    bool ret = imageSource->ImageConverChange(cropRect, desImageInfo, srcImageInfo);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: ImageConverChangeTest002
 * @tc.desc: test ImageConverChange
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ImageConverChangeTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    Rect cropRect;
    ImageInfo desImageInfo;
    ImageInfo srcImageInfo;
    bool ret = imageSource->ImageConverChange(cropRect, desImageInfo, srcImageInfo);
    ASSERT_EQ(ret, false);
    cropRect.top = 3;
    ret = imageSource->ImageConverChange(cropRect, desImageInfo, srcImageInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: DecodeBase64Test001
 * @tc.desc: test DecodeBase64
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeBase64Test001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    const char* value = "data:image/";
    const uint8_t *data = reinterpret_cast<const uint8_t *>(value);
    uint32_t size = 0;
    std::unique_ptr<SourceStream> ret = imageSource->DecodeBase64(data, size);
    ASSERT_EQ(ret, nullptr);
    size = 13;
    ret = imageSource->DecodeBase64(data, size);
    ASSERT_EQ(ret, nullptr);
    value = "data:image/\0;base64,";
    data = reinterpret_cast<const uint8_t *>(value);
    ret = imageSource->DecodeBase64(data, size);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: ConvertYUV420ToRGBATest001
 * @tc.desc: test ConvertYUV420ToRGBA
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ConvertYUV420ToRGBATest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint8_t *data = nullptr;
    uint32_t size = 0;
    bool isSupportOdd = false;
    bool isAddUV = false;
    uint32_t error = 0;
    imageSource->sourceOptions_.size.width = 1;
    bool ret = imageSource->ConvertYUV420ToRGBA(data, size, isSupportOdd, isAddUV, error);
    ASSERT_EQ(ret, false);
    isSupportOdd = true;
    imageSource->sourceOptions_.size.height = 0;
    ret = imageSource->ConvertYUV420ToRGBA(data, size, isSupportOdd, isAddUV, error);
    ASSERT_EQ(ret, true);
    imageSource->sourceOptions_.size.height = 5;
    data = new uint8_t;
    ret = imageSource->ConvertYUV420ToRGBA(data, size, isSupportOdd, isAddUV, error);
    ASSERT_EQ(ret, true);
    delete data;
}

/**
 * @tc.name: CreatePixelMapForYUVTest001
 * @tc.desc: test CreatePixelMapForYUV
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapForYUVTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::unique_ptr<PixelMap> ret = imageSource->CreatePixelMapForYUV(errorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: IsSupportGenAstcTest001
 * @tc.desc: test IsSupportGenAstc
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsSupportGenAstcTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    bool ret = imageSource->IsSupportGenAstc();
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetDelayTimeTest001
 * @tc.desc: test GetDelayTime
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetDelayTimeTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    auto ret = imageSource->GetDelayTime(errorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetDisposalTypeTest001
 * @tc.desc: test GetDisposalType
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetDisposalTypeTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    auto ret = imageSource->GetDisposalType(errorCode);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: DecodeSourceInfoTest001
 * @tc.desc: test DecodeSourceInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeSourceInfoTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    bool isAcquiredImageNum = true;
    imageSource->decodeState_ = SourceDecodingState::FORMAT_RECOGNIZED;
    imageSource->sourceInfo_.encodedFormat = "image/astc";
    uint32_t ret = imageSource->DecodeSourceInfo(isAcquiredImageNum);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: OnSourceUnresolvedTest001
 * @tc.desc: test OnSourceUnresolved
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, OnSourceUnresolvedTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->isAstc_ = true;
    uint32_t ret = imageSource->OnSourceUnresolved();
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: GetFormatExtendedTest001
 * @tc.desc: test GetFormatExtended
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFormatExtendedTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::string format;
    uint32_t result = SUCCESS;
    imageSource->mainDecoder_ = std::unique_ptr<ImagePlugin::AbsImageDecoder>(imageSource->CreateDecoder(result));
    uint32_t ret = imageSource->GetFormatExtended(format);
    ASSERT_EQ(ret, SUCCESS);
    imageSource->mainDecoder_ = nullptr;
    imageSource->sourceStreamPtr_ = nullptr;
    ret = imageSource->GetFormatExtended(format);
    ASSERT_EQ(ret, ERR_MEDIA_NULL_POINTER);
}

/**
 * @tc.name: GetFormatExtendedTest002
 * @tc.desc: Verify GetFormatExtended() returns SUCCESS when called with null decoder and empty format string.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetFormatExtendedTest002, TestSize.Level1)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->mainDecoder_ = nullptr;
    std::string format = "";
    uint32_t ret = imageSource->GetFormatExtended(format);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: CheckFormatHintTest001
 * @tc.desc: test CheckFormatHint
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CheckFormatHintTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::string formatHint = "a";
    auto formatIter = imageSource->formatAgentMap_.begin();
    uint32_t ret = imageSource->CheckFormatHint(formatHint, formatIter);
    ASSERT_EQ(ret, ERROR);
    MockAbsImageFormatAgent *mockAbsImageFormatAgent1 = new MockAbsImageFormatAgent;
    MockAbsImageFormatAgent *mockAbsImageFormatAgent2 = new MockAbsImageFormatAgent;
    imageSource->formatAgentMap_.insert(pair<std::string, ImagePlugin::AbsImageFormatAgent *>
        ("a", mockAbsImageFormatAgent1));
    imageSource->formatAgentMap_.insert(pair<std::string, ImagePlugin::AbsImageFormatAgent *>
        ("b", mockAbsImageFormatAgent2));
    imageSource->sourceStreamPtr_ = nullptr;
    ret = imageSource->CheckFormatHint(formatHint, formatIter);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    delete mockAbsImageFormatAgent1;
    delete mockAbsImageFormatAgent2;
}

/**
 * @tc.name: IsStreamCompletedTest001
 * @tc.desc: test IsStreamCompleted
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsStreamCompletedTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->sourceStreamPtr_ = std::make_unique<ImagePlugin::MockInputDataStream>();
    bool ret = imageSource->IsStreamCompleted();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: RemoveDecodeListenerTest002
 * @tc.desc: test RemoveDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RemoveDecodeListenerTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    DecodeListener *listener = nullptr;
    imageSource->RemoveDecodeListener(listener);
    std::shared_ptr<MockDecodeListener> mockDecodeListener = std::make_shared<MockDecodeListener>();
    imageSource->decodeListeners_.insert(mockDecodeListener.get());
    imageSource->RemoveDecodeListener(mockDecodeListener.get());
    ASSERT_EQ(imageSource->decodeListeners_.empty(), true);
}

/**
 * @tc.name: AddDecodeListenerTest002
 * @tc.desc: test AddDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, AddDecodeListenerTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    DecodeListener *listener = nullptr;
    imageSource->AddDecodeListener(listener);
    std::shared_ptr<MockDecodeListener> mockDecodeListener = std::make_shared<MockDecodeListener>();
    imageSource->AddDecodeListener(mockDecodeListener.get());
    ASSERT_EQ(imageSource->decodeListeners_.empty(), false);
}

/**
 * @tc.name: End2EndTest001
 * @tc.desc: test CreateImageSource and CreatePixelMap of jpg resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.jpg", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t jpegWidth = 472;
    int32_t jpegHeight = 226;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(jpegWidth, pixelMap->GetWidth());
    ASSERT_EQ(jpegHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 400;
    int32_t desiredHeight = 200;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
    ASSERT_EQ("undefined_", imageSource->GetPixelMapName(nullptr));
    ASSERT_EQ("400x200-streamsize-27897-mimetype-jpeg", imageSource->GetPixelMapName(pixelMap.get()));
}

/**
 * @tc.name: End2EndTest002
 * @tc.desc: test CreateImageSource and CreatePixelMap of png resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t pngWidth = 472;
    int32_t pngHeight = 75;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pngWidth, pixelMap->GetWidth());
    ASSERT_EQ(pngHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 200;
    int32_t desiredHeight = 250;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest003
 * @tc.desc: test CreateImageSource and CreatePixelMap of bmp resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.bmp", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t bmpWidth = 472;
    int32_t bmpHeight = 75;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(bmpWidth, pixelMap->GetWidth());
    ASSERT_EQ(bmpHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 472;
    int32_t desiredHeight = 75;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest004
 * @tc.desc: test CreateImageSource and CreatePixelMap of ico resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.ico", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t icoWidth = 64;
    int32_t icoHeight = 64;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(icoWidth, pixelMap->GetWidth());
    ASSERT_EQ(icoHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 32;
    int32_t desiredHeight = 32;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest005
 * @tc.desc: test CreateImageSource and CreatePixelMap of svg resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.svg", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t desiredWidth = 56;
    int32_t desiredHeight = 56;
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest006
 * @tc.desc: test CreateImageSource and CreatePixelMap of gif resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest006, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.gif", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t gifWidth = 198;
    int32_t gifHeight = 202;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(gifWidth, pixelMap->GetWidth());
    ASSERT_EQ(gifHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 200;
    int32_t desiredHeight = 200;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest007
 * @tc.desc: test CreateImageSource and CreatePixelMap of webp resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest007, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test_large.webp", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t webpWidth = 588;
    int32_t webpHeight = 662;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(webpWidth, pixelMap->GetWidth());
    ASSERT_EQ(webpHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: End2EndTest008
 * @tc.desc: test CreateImageSource and CreatePixelMap of dng resource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, End2EndTest008, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource("/data/local/tmp/image/test.dng", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    int32_t webpWidth = 5976;
    int32_t webpHeight = 3992;

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(webpWidth, pixelMap->GetWidth());
    ASSERT_EQ(webpHeight, pixelMap->GetHeight());

    int32_t desiredWidth = 100;
    int32_t desiredHeight = 100;

    decodeOpts.desiredSize.width = desiredWidth;
    decodeOpts.desiredSize.height = desiredHeight;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(desiredWidth, pixelMap->GetWidth());
    ASSERT_EQ(desiredHeight, pixelMap->GetHeight());
}

/**
 * @tc.name: UpdateData002
 * @tc.desc: test UpdateData
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, UpdateData002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->sourceStreamPtr_ = nullptr;
    uint8_t *data = new(uint8_t);
    uint32_t size = 1;
    bool isCompleted = false;
    uint32_t ret = imageSource->UpdateData(data, size, isCompleted);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    delete data;
    data = nullptr;
}

/**
 * @tc.name: ModifyImageProperty004
 * @tc.desc: test ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->imageStatusMap_.clear();
    uint32_t index = 0;
    std::string key = "test";
    std::string value = "test";
    uint8_t *data = new(uint8_t);
    uint32_t size = 0;
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_NE(ret, SUCCESS);
    delete data;
    data = nullptr;
}

/**
 * @tc.name: ModifyImageProperty005
 * @tc.desc: test ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->imageStatusMap_.clear();
    uint32_t index = 0;
    std::string key = "test";
    std::string value = "test";
    int fd = 0;
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: ModifyImageProperty006
 * @tc.desc: test ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty006, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->imageStatusMap_.clear();
    uint32_t index = 0;
    std::string key = "test";
    std::string value = "test";
    std::string path = "test";
    uint32_t ret = imageSource->ModifyImageProperty(index, key, value, path);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: ModifyImageProperty007
 * @tc.desc: test ModifyImageProperty fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty007, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    uint32_t retGetIn = imageSource->GetImagePropertyString(index, key, valueGetIn);
    ASSERT_EQ(retGetIn, OHOS::Media::SUCCESS);
    ASSERT_EQ(valueGetIn, "W");
    std::string valueModify = "E";
    const int fd = open(IMAGE_INPUT_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    int32_t retModify = imageSource->ModifyImageProperty(index, key, valueModify, fd);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);

    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSourceOut, nullptr);
    uint32_t retGet = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(retGet, OHOS::Media::SUCCESS);
    ASSERT_EQ(value, "E");
    retModify = imageSource->ModifyImageProperty(index, key, "W", fd);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);
}

/**
 * @tc.name: ModifyImageProperty008
 * @tc.desc: test ModifyImageProperty const std::string &path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty008, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    uint32_t retGetIn = imageSource->GetImagePropertyString(index, key, valueGetIn);
    ASSERT_EQ(retGetIn, OHOS::Media::SUCCESS);
    ASSERT_EQ(valueGetIn, "W");
    std::string valueModify = "E";
    uint32_t retModify = imageSource->ModifyImageProperty(index, key, valueModify, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);

    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSourceOut, nullptr);
    uint32_t retGet = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(retGet, OHOS::Media::SUCCESS);
    ASSERT_EQ(value, "E");

    retModify = imageSource->ModifyImageProperty(index, key, "W", IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);
}

/**
 * @tc.name: GetImagePropertyInt003
 * @tc.desc: test GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyInt003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->imageStatusMap_.clear();
    uint32_t index = 0;
    std::string key = "test";
    int32_t value = 1;
    uint32_t ret = imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: GetImagePropertyString003
 * @tc.desc: test GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyString003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->imageStatusMap_.clear();
    uint32_t index = 0;
    std::string key = "test";
    std::string value = "test";
    uint32_t ret = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_NE(ret, SUCCESS);
}

/**
 * @tc.name: Reset001
 * @tc.desc: test ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, Reset001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 0;
    const std::set<std::string> keys;
    uint8_t *data = nullptr;
    uint32_t size = 0;
    imageSource->mainDecoder_ = std::make_unique<ImagePlugin::MockAbsImageDecoder>();
    imageSource->Reset();
    ASSERT_EQ(imageSource->mainDecoder_, nullptr);
    uint32_t ret = imageSource->RemoveImageProperties(index, keys, data, size);
    ASSERT_EQ(ret, ERR_MEDIA_WRITE_PARCEL_FAIL);
}

/**
 * @tc.name: TransformSizeWithDensity001
 * @tc.desc: test ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, TransformSizeWithDensity001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    Size srcSize;
    int32_t srcDensity = 2;
    Size wantSize;
    wantSize.width = 1;
    wantSize.height = 1;
    int32_t wantDensity = 1;
    Size dstSize;
    imageSource->opts_.resolutionQuality = ResolutionQuality::LOW;
    imageSource->TransformSizeWithDensity(srcSize, srcDensity, wantSize, wantDensity, dstSize);
    ASSERT_EQ(dstSize.width, 1);
}

/**
 * @tc.name: GetExifMetadata001
 * @tc.desc: test ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetExifMetadata001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->exifMetadata_ = std::make_shared<ExifMetadata>();
    auto ret = imageSource->GetExifMetadata();
    ASSERT_EQ(ret, imageSource->exifMetadata_);
    imageSource->exifMetadata_ = nullptr;
    imageSource->sourceStreamPtr_ = nullptr;
    ret = imageSource->GetExifMetadata();
    ASSERT_EQ(ret, nullptr);
    std::shared_ptr<ExifMetadata> ptr = nullptr;
    imageSource->SetExifMetadata(ptr);
    ASSERT_EQ(imageSource->exifMetadata_, ptr);
}

/**
 * @tc.name: OnSourceRecognized001
 * @tc.desc: test ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, OnSourceRecognized001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->mainDecoder_ = nullptr;
    uint32_t ret = imageSource->OnSourceRecognized(false);
    ASSERT_NE(ret, SUCCESS);
    std::unique_ptr<ImagePlugin::AbsImageDecoder> decoder = std::make_unique<ImagePlugin::MockAbsImageDecoder>();
    ImagePlugin::PlImageInfo plInfo;
    float scale = 0;
    ret = imageSource->SetGainMapDecodeOption(decoder, plInfo, scale);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    imageSource->mainDecoder_ = std::make_unique<ImagePlugin::MockAbsImageDecoder>();
    imageSource->sourceStreamPtr_ = std::make_unique<ImagePlugin::MockInputDataStream>();
    ImageHdrType hdrType = ImageHdrType::UNKNOWN;
    struct ImagePlugin::DecodeContext gainMapCtx;
    struct Media::HdrMetadata metadata;
    bool result = imageSource->DecodeJpegGainMap(hdrType, scale, gainMapCtx, metadata);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: ApplyGainMap001
 * @tc.desc: test ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ApplyGainMap001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ImageHdrType hdrType = ImageHdrType::UNKNOWN;
    ImagePlugin::DecodeContext baseCtx;
    ImagePlugin::DecodeContext gainMapCtx;
    ImagePlugin::DecodeContext hdrCtx;
    HdrMetadata metadata;
    float scale = 0;
    imageSource->mainDecoder_ = std::make_unique<ImagePlugin::MockAbsImageDecoder>();
    bool ret = imageSource->ApplyGainMap(hdrType, baseCtx, hdrCtx, scale);
    ASSERT_EQ(ret, false);
    baseCtx.allocatorType = AllocatorType::DEFAULT;
    ret = imageSource->ComposeHdrImage(hdrType, baseCtx, gainMapCtx, hdrCtx, metadata);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: ReusePixelmap001
 * @tc.desc: test ReusePixelmap Heif SDR RGBA
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ReusePixelmap001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions optsPixel;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> reuseImageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(reuseImageSource.get(), nullptr);
    DecodeOptions reusePixelmapOpts;
    std::shared_ptr<PixelMap> rPixelmap = std::move(pixelMap);
    reusePixelmapOpts.reusePixelmap = rPixelmap;
    std::unique_ptr<PixelMap> newPixelMap = reuseImageSource->CreatePixelMap(index, reusePixelmapOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
}

/**
 * @tc.name: ReusePixelmap002
 * @tc.desc: test ReusePixelmap Jpeg HDR
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ReusePixelmap002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::HDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> reuseImageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(reuseImageSource.get(), nullptr);
    DecodeOptions reusePixelmapOpts;
    std::shared_ptr<PixelMap> rPixelmap = std::move(pixelMap);
    reusePixelmapOpts.reusePixelmap = rPixelmap;
    reusePixelmapOpts.desiredDynamicRange = Media::DecodeDynamicRange::HDR;
    std::unique_ptr<PixelMap> newPixelMap = reuseImageSource->CreatePixelMap(index, reusePixelmapOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
}

/**
 * @tc.name: ReusePixelmap003
 * @tc.desc: test ReusePixelmap Heif SDR YUV
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ReusePixelmap003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredPixelFormat = PixelFormat::NV12;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> reuseImageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(reuseImageSource.get(), nullptr);
    DecodeOptions reusePixelmapOpts;
    std::shared_ptr<PixelMap> rPixelmap = std::move(pixelMap);
    reusePixelmapOpts.desiredPixelFormat = PixelFormat::NV12;
    reusePixelmapOpts.reusePixelmap = rPixelmap;
    std::unique_ptr<PixelMap> newPixelMap = reuseImageSource->CreatePixelMap(index, reusePixelmapOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
}

/**
 * @tc.name: CreatePixelMapUsingBrokenImage001
 * @tc.desc: test CreatePixelMap use broken jpeg image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapUsingBrokenImage001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_BROKEN_ONE,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions dopts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, dopts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
}

/**
 * @tc.name: CreatePixelMapUsingBrokenImage002
 * @tc.desc: test CreatePixelMap use broken jpeg image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapUsingBrokenImage002, TestSize.Level1)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_BROKEN_TWO,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions dopts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, dopts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
}

/**
 * @tc.name: ImageSourceTest_CreateImageSourceTest003
 * @tc.desc: Verify that create image source when use larger than MAX_SOURCE_SIZE size.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSourceTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSourceTest003 start";
    uint32_t errorCode = -1;
    uint8_t* data = nullptr;
    uint32_t size = MAX_SOURCE_SIZE + 1;
    SourceOptions opts;
    auto errImageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    ASSERT_EQ(errImageSource, nullptr);
    ASSERT_EQ(errorCode, ERR_IMAGE_TOO_LARGE);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSourceTest003 end";
}

/**
 * @tc.name: ImageSourceTest_CreateImageSourceTest004
 * @tc.desc: Verify that create image source when use letter than IMAGE_URL_PREFIX's size.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSourceTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSourceTest004 start";
    uint32_t errorCode = -1;
    uint32_t size = IMAGE_URL_PREFIX.size() - NUM_1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);

    SourceOptions opts;
    opts.pixelFormat = PixelFormat::NV12;
    opts.size.width = NUM_1;
    opts.size.height = NUM_10;
    auto errImageSource = ImageSource::CreateImageSource(data.get(), size, opts, errorCode);
    ASSERT_NE(errImageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = NUM_1;
    decodeOpts.desiredSize.height = NUM_10;

    auto errPixelMap = errImageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    ASSERT_EQ(errPixelMap, nullptr);
    ASSERT_EQ(errorCode, ERROR);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSourceTest004 end";
}

/**
 * @tc.name: ImageSourceTest_ConvertAutoAllocatorTypeTest001
 * @tc.desc: Verify that ConvertAutoAllocatorType when decode hdr image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ConvertAutoAllocatorTypeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;

    auto ret = imageSource->ConvertAutoAllocatorType(decodeOpts);
    ASSERT_EQ(ret, AllocatorType::DMA_ALLOC);
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest001 end";
}

/**
 * @tc.name: ImageSourceTest_ConvertAutoAllocatorTypeTest002
 * @tc.desc: Verify that ConvertAutoAllocatorType when decode sdr image and decode format is ARGB_8888.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ConvertAutoAllocatorTypeTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    decodeOpts.desiredPixelFormat = PixelFormat::ARGB_8888;
    imageSource->sourceHdrType_ = ImageHdrType::SDR;

    auto ret = imageSource->ConvertAutoAllocatorType(decodeOpts);
    ASSERT_EQ(ret, AllocatorType::SHARE_MEM_ALLOC);
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest002 end";
}

/**
 * @tc.name: ImageSourceTest_ConvertAutoAllocatorTypeTest003
 * @tc.desc: Verify that ConvertAutoAllocatorType when decode sdr image but overflow risk.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ConvertAutoAllocatorTypeTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    imageSource->sourceHdrType_ = ImageHdrType::SDR;

    auto iter = imageSource->GetValidImageStatus(0, errorCode);
    ASSERT_NE(iter, imageSource->imageStatusMap_.end());
    ImageInfo& firstImageInfo = (iter->second).imageInfo;
    firstImageInfo.encodedFormat = "image/jpeg";
    firstImageInfo.size.width = NUM_2;
    firstImageInfo.size.height = INT_MAX;

    auto ret = imageSource->ConvertAutoAllocatorType(decodeOpts);
    ASSERT_EQ(ret, AllocatorType::SHARE_MEM_ALLOC);
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest003 end";
}

/**
 * @tc.name: ImageSourceTest_ConvertAutoAllocatorTypeTest004
 * @tc.desc: Verify that ConvertAutoAllocatorType when decode sdr image but unknown encodedFormat.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ConvertAutoAllocatorTypeTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    imageSource->sourceHdrType_ = ImageHdrType::SDR;

    auto iter = imageSource->GetValidImageStatus(0, errorCode);
    ASSERT_NE(iter, imageSource->imageStatusMap_.end());
    ImageInfo& firstImageInfo = (iter->second).imageInfo;
    firstImageInfo.encodedFormat = "mock format";
    firstImageInfo.size.width = NUM_64;
    firstImageInfo.size.height = DEFAULT_DMA_SIZE / NUM_64;

    auto ret = imageSource->ConvertAutoAllocatorType(decodeOpts);
    ASSERT_EQ(ret, AllocatorType::DMA_ALLOC);
    GTEST_LOG_(INFO) << "ImageSourceTest: ConvertAutoAllocatorTypeTest004 end";
}

/**
 * @tc.name: ImageSourceTest_IsSupportAllocatorTypeTest001
 * @tc.desc: Verify that IsSupportAllocatorType satisify IsSvgUseDma condition.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsSupportAllocatorTypeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: IsSupportAllocatorTypeTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    auto iter = imageSource->GetValidImageStatus(0, errorCode);
    ASSERT_NE(iter, imageSource->imageStatusMap_.end());
    ImageInfo& firstImageInfo = (iter->second).imageInfo;
    firstImageInfo.encodedFormat = "image/svg+xml";

    auto ret = imageSource->IsSupportAllocatorType(decodeOpts, NUM_1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImageSourceTest: IsSupportAllocatorTypeTest001 end";
}

/**
 * @tc.name: ImageSourceTest_IsSupportAllocatorTypeTest002
 * @tc.desc: Verify that IsSupportAllocatorType when decode sdr image and pixel format is ARGB_8888
 *           and allocatype is DMA_ALLOC.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, IsSupportAllocatorTypeTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: IsSupportAllocatorTypeTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    imageSource->sourceHdrType_ = ImageHdrType::SDR;
    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    decodeOpts.desiredPixelFormat = PixelFormat::ARGB_8888;

    auto iter = imageSource->GetValidImageStatus(0, errorCode);
    ASSERT_NE(iter, imageSource->imageStatusMap_.end());
    ImageInfo& firstImageInfo = (iter->second).imageInfo;
    firstImageInfo.encodedFormat = "image/jpeg";

    auto ret = imageSource->IsSupportAllocatorType(decodeOpts, NUM_1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImageSourceTest: IsSupportAllocatorTypeTest002 end";
}

/**
 * @tc.name: ImageSourceTest_InitDecodeContextTest001
 * @tc.desc: Verify that InitDecodeContext when desiredPixelFormat is ARGB_8888.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, InitDecodeContextTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::HEAP_ALLOC;
    decodeOpts.isAppUseAllocator = false;
    decodeOpts.desiredPixelFormat = PixelFormat::ARGB_8888;
    ImageInfo imageInfo;
    ImagePlugin::PlImageInfo plImageInfo;

    auto ret = imageSource->InitDecodeContext(decodeOpts, imageInfo, imageSource->preference_,
        false, plImageInfo);
    ASSERT_EQ(ret.isAppUseAllocator, true);
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest001 end";
}

/**
 * @tc.name: ImageSourceTest_InitDecodeContextTest002
 * @tc.desc: Verify that InitDecodeContext when desiredPixelFormat is NV12.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, InitDecodeContextTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest002 start";
    InitDecodeContextTest(PixelFormat::NV12, PixelFormat::YCBCR_P010);
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest002 end";
}

/**
 * @tc.name: ImageSourceTest_InitDecodeContextTest003
 * @tc.desc: Verify that InitDecodeContext when desiredPixelFormat is NV21.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, InitDecodeContextTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest003 start";
    InitDecodeContextTest(PixelFormat::NV21, PixelFormat::YCRCB_P010);
    GTEST_LOG_(INFO) << "ImageSourceTest: InitDecodeContextTest003 end";
}

/**
 * @tc.name: ImageSourceTest_CreatePixelMapTest001
 * @tc.desc: Verify that CreatePixelMap when decode options is invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest001 start";
    CreatePixelMapUseInvalidOptsTest(1, 0);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest001 end";
}

/**
 * @tc.name: CreatePixelMapTest002
 * @tc.desc: Verify that CreatePixelMap when decode options is invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest002 start";
    CreatePixelMapUseInvalidOptsTest(2, 0);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest002 end";
}

/**
 * @tc.name: CreatePixelMapTest003
 * @tc.desc: Verify that CreatePixelMap when decode options is invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest003 start";
    CreatePixelMapUseInvalidOptsTest(0, 1);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest003 end";
}

/**
 * @tc.name: CreatePixelMapTest004
 * @tc.desc: Verify that CreatePixelMap when decode options is invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest004 start";
    CreatePixelMapUseInvalidOptsTest(0, 2);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest004 end";
}

/**
 * @tc.name: CreatePixelMapTest005
 * @tc.desc: Verify that CreatePixelMap when decode options is invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest005 start";
    CreatePixelMapUseInvalidOptsTest(0, 3, ERROR);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapTest005 end";
}

/**
 * @tc.name: ImageSourceTest_ModifyImagePropertyExTest001
 * @tc.desc: Verify that ModifyImagePropertyEx when srcFd_ is -1 and srcFilePath_ is empty and
 *           srcBuffer_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImagePropertyExTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->srcFd_ = -1;
    imageSource->srcFilePath_ = "";
    std::string key, value;

    auto ret = imageSource->ModifyImagePropertyEx(0, key, value);
    ASSERT_EQ(ret, ERROR);
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest001 end";
}

/**
 * @tc.name: ImageSourceTest_ModifyImagePropertyExTest002
 * @tc.desc: Verify that ModifyImagePropertyEx when srcFd_ is 0.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImagePropertyExTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->srcFd_ = 0;
    std::string key, value;

    auto ret = imageSource->ModifyImagePropertyEx(0, key, value);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest002 end";
}

/**
 * @tc.name: ImageSourceTest_ModifyImagePropertyExTest003
 * @tc.desc: Verify that ModifyImagePropertyEx when srcFilePath_ is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImagePropertyExTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->srcFd_ = -1;
    imageSource->srcFilePath_ = std::string{"/data/local/tmp/image/mock.notexist"};
    std::string key, value;

    auto ret = imageSource->ModifyImagePropertyEx(0, key, value);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest003 end";
}

/**
 * @tc.name: ImageSourceTest_ModifyImagePropertyExTest004
 * @tc.desc: Verify that ModifyImagePropertyEx when srcBuffer_ is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImagePropertyExTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->srcFd_ = -1;
    imageSource->srcFilePath_ = "";
    std::unique_ptr<uint8_t[]> mockBuffer = std::make_unique<uint8_t[]>(1);
    imageSource->srcBuffer_ = mockBuffer.get();
    imageSource->srcBufferSize_ = 1;
    std::string key, value;

    auto ret = imageSource->ModifyImagePropertyEx(0, key, value);
    ASSERT_EQ(ret, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest004 end";
}

/**
 * @tc.name: ImageSourceTest_ModifyImagePropertyExTest005
 * @tc.desc: Verify that ModifyImagePropertyEx when srcBuffer_ is not exist but srcBufferSize_ is 0.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImagePropertyExTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest005 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->srcFd_ = -1;
    imageSource->srcFilePath_ = "";
    std::unique_ptr<uint8_t[]> mockBuffer = std::make_unique<uint8_t[]>(1);
    imageSource->srcBuffer_ = mockBuffer.get();
    imageSource->srcBufferSize_ = 0;
    std::string key, value;

    auto ret = imageSource->ModifyImagePropertyEx(0, key, value);
    ASSERT_EQ(ret, ERROR);
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImagePropertyExTest005 end";
}

/**
 * @tc.name: ImageSourceTest_GetImagePropertyCommonTest001
 * @tc.desc: Verify that GetImagePropertyCommon when key is Hw.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyCommonTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyCommonTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->sourceStreamPtr_.reset();
    imageSource->isExifReadFailed_ = false;
    imageSource->exifMetadata_.reset();
    std::string key{"Hw"}, value;

    errorCode = imageSource->GetImagePropertyCommon(0, key, value);
    ASSERT_EQ(value, std::string{"default_exif_value"});
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyCommonTest001 end";
}

/**
 * @tc.name: ImageSourceTest_GetImagePropertyStringTest001
 * @tc.desc: Verify that GetImagePropertyString when key is IMAGE_GIFLOOPCOUNT_TYPE.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyStringTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyStringTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    std::string key{"GIFLoopCount"}, value;
    errorCode = imageSource->GetImagePropertyString(0, key, value);
    ASSERT_EQ(errorCode, ERR_MEDIA_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyStringTest001 end";
}

/**
 * @tc.name: ImageSourceTest_GetImagePropertyStringTest002
 * @tc.desc: Verify that GetImagePropertyString when key is IMAGE_GIFLOOPCOUNT_TYPE.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetImagePropertyStringTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyStringTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    std::string key{"GIFLoopCount"}, value;
    imageSource->decodeState_ = SourceDecodingState::SOURCE_ERROR;

    errorCode = imageSource->GetImagePropertyString(0, key, value);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceTest: GetImagePropertyStringTest002 end";
}

/**
 * @tc.name: ImageSourceTest_RemoveImagePropertiesTest001
 * @tc.desc: Verify that RemoveImageProperties when path is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RemoveImagePropertiesTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveImagePropertiesTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    std::string path{"/data/local/tmp/mock.notexist"};
    std::set<std::string> keys;

    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveImagePropertiesTest001 end";
}

/**
 * @tc.name: ImageSourceTest_RemoveImagePropertiesTest002
 * @tc.desc: Verify that RemoveImageProperties when fd is 0/1/2.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RemoveImagePropertiesTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveImagePropertiesTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    int fd = 0;
    std::set<std::string> keys;

    errorCode = imageSource->RemoveImageProperties(0, keys, fd);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveImagePropertiesTest002 end";
}

/**
 * @tc.name: ImageSourceTest_CreatePixelMapForYUVTest002
 * @tc.desc: Verify that CreatePixelMapForYUV is valid.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapForYUVTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapForYUVTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    opts.size.width = IMAGE_INPUT_JPG_WIDTH;
    opts.size.height = IMAGE_INPUT_JPG_HEIGHT;
    opts.pixelFormat = PixelFormat::NV12;

    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    auto pixelMap = imageSource->CreatePixelMapForYUV(errorCode);
    ASSERT_NE(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapForYUVTest002 end";
}

/**
 * @tc.name: ImageSourceTest_CreatePixelAstcFromImageFileTest001
 * @tc.desc: Verify that CreatePixelAstcFromImageFile is valid.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelAstcFromImageFileTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelAstcFromImageFileTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;

    auto pixelMap = imageSource->CreatePixelAstcFromImageFile(0, decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelAstcFromImageFileTest001 end";
}

/**
 * @tc.name: ImageSourceTest_DecodeJpegAuxiliaryPictureTest001
 * @tc.desc: Verify that DecodeJpegAuxiliaryPicture when sourceStream_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeJpegAuxiliaryPictureTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeJpegAuxiliaryPictureTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->sourceStreamPtr_.reset();
    std::set<AuxiliaryPictureType> auxTypes;
    std::unique_ptr<Picture> picture;

    imageSource->DecodeJpegAuxiliaryPicture(auxTypes, picture, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeJpegAuxiliaryPictureTest001 end";
}

/**
 * @tc.name: ImageSourceTest_CreatePixelAstcFromImageFileTest002
 * @tc.desc: Verify that CreatePixelAstcFromImageFile when input size is overlarge.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelAstcFromImageFileTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelAstcFromImageFileTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH * (NUM_10 + NUM_2);
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;

    auto pixelMap = imageSource->CreatePixelAstcFromImageFile(0, decodeOpts, errorCode);
    ASSERT_EQ(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelAstcFromImageFileTest002 end";
}

/**
 * @tc.name: ImageSourceTest_DecodeHeifAuxiliaryPicturesTest001
 * @tc.desc: Verify that DecodeHeifAuxiliaryPictures when mainDecoder is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeHeifAuxiliaryPicturesTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeHeifAuxiliaryPicturesTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    imageSource->mainDecoder_.reset();
    std::set<AuxiliaryPictureType> auxTypes;
    std::unique_ptr<Picture> picture;

    imageSource->DecodeHeifAuxiliaryPictures(auxTypes, picture, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_PLUGIN_CREATE_FAILED);
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeHeifAuxiliaryPicturesTest001 end";
}

/**
 * @tc.name: ImageSourceTest_DecodeHeifAuxiliaryPicturesTest002
 * @tc.desc: Verify that DecodeHeifAuxiliaryPictures when picture is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, DecodeHeifAuxiliaryPicturesTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeHeifAuxiliaryPicturesTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH_EXACTSIZE, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    bool ret = imageSource->ParseHdrType();
    ASSERT_EQ(ret, true);
    std::set<AuxiliaryPictureType> auxTypes;
    std::unique_ptr<Picture> picture;

    imageSource->DecodeHeifAuxiliaryPictures(auxTypes, picture, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ImageSourceTest: DecodeHeifAuxiliaryPicturesTest002 end";
}

/**
 * @tc.name: WideGamutTest001
 * @tc.desc: test WideGamut one channel gainmap Jpeg HDR input
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, WideGamutTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.isCreateWideGamutSdrPixelMap = true;
    decodeOpts.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
    Media::PixelFormat pixelFormat = pixelMap->GetPixelFormat();
    ASSERT_EQ(pixelFormat, Media::PixelFormat::RGBA_8888);
}

/**
 * @tc.name: WideGamutTest002
 * @tc.desc: test WideGamut one channel gainmap Jpeg HDR input
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, WideGamutTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.isCreateWideGamutSdrPixelMap = true;
    decodeOpts.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
    Media::PixelFormat pixelFormat = pixelMap->GetPixelFormat();
    ASSERT_EQ(pixelFormat, Media::PixelFormat::RGBA_1010102);
}

/**
 * @tc.name: WideGamutTest003
 * @tc.desc: test WideGamut one channel gainmap Jpeg HDR input
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, WideGamutTest003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_HEIC_THREE_GAINMAP_HDR_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.isCreateWideGamutSdrPixelMap = true;
    decodeOpts.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
    Media::PixelFormat pixelFormat = pixelMap->GetPixelFormat();
    ASSERT_EQ(pixelFormat, Media::PixelFormat::RGBA_1010102);
}

/**
 * @tc.name: LargeImageTest001
 * @tc.desc: test decode supported large image(JPEG), using default decode options, expect decode fail
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, LargeImageTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_LARGE_SIZE_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    uint32_t index = 0;
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_TOO_LARGE);
}

/**
 * @tc.name: LargeImageTest002
 * @tc.desc: test decode supported large image(JPEG), using valid desiredSize decode options, expect decode success
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, LargeImageTest002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_LARGE_SIZE_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {DECODE_DESIRED_WIDTH, DECODE_DESIRED_HEIGHT};
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    ASSERT_EQ(pixelMap->GetWidth(), DECODE_DESIRED_WIDTH);
    ASSERT_EQ(pixelMap->GetHeight(), DECODE_DESIRED_HEIGHT);
}

/**
 * @tc.name: LargeImageTest003
 * @tc.desc: test decode unsupported large image(GIF), using valid desiredSize decode options, expect decode fail
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, LargeImageTest003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_GIF_LARGE_SIZE_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {DECODE_DESIRED_WIDTH, DECODE_DESIRED_HEIGHT};
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_TOO_LARGE);
}

/**
 * @tc.name: LargeImageTest004
 * @tc.desc: test decode supported large image(JPEG),
 *           using valid desiredSize and valid desiredRegion(scale first) decode options,
 *           expect decode success, output pixelmap size is equal to desiredRegion size.
 *           process:
 *           src size(30000x30000) -> sample decode size(7500x7500) -> crop size(4096x4096)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, LargeImageTest004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_LARGE_SIZE_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {DECODE_DESIRED_WIDTH, DECODE_DESIRED_HEIGHT};
    decodeOpts.CropRect = {0, 0, DESIRED_REGION_WIDTH, DESIRED_REGION_HEIGHT};
    decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    ASSERT_EQ(pixelMap->GetWidth(), DESIRED_REGION_WIDTH);
    ASSERT_EQ(pixelMap->GetHeight(), DESIRED_REGION_HEIGHT);
}

/**
 * @tc.name: LargeImageTest005
 * @tc.desc: test decode supported large image(JPEG),
 *           using valid desiredSize and valid desiredRegion(crop first) decode options,
 *           expect decode success, output pixelmap size is equal to desiredSize size.
 *           process:
 *           src size(30000x30000) -> region decode size(4096x4096) -> scale size(7500x7500)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, LargeImageTest005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_LARGE_SIZE_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    uint32_t index = 0;
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {DECODE_DESIRED_WIDTH, DECODE_DESIRED_HEIGHT};
    decodeOpts.CropRect = {0, 0, DESIRED_REGION_WIDTH, DESIRED_REGION_HEIGHT};
    decodeOpts.cropAndScaleStrategy = CropAndScaleStrategy::CROP_FIRST;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    ASSERT_EQ(pixelMap->GetWidth(), DECODE_DESIRED_WIDTH);
    ASSERT_EQ(pixelMap->GetHeight(), DECODE_DESIRED_HEIGHT);
}
} // namespace Multimedia
} // namespace OHOS