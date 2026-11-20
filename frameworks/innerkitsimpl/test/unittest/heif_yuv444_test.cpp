/**
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

#include <fstream>
#include <memory>
#include <securec.h>
#include <string>
#include <vector>

#include "HeifDecoderImpl.h"
#include "image_source.h"
#include "image_type.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {
static const std::string IMAGE_INPUT_HEIF_PATH = "/data/local/tmp/image/";
static const std::string YUV444_10BIT_HEIF = "test_yuv444_10bit.heic";
static const std::string YUV444_8BIT_HEIF = "test_yuv444_8bit.heic";
static const std::string HEIF_FORMAT_HINT = "image/heif";

#ifdef HEIF_HW_DECODE_ENABLE

class TestHeifStream : public HeifStream {
public:
    explicit TestHeifStream(const std::vector<uint8_t> &data) : data_(data) {}

    size_t read(void *buf, size_t size) override
    {
        if (buf == nullptr || position_ >= data_.size()) {
            return 0;
        }
        size_t readSize = (size < data_.size() - position_) ? size : data_.size() - position_;
        if (memcpy_s(buf, readSize, data_.data() + position_, readSize) != EOK) {
            return 0;
        }
        position_ += readSize;
        return readSize;
    }

    bool rewind() override
    {
        position_ = 0;
        return true;
    }

    bool seek(size_t pos) override
    {
        position_ = (pos < data_.size()) ? pos : data_.size();
        return true;
    }

    bool hasLength() const override
    {
        return true;
    }

    size_t getLength() const override
    {
        return data_.size();
    }

    bool hasPosition() const override
    {
        return true;
    }

    size_t getPosition() const override
    {
        return position_;
    }

private:
    std::vector<uint8_t> data_;
    size_t position_ = 0;
};

static bool LoadHeifFile(const std::string &fileName, std::vector<uint8_t> &fileData)
{
    std::string path = IMAGE_INPUT_HEIF_PATH + fileName;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        GTEST_LOG_(INFO) << "HeifYuv444Test: open file failed: " << path.c_str();
        return false;
    }
    std::streamsize size = input.tellg();
    if (size <= 0) {
        return false;
    }
    input.seekg(0, std::ios::beg);
    fileData.resize(static_cast<size_t>(size));
    input.read(reinterpret_cast<char *>(fileData.data()), size);
    return !input.fail();
}

static std::shared_ptr<HeifDecoderImpl> CreateInitedHeifDecoder(const std::vector<uint8_t> &fileData)
{
    if (fileData.empty()) {
        return nullptr;
    }
    auto decoder = std::make_shared<HeifDecoderImpl>();
    TestHeifStream *stream = new (std::nothrow) TestHeifStream(fileData);
    if (stream == nullptr) {
        return nullptr;
    }
    if (!decoder->init(stream, nullptr)) {
        GTEST_LOG_(INFO) << "HeifYuv444Test: decoder init failed";
        return nullptr;
    }
    return decoder;
}

class HeifYuv444Test : public testing::Test {
public:
    HeifYuv444Test() {}
    ~HeifYuv444Test() {}
};

/**
 * @tc.name: IsYuv444SourceTest001
 * @tc.desc: Verify IsYuv444Source and IsYuv444TenBitSource return false when decoder is not initialized.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, IsYuv444SourceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest001 start";
    HeifDecoderImpl decoder;
    EXPECT_FALSE(decoder.IsYuv444Source());
    EXPECT_FALSE(decoder.IsYuv444TenBitSource());
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest001 end";
}

/**
 * @tc.name: IsYuv444SourceTest002
 * @tc.desc: Verify a single-layer 4:4:4 10bit HDR heif is recognized as 10bit yuv444 source.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, IsYuv444SourceTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest002 start";
    std::vector<uint8_t> fileData;
    ASSERT_TRUE(LoadHeifFile(YUV444_10BIT_HEIF, fileData));
    auto decoder = CreateInitedHeifDecoder(fileData);
    ASSERT_NE(decoder, nullptr);
    EXPECT_TRUE(decoder->IsYuv444Source());
    EXPECT_TRUE(decoder->IsYuv444TenBitSource());
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest002 end";
}

/**
 * @tc.name: IsYuv444SourceTest003
 * @tc.desc: Verify an 8bit 4:4:4 heif is recognized as 8bit yuv444 source.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, IsYuv444SourceTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest003 start";
    std::vector<uint8_t> fileData;
    ASSERT_TRUE(LoadHeifFile(YUV444_8BIT_HEIF, fileData));
    auto decoder = CreateInitedHeifDecoder(fileData);
    ASSERT_NE(decoder, nullptr);
    EXPECT_TRUE(decoder->IsYuv444Source());
    EXPECT_FALSE(decoder->IsYuv444TenBitSource());
    GTEST_LOG_(INFO) << "HeifYuv444Test: IsYuv444SourceTest003 end";
}

/**
 * @tc.name: ImageSourceYuv444Test001
 * @tc.desc: Verify an unknown desired format on a 10bit yuv444 source resolves to RGBA_1010102.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_10BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::UNKNOWN;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::RGBA_1010102);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test001 end";
}

/**
 * @tc.name: ImageSourceYuv444Test002
 * @tc.desc: Verify ycbcr p010 requested by a 10bit yuv444 source is kept as ycbcr p010.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_10BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::YCBCR_P010;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::YCBCR_P010);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test002 end";
}

/**
 * @tc.name: ImageSourceYuv444Test003
 * @tc.desc: Verify ycrcb p010 requested by a 10bit yuv444 source is kept as ycrcb p010.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_10BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::YCRCB_P010;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::YCRCB_P010);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test003 end";
}

/**
 * @tc.name: ImageSourceYuv444Test004
 * @tc.desc: Verify an unsupported desired format is rejected for a 10bit yuv444 source.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_10BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::Y8;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    EXPECT_NE(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test004 end";
}

/**
 * @tc.name: ImageSourceYuv444Test005
 * @tc.desc: Verify an HDR request on a 10bit yuv444 source resolves to RGBA_1010102.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test005 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_10BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::UNKNOWN;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::RGBA_1010102);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test005 end";
}

/**
 * @tc.name: ImageSourceYuv444Test006
 * @tc.desc: Verify the accepted 8bit output formats decode successfully for an 8bit yuv444 source.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test006 start";
    const PixelFormat formats[] = {
        PixelFormat::NV12, PixelFormat::NV21, PixelFormat::RGBA_8888, PixelFormat::BGRA_8888,
        PixelFormat::RGB_565
    };
    for (PixelFormat format : formats) {
        uint32_t errorCode = 0;
        SourceOptions opts;
        opts.formatHint = HEIF_FORMAT_HINT;
        std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
            IMAGE_INPUT_HEIF_PATH + YUV444_8BIT_HEIF, opts, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(imageSource.get(), nullptr);
        DecodeOptions decodeOpts;
        decodeOpts.desiredPixelFormat = format;
        decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
        std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        EXPECT_EQ(errorCode, SUCCESS) << "format " << static_cast<int32_t>(format);
        ASSERT_NE(pixelMap.get(), nullptr) << "format " << static_cast<int32_t>(format);
        EXPECT_EQ(pixelMap->GetPixelFormat(), format) << "format " << static_cast<int32_t>(format);
    }
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test006 end";
}

/**
 * @tc.name: ImageSourceYuv444Test007
 * @tc.desc: Verify a 10bit format requested by an 8bit yuv444 source falls back to RGBA_8888.
 * @tc.type: FUNC
 */
HWTEST_F(HeifYuv444Test, ImageSourceYuv444Test007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test007 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = HEIF_FORMAT_HINT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
        IMAGE_INPUT_HEIF_PATH + YUV444_8BIT_HEIF, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_1010102;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::RGBA_8888);
    GTEST_LOG_(INFO) << "HeifYuv444Test: ImageSourceYuv444Test007 end";
}
#endif // HEIF_HW_DECODE_ENABLE
} // namespace ImagePlugin
} // namespace OHOS
