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

#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>
#include "image/abs_image_decoder.h"
#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_source.h"
#include "buffer_source_stream.h"
#include "file_source_stream.h"
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

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";

class ImageSourceTest : public testing::Test {
public:
    ImageSourceTest() {}
    ~ImageSourceTest() {}
};

/**
 * @tc.name: GetSupportedFormats001
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSupportedFormats001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetSupportedFormats001 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
	ASSERT_EQ(ret, SUCCESS);
	GTEST_LOG_(INFO) << "ImageSourceTest: GetSupportedFormats001 end";
}

/**
 * @tc.name: GetSupportedFormats002
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetSupportedFormats002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetSupportedFormats002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    std::set<std::string> formats;
    imageSource->GetSupportedFormats(formats);
    GTEST_LOG_(INFO) << "ImageSourceTest: GetSupportedFormats002 end";
}

/**
 * @tc.name: CreateImageSource003
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource003 start";
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const uint8_t *data = nullptr;
    uint32_t size = 1;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    ASSERT_EQ(imageSource, nullptr);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource003 end";
}

/**
 * @tc.name: CreateImageSource005
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource005 start";

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string pathName = IMAGE_INPUT_JPEG_PATH;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource005 end";
}

/**
 * @tc.name: CreateImageSource006
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource006 start";

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string pathName = "a";
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    ASSERT_EQ(creimagesource, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource006 end";
}

/**
 * @tc.name: CreateImageSource007
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource007 start";
    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(fd, opts, errorCode);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource007 end";
}

/**
 * @tc.name: CreateImageSource008
 * @tc.desc: test CreateImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateImageSource008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource008 start";

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const int fd = 0;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_EQ(creimagesource, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: CreateImageSource008 end";
}

/**
 * @tc.name: CreateIncrementalImageSource001
 * @tc.desc: test CreateIncrementalImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreateIncrementalImageSource001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateIncrementalImageSource001 start";
    uint32_t errorCode = 0;
    const IncrementalSourceOptions opts;
    std::unique_ptr<ImageSource> creimagesource = ImageSource::CreateIncrementalImageSource(opts, errorCode);
    GTEST_LOG_(INFO) << "ImageSourceTest: CreateIncrementalImageSource001 end";
}

/**
 * @tc.name: CreatePixelMapEx001
 * @tc.desc: test CreatePixelMapEx
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMapEx001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapEx001 start";

    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmapex = imageSource->CreatePixelMapEx(index, opts, errorCode);
    ASSERT_EQ(crepixelmapex, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMapEx001 end";
}

/**
 * @tc.name: CreatePixelMap001
 * @tc.desc: test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMap001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMap001 start";

    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmap = imageSource->CreatePixelMap(index, opts, errorCode);
    ASSERT_EQ(crepixelmap, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMap001 end";
}

/**
 * @tc.name: CreatePixelMap002
 * @tc.desc: test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, CreatePixelMap002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMap002 start";

    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    uint32_t index = 1;
    const DecodeOptions opts;
    std::unique_ptr<PixelMap> crepixelmap = imageSource->CreatePixelMap(index, opts, errorCode);
    ASSERT_EQ(crepixelmap, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: CreatePixelMap002 end";
}

/**
 * @tc.name: UpdateData001
 * @tc.desc: test UpdateData
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, UpdateData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: UpdateData001 start";
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
    GTEST_LOG_(INFO) << "ImageSourceTest: UpdateData001 end";
}

/**
 * @tc.name: RegisterListener001
 * @tc.desc: test RegisterListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RegisterListener001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: RegisterListener001 start";

    PeerListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->RegisterListener(listener);

    GTEST_LOG_(INFO) << "ImageSourceTest: RegisterListener001 end";
}

/**
 * @tc.name: UnRegisterListener001
 * @tc.desc: test UnRegisterListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, UnRegisterListener001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: UnRegisterListener001 start";

    PeerListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->UnRegisterListener(listener);

    GTEST_LOG_(INFO) << "ImageSourceTest: UnRegisterListener001 end";
}

/**
 * @tc.name: AddDecodeListener001
 * @tc.desc: test AddDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, AddDecodeListener001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: AddDecodeListener001 start";

    DecodeListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->AddDecodeListener(listener);

    GTEST_LOG_(INFO) << "ImageSourceTest: AddDecodeListener001 end";
}

/**
 * @tc.name: RemoveDecodeListener001
 * @tc.desc: test RemoveDecodeListener
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, RemoveDecodeListener001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveDecodeListener001 start";

    DecodeListener *listener = nullptr;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    imageSource->RemoveDecodeListener(listener);

    GTEST_LOG_(INFO) << "ImageSourceTest: RemoveDecodeListener001 end";
}

/**
 * @tc.name: GetNinePatchInfo001
 * @tc.desc: test GetNinePatchInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetNinePatchInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetNinePatchInfo001 start";

    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, false);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);

    const NinePatchInfo &ninePatch = imageSource->GetNinePatchInfo();
    ASSERT_EQ(ninePatch.ninePatch, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceTest: GetNinePatchInfo001 end";
}

/**
 * @tc.name: SetMemoryUsagePreference001
 * @tc.desc: test SetMemoryUsagePreference
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, SetMemoryUsagePreference001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: SetMemoryUsagePreference001 start";

    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, false);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    MemoryUsagePreference preference = MemoryUsagePreference::LOW_RAM;
    imageSource->SetMemoryUsagePreference(preference);

    GTEST_LOG_(INFO) << "ImageSourceTest: SetMemoryUsagePreference001 end";
}

/**
 * @tc.name: GetMemoryUsagePreference001
 * @tc.desc: test GetMemoryUsagePreference
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetMemoryUsagePreference001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetMemoryUsagePreference001 start";

    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, false);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    imageSource->GetMemoryUsagePreference();

    GTEST_LOG_(INFO) << "ImageSourceTest: GetMemoryUsagePreference001 end";
}

/**
 * @tc.name: GetRedactionArea001
 * @tc.desc: test GetRedactionArea(fd, redactionType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, GetRedactionArea001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: GetRedactionArea001 start";

    int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT);
    int redactionType = 0;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, false);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetRedactionArea(fd, redactionType, ranges);
    ASSERT_NE(ret, 0);

    GTEST_LOG_(INFO) << "ImageSourceTest: GetRedactionArea001 end";
}
} // namespace Multimedia
} // namespace OHOS