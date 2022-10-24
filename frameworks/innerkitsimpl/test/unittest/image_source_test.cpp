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
#include <fstream>
#include "image_source.h"

#include <algorithm>
#include <vector>
#include "buffer_source_stream.h"
#if !defined(_WIN32) && !defined(_APPLE)
#include "hitrace_meter.h"
#endif
#include "file_source_stream.h"
#include "image/abs_image_decoder.h"
#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_log.h"
#include "image_utils.h"
#include "incremental_source_stream.h"
#include "istream_source_stream.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "source_stream.h"
#if defined(_ANDROID) || defined(_IOS)
#include "include/jpeg_decoder.h"
#endif
#include "include/utils/SkBase64.h"
#include "image_trace.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
using namespace std;
using namespace ImagePlugin;
using namespace MultimediaPlugin;

class ImageSourceTest : public testing::Test {
public:
    ImageSourceTest() {}
    ~ImageSourceTest() {}
};

/**
 * @tc.name: ModifyImageProperty001
 * @tc.desc: test ModifyImageProperty(index, key, value, path)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty001 start";

    uint32_t ret;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImagePlugin::AbsImageDecoder> mainDecoder_;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key;
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT);
    ret = mainDecoder_->ModifyImageProperty(index, key, value, path);

    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty001 end";
}

/**
 * @tc.name: ModifyImageProperty002
 * @tc.desc: test ModifyImageProperty(index, key, value, fd)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty002 start";

    uint32_t ret;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImagePlugin::AbsImageDecoder> mainDecoder_;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key;
    ret = mainDecoder_->ModifyImageProperty(index, key, value, fd);
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty002 end";
}

/**
 * @tc.name: ModifyImageProperty003
 * @tc.desc: test ModifyImageProperty(index, key, value, data, size)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceTest, ModifyImageProperty003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty003 start";

    uint32_t ret;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImagePlugin::AbsImageDecoder> mainDecoder_;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    uint32_t index = 0;
    int32_t value = 0;
    uint8_t data = 0;
    uint32_t size = 0;

    std::string key;
    ret = mainDecoder_->ModifyImageProperty(index, key, value, data, size);
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceTest: ModifyImageProperty003 end";
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
    fs->open("/data/local/tmp/image/test.9.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
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
    fs->open("/data/local/tmp/image/test.9.png", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    MemoryUsagePreference preference = 1;
    imageSource->SetMemoryUsagePreference(preference);

    GTEST_LOG_(INFO) << "ImageSourceTest: SetMemoryUsagePreference001 end";
}







}
}