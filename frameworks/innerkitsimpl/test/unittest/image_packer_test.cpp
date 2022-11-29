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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include "image/abs_image_encoder.h"
#include "image_packer.h"
#include "buffer_packer_stream.h"
#include "file_packer_stream.h"
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "ostream_packer_stream.h"
#include "plugin_server.h"

using namespace OHOS::Media;
using namespace testing::ext;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImagePlugin;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_100 = 100;
constexpr int64_t BUFFER_SIZE = 2 * 1024 * 1024;
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_packing.jpg";
class ImagePackerTest : public testing::Test {
public:
    ImagePackerTest() {}
    ~ImagePackerTest() {}
};

/**
 * @tc.name: GetSupportedFormats001
 * @tc.desc: test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, GetSupportedFormats001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: GetSupportedFormats001 start";
    ImagePacker pack;
    std::vector<ClassInfo> classInfos;
    std::set<std::string> formats;
    uint32_t getsupport = pack.GetSupportedFormats(formats);
    ASSERT_EQ(getsupport, OHOS::Media::SUCCESS);
    GTEST_LOG_(INFO) << "ImagePackerTest: GetSupportedFormats001 end";
}

/**
 * @tc.name: StartPacking001
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking001 start";
    ImagePacker pack;
    uint8_t *outputData = nullptr;
    uint32_t maxSize = 0;
    const PackOption option;
    uint32_t startpc = pack.StartPacking(outputData, maxSize, option);
    ASSERT_EQ(startpc, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking001 end";
}

/**
 * @tc.name: StartPacking002
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking002 start";
    ImagePacker pack;
    uint8_t *outputData = nullptr;
    uint32_t maxSize = 0;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    uint32_t startpc = pack.StartPacking(outputData, maxSize, option);
    ASSERT_EQ(startpc, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking002 end";
}

/**
 * @tc.name: StartPacking003
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking003 start";
    ImagePacker pack;
    int64_t bufferSize = BUFFER_SIZE;
    uint8_t *outputData = static_cast<uint8_t *>(malloc(bufferSize));
    uint32_t maxSize = 0;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    uint32_t startpc = pack.StartPacking(outputData, maxSize, option);
    ASSERT_EQ(startpc, 0);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking003 end";
}

/**
 * @tc.name: StartPacking004
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking004 start";
    ImagePacker pack;
    const std::string filePath;
    PackOption option;
    uint32_t startpc = pack.StartPacking(filePath, option);
    ASSERT_EQ(startpc, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking004 end";
}

/**
 * @tc.name: StartPacking005
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking005 start";
    ImagePacker pack;
    const std::string filePath = IMAGE_INPUT_JPEG_PATH;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    uint32_t startpc = pack.StartPacking(filePath, option);
    ASSERT_EQ(startpc, 0);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking005 end";
}

/**
 * @tc.name: StartPacking006
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking006 start";
    ImagePacker pack;
    const int fd = 0;
    const PackOption option;
    uint32_t startpc = pack.StartPacking(fd, option);
    ASSERT_EQ(startpc, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking006 end";
}

/**
 * @tc.name: StartPacking007
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking007 start";
    ImagePacker pack;
    const int fd = 0;
    const int fd2 = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    pack.StartPacking(fd, option);
    pack.StartPacking(fd2, option);
    PackOption option2;
    option2.format = "";
    pack.StartPacking(fd2, option2);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking007 end";
}

/**
 * @tc.name: StartPacking008
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking008 start";
    ImagePacker pack;
    std::ostream &outputStream = std::cout;
    const PackOption option;
    pack.StartPacking(outputStream, option);
    
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking008 end";
}

/**
 * @tc.name: StartPacking009
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking009 start";
    ImagePacker pack;
    std::ostream &outputStream = std::cout;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    uint32_t startpc = pack.StartPacking(outputStream, option);
    ASSERT_EQ(startpc, 0);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking009 end";
}

/**
 * @tc.name: StartPacking010
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking010 start";
    ImagePacker pack;
    uint8_t *outPut = nullptr;
    PackOption option;
    option.format = "";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    pack.StartPacking(outPut, static_cast<uint32_t>(100), option);
    pack.StartPacking(outPut, static_cast<uint32_t>(-1), option);
    uint8_t outPut2 = 1;
    pack.StartPacking(&outPut2, static_cast<uint32_t>(-1), option);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking010 end";
}

/**
 * @tc.name: StartPacking012
 * @tc.desc: test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking012 start";
    ImagePacker pack;
    const std::string filePath = IMAGE_INPUT_JPEG_PATH;
    const std::string filePath2 = "ImagePackerTestNoImage.jpg";
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    pack.StartPacking(filePath2, option);
    option.format = "";
    pack.StartPacking(filePath, option);
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking012 end";
}

/**
 * @tc.name: AddImage001
 * @tc.desc: test AddImage
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, AddImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage001 start";
    ImagePacker pack;
    PixelMap pixelMap;
    pack.AddImage(pixelMap);
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
    ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    pack.AddImage(*imageSource);
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage001 end";
}

/**
 * @tc.name: AddImage002
 * @tc.desc: test AddImage
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, AddImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage002 start";
    ImagePacker pack;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = -1;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    pack.AddImage(*imageSource);
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage002 end";
}

/**
 * @tc.name: AddImage003
 * @tc.desc: test AddImage
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, AddImage003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage003 start";
    ImagePacker pack;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 0;
    pack.AddImage(*imageSource, index);
    GTEST_LOG_(INFO) << "ImagePackerTest: AddImage003 end";
}

/**
 * @tc.name: FinalizePacking001
 * @tc.desc: test FinalizePacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, FinalizePacking001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: FinalizePacking001 start";
    ImagePacker pack;
    pack.FinalizePacking();
    GTEST_LOG_(INFO) << "ImagePackerTest: FinalizePacking001 end";
}

/**
 * @tc.name: FinalizePacking002
 * @tc.desc: test FinalizePacking
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, FinalizePacking002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: FinalizePacking002 start";
    ImagePacker pack;
    int64_t packedSize = 0;
    pack.FinalizePacking(packedSize);
    GTEST_LOG_(INFO) << "ImagePackerTest: FinalizePacking002 end";
}
} // namespace Multimedia
} // namespace OHOS