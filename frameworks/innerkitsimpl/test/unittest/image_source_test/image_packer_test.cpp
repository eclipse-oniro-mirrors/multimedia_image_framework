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
#include <filesystem>
#include <fstream>
#include <vector>
#include "image/abs_image_encoder.h"
#include "image_packer.h"
#include "buffer_packer_stream.h"
#include "file_packer_stream.h"
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "ostream_packer_stream.h"
#include "plugin_server.h"
#include "jpeg_exif_metadata_accessor.h"
#include "file_metadata_stream.h"
#include "metadata_accessor_factory.h"
#include "metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;
using namespace OHOS::ImagePlugin;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_100 = 100;
constexpr int64_t BUFFER_SIZE = 2 * 1024 * 1024;
constexpr uint32_t MAX_IMAGE_SIZE = 10 * 1024;
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_packing.jpg";
static const std::string IMAGE_JPG_SRC = "/data/local/tmp/image/test_packing_exif.jpg";
static const std::string IMAGE_JPG_DEST = "/data/local/tmp/image/test_jpg2jpg_out.jpg";
static const std::string IMAGE_PNG_SRC = "/data/local/tmp/image/test.png";
static const std::string IMAGE_PNG2JPG_DEST = "/data/local/tmp/image/test_png2jepg_out.jpg";

class ImagePackerTest : public testing::Test {
public:
    ImagePackerTest() {}
    ~ImagePackerTest() {}
};

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
    const int fd2 = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    PackOption option;
    option.format = "image/jpeg";
    option.quality = NUM_100;
    option.numberHint = NUM_1;
    pack.StartPacking(fd2, option);
    PackOption option2;
    option2.format = "";
    uint32_t ret = pack.StartPacking(fd2, option2);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    uint32_t ret = pack.StartPacking(outputStream, option);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    uint32_t ret = pack.StartPacking(&outPut2, static_cast<uint32_t>(-1), option);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    uint32_t ret = pack.StartPacking(filePath, option);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t ret = pack.AddImage(*imageSource);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t ret = pack.AddImage(*imageSource);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    uint32_t index = 0;
    uint32_t ret = pack.AddImage(*imageSource, index);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    uint32_t ret = pack.FinalizePacking();
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
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
    uint32_t ret = pack.FinalizePacking(packedSize);
    ASSERT_NE(ret, OHOS::Media::SUCCESS);
    GTEST_LOG_(INFO) << "ImagePackerTest: FinalizePacking002 end";
}

/**
 * @tc.name: StartPacking013
 * @tc.desc: test StartPacking013 with uint8_t *outputData jpeg => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking013 start";

    uint32_t errorCode = -1;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    const int fileSize = 1024 * 1024 * 10;
    ImagePacker pack;

    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    std::ofstream fileDestJpg(IMAGE_JPG_DEST, std::ios::binary);
    ASSERT_TRUE(fileDestJpg.is_open());
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    fileDestJpg.write(reinterpret_cast<char *>(outputData.data()), fileSize);
    ASSERT_FALSE(fileDestJpg.bad());
    fileDestJpg.close();

    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(outputData.data(), fileSize, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking013 end";
}

/**
 * @tc.name: StartPacking014
 * @tc.desc: test StartPacking014 with const std::string &filePath jpeg => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking014 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(IMAGE_JPG_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);

    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_JPG_DEST, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking014 end";
}

/**
 * @tc.name: StartPacking015
 * @tc.desc: test StartPacking015 with std::ostream &outputStream jpeg => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking015 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    std::ofstream stream(IMAGE_JPG_DEST, std::ios::binary);
    ASSERT_TRUE(stream.is_open());
    uint32_t startpc = pack.StartPacking(stream, option);

    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    std::unique_ptr<std::ifstream> istreamDest = std::make_unique<std::ifstream>(IMAGE_PNG2JPG_DEST, std::ios::binary);
    ASSERT_NE(istreamDest, nullptr);
    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(std::move(istreamDest), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking015 end";
}

/**
 * @tc.name: StartPacking016
 * @tc.desc: test StartPacking016 with const int &fd jpeg => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking016 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    const int fd = open(IMAGE_JPG_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(fd, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    std::cout << "Time taken by FinalizePacking: " << diff.count() << " s\n";

    const int fdDest = open(IMAGE_JPG_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(fdDest, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking016 end";
}

/**
 * @tc.name: StartPacking017
 * @tc.desc: test StartPacking017 with uint8_t *outputData png => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking017 start";

    uint32_t errorCode = -1;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_PNG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    std::vector<uint8_t> outputData(MAX_IMAGE_SIZE);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(outputData.data(), MAX_IMAGE_SIZE, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    std::ofstream fileDestJpg(IMAGE_PNG2JPG_DEST, std::ios::binary);
    ASSERT_TRUE(fileDestJpg.is_open());
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    fileDestJpg.write(reinterpret_cast<char *>(outputData.data()), MAX_IMAGE_SIZE);
    ASSERT_FALSE(fileDestJpg.bad());
    fileDestJpg.close();

    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(outputData.data(), MAX_IMAGE_SIZE, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking017 end";
}

/**
 * @tc.name: StartPacking018
 * @tc.desc: test StartPacking018 with const std::string &filePath png => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking018 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_PNG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(IMAGE_PNG2JPG_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);

    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_PNG2JPG_DEST, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking018 end";
}

/**
 * @tc.name: StartPacking019
 * @tc.desc: test StartPacking019 with std::ostream &outputStream png => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking019 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_PNG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    std::ofstream stream(IMAGE_PNG2JPG_DEST, std::ios::binary);
    ASSERT_TRUE(stream.is_open());
    uint32_t startpc = pack.StartPacking(stream, option);

    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    std::unique_ptr<std::ifstream> istreamDest = std::make_unique<std::ifstream>(IMAGE_PNG2JPG_DEST, std::ios::binary);
    ASSERT_NE(istreamDest, nullptr);
    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(std::move(istreamDest), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking019 end";
}

/**
 * @tc.name: StartPacking020
 * @tc.desc: test StartPacking020 with const int &fd png => jpeg
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerTest, StartPacking020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking020 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_PNG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    ImagePacker pack;
    const int fd = open(IMAGE_PNG2JPG_DEST.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(fd, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    const int fdDest = open(IMAGE_PNG2JPG_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(fdDest, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    close(fd);
    close(fdDest);

    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking020 end";
}
} // namespace Multimedia
} // namespace OHOS
