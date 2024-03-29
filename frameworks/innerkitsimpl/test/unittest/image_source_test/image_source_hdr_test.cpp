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
#include <fstream>
#include <fcntl.h>
#include "hilog/log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "file_source_stream.h"
#include "buffer_source_stream.h"
#include "ext_stream.h"
#include "hdr_helper.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = {
    LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceJpegTest"
};

static const std::string IMAGE_INPUT_ULTRA_HDR_PATH = "/data/local/tmp/image/ultrahdr.jpg";

class ImageSourceHdrTest : public testing::Test {
public:
    ImageSourceHdrTest() {}
    ~ImageSourceHdrTest() {}
};

/**
 * @tc.name: HdrDecode001
 * @tc.desc: Test UltraHdr decode
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, HdrDecode001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_ULTRA_HDR_PATH,
                                                                              opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::DEFAULT;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
#ifdef IMAGE_HDR_CONVERTER_FLAG
    ASSERT_EQ(pixelMap->GetPixelFormat(), Media::PixelFormat::RGBA_1010102);
#endif
}
}
}