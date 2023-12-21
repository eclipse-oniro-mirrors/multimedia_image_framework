/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "hardware/jpeg_hw_decoder.h"
#include "mock_jpeg_hw_decode_flow.h"
#include "image_system_properties.h"

namespace OHOS::Media {
using namespace testing::ext;
using namespace OHOS::ImagePlugin;
using namespace OHOS::HDI::Codec::Image::V1_0;

class JpegHwDecoderTest : public testing::Test {
public:
    static constexpr char JPEG_FORMAT[] = "image/jpeg";
    static constexpr char HEIF_FORMAT[] = "image/heif";
    static constexpr char TEST_JPEG_IMG[] = "/data/local/tmp/image/test_hw1.jpg";
};

HWTEST_F(JpegHwDecoderTest, unsupported_img_empty_format, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    PlSize srcImgSize = {
        .width = 8192,
        .height = 8192
    };
    bool ret = testObj.IsHardwareDecodeSupported("", srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_unknown_format, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    PlSize srcImgSize = {
        .width = 512,
        .height = 512
    };
    bool ret = testObj.IsHardwareDecodeSupported(HEIF_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_size_too_small, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    PlSize srcImgSize = {
        .width = 140,
        .height = 512
    };
    bool ret = testObj.IsHardwareDecodeSupported(JPEG_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_size_too_big, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    PlSize srcImgSize = {
        .width = 8192,
        .height = 8193
    };
    bool ret = testObj.IsHardwareDecodeSupported(JPEG_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, decode_ok, TestSize.Level1)
{
    CommandOpt opt;
    opt.width = 1280;
    opt.height = 768;
    opt.sampleSize = 1;
    opt.inputFile = TEST_JPEG_IMG;
    JpegHwDecoderFlow demo;
    bool ret = true;
    if (ImageSystemProperties::GetHardWareDecodeEnabled()) {
        ret = demo.Run(opt, false);
    }
    ASSERT_TRUE(ret);
}
} // namespace OHOS::Media