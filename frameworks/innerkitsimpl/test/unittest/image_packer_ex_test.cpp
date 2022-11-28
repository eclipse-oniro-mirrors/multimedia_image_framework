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
#include "image_packer_ex.h"
#include "file_packer_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";

class ImagePackerExTest : public testing::Test {
public:
    ImagePackerExTest() {}
    ~ImagePackerExTest() {}
};

/**
 * @tc.name: AttrDataTest001
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerExTest, ImagePackerExTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerExTest: ImagePackerExTest001 start";
    ImagePackerEx *imageEx = new ImagePackerEx();
    std::ostream &outputStream = std::cout;
    PackOption option;
    option.format = "image/jpeg";
    imageEx->StartPacking(outputStream, option);

    PackOption option2;
    option2.format = "";
    option2.quality = 101;
    imageEx->StartPacking(outputStream, option2);
    delete imageEx;
    GTEST_LOG_(INFO) << "ImagePackerExTest: ImagePackerExTest001 end";
}
}
}