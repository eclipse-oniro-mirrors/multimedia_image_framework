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
#include "image_impl.h"

namespace OHOS {
namespace Multimedia {
using namespace testing::ext;
using namespace OHOS::Media;

class ImageImplTest : public testing::Test {
public:
    ImageImplTest() {}
    ~ImageImplTest() {}
};

/**
 * @tc.name: ImageImplTest001
 * @tc.desc: test ImageImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageImplTest, ImageImplTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageImplTest: ImageImplTest001 start";
    ImageImpl imageImplNull(nullptr);
    imageImplNull.GetNativeImage();
    CRegion region;
    imageImplNull.GetClipRect(&region);
    CSize size;
    imageImplNull.GetSize(&size);
    int32_t format;
    imageImplNull.GetFormat(&format);
    CRetComponent component;
    imageImplNull.GetComponent(0, &component);
    imageImplNull.Release();
    GTEST_LOG_(INFO) << "ImageImplTest: ImageImplTest001 end";
}
}
}