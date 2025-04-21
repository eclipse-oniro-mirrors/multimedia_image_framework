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
#include "image_receiver_impl.h"

namespace OHOS {
namespace Multimedia {
using namespace testing::ext;
using namespace OHOS::Media;

class ImageReceiverImplTest : public testing::Test {
public:
    ImageReceiverImplTest() {}
    ~ImageReceiverImplTest() {}
};

/**
 * @tc.name: ImageReceiverImplTest001
 * @tc.desc: test ImageReceiverImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverImplTest, ImageReceiverImplTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverImplTest: ImageReceiverImplTest001 start";
    ImageReceiverImpl imageReceiverNull(nullptr);
    CSize size;
    imageReceiverNull.GetSize(&size);
    int32_t capacity;
    imageReceiverNull.GetCapacity(&capacity);
    int32_t format;
    imageReceiverNull.GetFormat(&format);
    imageReceiverNull.GetReceivingSurfaceId();
    imageReceiverNull.ReadNextImage();
    imageReceiverNull.ReadLatestImage();
    imageReceiverNull.Release();
    ImageReceiverImpl::CreateImageReceiver(0, 0, 0, 0);
    ImageReceiverImpl::CreateImageReceiver(100, 100, 2000, 8);
    GTEST_LOG_(INFO) << "ImageReceiverImplTest: ImageReceiverImplTest001 end";
}

/**
 * @tc.name: ImageReceiverImplTest002
 * @tc.desc: test ImageReceiverImpl
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverImplTest, ImageReceiverImplTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverImplTest: ImageReceiverImplTest002 start";
    auto imageReceiver = ImageReceiver::CreateImageReceiver(100, 100, 2000, 8);
    ImageReceiverImpl imageReceiverNull(imageReceiver);
    CSize size;
    imageReceiverNull.GetSize(&size);
    int32_t capacity;
    imageReceiverNull.GetCapacity(&capacity);
    int32_t format;
    imageReceiverNull.GetFormat(&format);
    imageReceiverNull.GetReceivingSurfaceId();
    imageReceiverNull.ReadNextImage();
    imageReceiverNull.ReadLatestImage();
    GTEST_LOG_(INFO) << "ImageReceiverImplTest: ImageReceiverImplTest002 end";
}
}
}