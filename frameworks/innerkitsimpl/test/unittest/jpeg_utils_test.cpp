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
#define private public
#include "gtest/gtest.h"
#include "jpeg_utils.h"
#include "buffer_source_stream.h"
#include "image_packer.h"
#include "jpeg_decoder.h"

using namespace testing::ext;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace ImagePlugin {
    class JpegUtilsTest : public testing::Test {
public:
    JpegUtilsTest() {}
    ~JpegUtilsTest() {}
};


}
}