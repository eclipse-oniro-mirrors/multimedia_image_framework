/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "memory_manager.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {

constexpr uint64_t TEST_MEMORY_SIZE_1024 = 1024;

class MemoryManagerTest : public testing::Test {
public:
    MemoryManagerTest() {}
    ~MemoryManagerTest() {}
};

/**
 * @tc.name: MemoryManagerCreateMemoryTest001
 * @tc.desc: Test MemoryManager CreateMemory with CUSTOM_ALLOC type
 * @tc.type: FUNC
 */
HWTEST_F(MemoryManagerTest, MemoryManagerCreateMemoryTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MemoryManagerTest: MemoryManagerCreateMemoryTest001 start";
    
    MemoryData data;
    data.size = TEST_MEMORY_SIZE_1024;
    
    std::unique_ptr<AbsMemory> memory = MemoryManager::CreateMemory(AllocatorType::CUSTOM_ALLOC, data);
    EXPECT_EQ(memory, nullptr);
    
    GTEST_LOG_(INFO) << "MemoryManagerTest: MemoryManagerCreateMemoryTest001 end";
}
} // namespace Multimedia
} // namespace OHOS
