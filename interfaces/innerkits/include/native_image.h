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

#ifndef INTERFACES_INNERKITS_INCLUDE_NATIVE_IMAGE_H
#define INTERFACES_INNERKITS_INCLUDE_NATIVE_IMAGE_H

#include <map>
#include <memory>
#include <vector>
#include "image_receiver_context.h"
#include "image_format.h"

namespace OHOS {
namespace Media {
struct NativeComponent {
    int32_t rowStride = 0;
    int32_t pixelStride = 0;
    std::vector<uint8_t> raw;
    uint8_t* virAddr;
    size_t size = 0;
};

class IBufferProcessor {
public:
    virtual ~IBufferProcessor() {};
    virtual void BufferRelease(sptr<SurfaceBuffer>& buffer) = 0;
};

class NativeImage {
public:
    NativeImage(sptr<SurfaceBuffer> buffer, std::shared_ptr<IBufferProcessor> releaser);
    NativeImage(sptr<SurfaceBuffer> buffer, std::shared_ptr<IBufferProcessor> releaser, int64_t timestamp);
    ~NativeImage() = default;
    int32_t GetSize(int32_t &width, int32_t &height);
    int32_t GetDataSize(uint64_t &size);
    int32_t GetFormat(int32_t &format);
    int32_t GetTimestamp(int64_t &timestamp);
    NativeComponent* GetComponent(int32_t type);
    std::map<int32_t, std::unique_ptr<NativeComponent>>& GetComponents()
    {
        return components_;
    }
    int32_t CombineYUVComponents();
    sptr<SurfaceBuffer> GetBuffer()
    {
        return buffer_;
    }
    void release();
private:
    NativeComponent* CreateComponent(int32_t type, size_t size, int32_t row, int32_t pixel, uint8_t* vir);
    NativeComponent* CreateCombineComponent(int32_t type);
    NativeComponent* GetCachedComponent(int32_t type);
    int32_t SplitYUV422SPComponent();
    int32_t SplitSurfaceToComponent();
    uint8_t* GetSurfaceBufferAddr();
    sptr<SurfaceBuffer> buffer_;
    std::shared_ptr<IBufferProcessor> releaser_;
    std::map<int32_t, std::unique_ptr<NativeComponent>> components_;
    int64_t timestamp_;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_NATIVE_IMAGE_H
