/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hardware/imagecodec/image_codec_buffer.h"
#include "hardware/imagecodec/image_codec_log.h"
#include "sys/mman.h"
#include "ashmem.h" // commonlibrary/c_utils/base/include/ashmem.h

namespace OHOS::ImagePlugin {
using namespace std;

/*============================ ImageCodecBuffer ====================================*/
std::shared_ptr<ImageCodecBuffer> ImageCodecBuffer::CreateDmaBuffer(int fd, int32_t capacity, int32_t stride)
{
    if (fd < 0 || capacity <= 0) {
        LOGE("invalid input param: fd=%{public}d, capacity=%{public}d", fd, capacity);
        return nullptr;
    }
    return make_shared<ImageDmaBuffer>(dup(fd), capacity, stride);
}

std::shared_ptr<ImageCodecBuffer> ImageCodecBuffer::CreateSurfaceBuffer(const BufferRequestConfig &config)
{
    std::shared_ptr<ImageCodecBuffer> buf = make_shared<ImageSurfaceBuffer>(config);
    if (buf != nullptr && buf->Init()) {
        return buf;
    }
    return nullptr;
}

std::shared_ptr<ImageCodecBuffer> ImageCodecBuffer::CreateSurfaceBuffer(sptr<SurfaceBuffer> surface)
{
    std::shared_ptr<ImageCodecBuffer> buf = make_shared<ImageSurfaceBuffer>(surface);
    return buf;
}

/*============================ ImageDmaBuffer ====================================*/
ImageDmaBuffer::ImageDmaBuffer(int fd, int32_t capacity, int32_t stride): fd_(fd)
{
    capacity_ = capacity;
    stride_ = stride;
}

ImageDmaBuffer::~ImageDmaBuffer()
{
    if (addr_ != nullptr) {
        (void)::munmap(addr_, static_cast<size_t>(capacity_));
        addr_ = nullptr;
    }

    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

uint8_t* ImageDmaBuffer::GetAddr()
{
    if (addr_ == nullptr) {
        IF_TRUE_RETURN_VAL_WITH_MSG(fd_ < 0, nullptr, "invalid fd=%{public}d", fd_);
        unsigned int prot = PROT_READ | PROT_WRITE;
        void *addr = ::mmap(nullptr, static_cast<size_t>(capacity_), static_cast<int>(prot), MAP_SHARED, fd_, 0);
        IF_TRUE_RETURN_VAL_WITH_MSG(addr == MAP_FAILED, nullptr, "mmap failed for fd=%{public}d", fd_);
        addr_ = reinterpret_cast<uint8_t*>(addr);
    }
    return addr_;
}

/*============================ ImageSurfaceBuffer ====================================*/
ImageSurfaceBuffer::ImageSurfaceBuffer(const BufferRequestConfig &config): config_(config)
{}

ImageSurfaceBuffer::ImageSurfaceBuffer(sptr<SurfaceBuffer> surface)
{
    surfaceBuffer_ = surface;
    stride_ = surfaceBuffer_->GetStride();
}

ImageSurfaceBuffer::~ImageSurfaceBuffer()
{
    if (addr_ != nullptr) {
        GSError ret = surfaceBuffer_->Unmap();
        if (ret != GSERROR_OK) {
            LOGE("failed to unmap surface buffer");
        }
        addr_ = nullptr;
    }
}

bool ImageSurfaceBuffer::Init()
{
    surfaceBuffer_ = SurfaceBuffer::Create();
    IF_TRUE_RETURN_VAL_WITH_MSG(surfaceBuffer_ == nullptr, false, "failed to create surface buffer");
    GSError ret = surfaceBuffer_->Alloc(config_);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != GSERROR_OK, false, "failed to alloc surface buffer");
    capacity_ = static_cast<int32_t>(surfaceBuffer_->GetSize());
    stride_ = surfaceBuffer_->GetStride();
    return true;
}

int32_t ImageSurfaceBuffer::GetFileDescriptor()
{
    return surfaceBuffer_->GetFileDescriptor();
}

uint8_t* ImageSurfaceBuffer::GetAddr()
{
    if (addr_ == nullptr) {
        GSError ret = surfaceBuffer_->Map();
        IF_TRUE_RETURN_VAL_WITH_MSG(ret != GSERROR_OK, nullptr,
                                    "mmap failed, err=%{public}s", GSErrorStr(ret).c_str());
        addr_ = reinterpret_cast<uint8_t*>(surfaceBuffer_->GetVirAddr());
        if (surfaceBuffer_->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE) {
            ret = surfaceBuffer_->InvalidateCache();
            if (ret != GSERROR_OK) {
                LOGW("InvalidateCache failed, GSError=%{public}d", ret);
            }
        }
    }
    return addr_;
}

sptr<SurfaceBuffer> ImageSurfaceBuffer::GetSurfaceBuffer()
{
    return surfaceBuffer_;
}
} // namespace OHOS::ImagePlugin