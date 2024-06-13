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

#ifndef IMAGE_CODEC_BUFFER_H
#define IMAGE_CODEC_BUFFER_H

#include "surface_type.h" // foundation/graphic/graphic_surface/interfaces/inner_api/surface/surface_type.h
#include "surface_buffer.h" // foundation/graphic/graphic_surface/interfaces/inner_api/surface/surface_buffer.h

namespace OHOS::ImagePlugin {
enum YuvSemiPlanarArrangement {
    PLANE_Y = 0,
    PLANE_U,
    PLANE_V,
    PLANE_BUTT
};

class ImageCodecBuffer {
public:
    static std::shared_ptr<ImageCodecBuffer> CreateDmaBuffer(int fd, int32_t capacity, int32_t stride);
    static std::shared_ptr<ImageCodecBuffer> CreateSurfaceBuffer(const BufferRequestConfig &config);
    static std::shared_ptr<ImageCodecBuffer> CreateSurfaceBuffer(sptr<SurfaceBuffer> surface);

    virtual ~ImageCodecBuffer() = default;
    void GetBufferCirculateInfo(int64_t& pts, uint32_t& flag, uint32_t& size, uint32_t& offset) const
    {
        pts = pts_;
        flag = flag_;
        size = size_;
        offset = offset_;
    }
    void SetBufferCirculateInfo(int64_t pts, uint32_t flag, uint32_t size, uint32_t offset)
    {
        pts_ = pts;
        flag_ = flag;
        size_ = size;
        offset_ = offset;
    }
    uint32_t GetBufferFlag() const { return flag_; }
    int64_t GetPts() const { return pts_; }
    int32_t GetCapacity() const { return capacity_; }
    int32_t GetStride() const { return stride_; }
    virtual bool Init() = 0;
    virtual int32_t GetFileDescriptor() = 0;
    virtual sptr<SurfaceBuffer> GetSurfaceBuffer() = 0;
    virtual uint8_t* GetAddr() = 0;
protected:
    ImageCodecBuffer() = default;
protected:
    int64_t pts_ = 0;
    uint32_t size_ = 0;
    uint32_t offset_ = 0;
    uint32_t flag_; // OMX_BUFFERFLAG_X defined in OMX_Core.h
    int32_t capacity_ = 0;
    int32_t stride_ = 0;
};

class ImageDmaBuffer : public ImageCodecBuffer {
public:
    ImageDmaBuffer(int fd, int32_t capacity, int32_t stride);
    ~ImageDmaBuffer();
    bool Init() override { return true; }
    int32_t GetFileDescriptor() override { return fd_; }
    sptr<SurfaceBuffer> GetSurfaceBuffer() override { return nullptr; }
    uint8_t* GetAddr() override;
private:
    int32_t fd_ = -1;
    uint8_t* addr_ = nullptr;
};

class ImageSurfaceBuffer : public ImageCodecBuffer {
public:
    explicit ImageSurfaceBuffer(const BufferRequestConfig &config);
    explicit ImageSurfaceBuffer(sptr<SurfaceBuffer> surface);
    ~ImageSurfaceBuffer();
    bool Init() override;
    int32_t GetFileDescriptor() override;
    uint8_t* GetAddr() override;
    sptr<SurfaceBuffer> GetSurfaceBuffer() override;
private:
    BufferRequestConfig config_{};
    sptr<SurfaceBuffer> surfaceBuffer_ = nullptr;
    uint8_t* addr_ = nullptr;
};

} // namespace OHOS::ImagePlugin
#endif