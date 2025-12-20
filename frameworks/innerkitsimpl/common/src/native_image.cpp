/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"
#include "native_image.h"
#if !defined(CROSS_PLATFORM)
#include "metadata_helper.h"
#include "v1_0/cm_color_space.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "NativeImage"

namespace {
    constexpr int32_t NUMI_0 = 0;
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_4 = 4;
    const std::string DATA_SIZE_TAG = "dataSize";
}

namespace OHOS {
namespace Media {

NativeImage::NativeImage(sptr<SurfaceBuffer> buffer,
    std::shared_ptr<IBufferProcessor> releaser) : buffer_(buffer), releaser_(releaser), timestamp_(0)
{}

NativeImage::NativeImage(sptr<SurfaceBuffer> buffer, std::shared_ptr<IBufferProcessor> releaser,
    int64_t timestamp) : buffer_(buffer), releaser_(releaser), timestamp_(timestamp)
{}

static const std::set<int32_t> SUPPORTED_YUVFORMAT = {
    GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
    GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
    GRAPHIC_PIXEL_FMT_YCBCR_P010,
    GRAPHIC_PIXEL_FMT_YCRCB_P010,
};

struct YUVData {
    std::vector<uint8_t> y;
    std::vector<uint8_t> u;
    std::vector<uint8_t> v;
    uint64_t ySize;
    uint64_t uvSize;
};

static inline void DataSwap(uint8_t* a, uint8_t* b, bool flip)
{
    if (flip) {
        *a = *b;
    } else {
        *b = *a;
    }
}

static inline bool IsYUV422SPFormat(int32_t format)
{
    if (format == int32_t(ImageFormat::YCBCR_422_SP) ||
        format == int32_t(GRAPHIC_PIXEL_FMT_YCBCR_422_SP)) {
        return true;
    }
    return false;
}

static void YUV422SPDataCopy(uint8_t* buffer, uint64_t size, YUVData &data, bool flip)
{
    uint64_t ui = NUM_0;
    uint64_t vi = NUM_0;
    for (uint64_t i = NUM_0; i < size; i++) {
        if (i < data.ySize) {
            DataSwap(&(buffer[i]), &(data.y[i]), flip);
            continue;
        }
        if (vi >= data.uvSize || ui >= data.uvSize) {
            // Over write buffer size.
            continue;
        }
        if (i % NUM_2 == NUM_1) {
            DataSwap(&(buffer[i]), &(data.v[vi]), flip);
            vi++;
        } else {
            DataSwap(&(buffer[i]), &(data.u[ui]), flip);
            ui++;
        }
    }
}
uint8_t* NativeImage::GetSurfaceBufferAddr()
{
    if (buffer_ != nullptr) {
        return static_cast<uint8_t*>(buffer_->GetVirAddr());
    }
    return nullptr;
}
int32_t NativeImage::SplitYUV422SPComponent()
{
    auto rawBuffer = GetSurfaceBufferAddr();
    if (rawBuffer == nullptr) {
        IMAGE_LOGE("SurfaceBuffer viraddr is nullptr");
        return ERR_MEDIA_NULL_POINTER;
    }

    uint64_t surfaceSize = NUM_0;
    auto res = GetDataSize(surfaceSize);
    if (res != SUCCESS || surfaceSize == NUM_0) {
        IMAGE_LOGE("S size is 0");
        return ERR_MEDIA_DATA_UNSUPPORT;
    }

    int32_t width = NUM_0;
    int32_t height = NUM_0;
    res = GetSize(width, height);
    if (res != SUCCESS || width <= NUMI_0 || height <= NUMI_0) {
        IMAGE_LOGE("Invaild width %{public}" PRId32 " height %{public}" PRId32, width, height);
        return ERR_MEDIA_DATA_UNSUPPORT;
    }

    struct YUVData yuv;
    uint64_t uvStride = static_cast<uint64_t>((width + NUM_1) / NUM_2);
    if (ImageUtils::CheckMulOverflow(width, height)) {
        IMAGE_LOGE("Invalid width %{public}" PRId32 " height %{public}" PRId32, width, height);
        return ERR_MEDIA_DATA_UNSUPPORT;
    }
    yuv.ySize = static_cast<uint64_t>(width) * static_cast<uint64_t>(height);
    yuv.uvSize = static_cast<uint64_t>(height) * uvStride;
    if (surfaceSize < (yuv.ySize + yuv.uvSize * NUM_2)) {
        IMAGE_LOGE("S size %{public}" PRIu64 " < y plane %{public}" PRIu64
            " + uv plane %{public}" PRIu64, surfaceSize, yuv.ySize, yuv.uvSize * NUM_2);
        return ERR_MEDIA_DATA_UNSUPPORT;
    }

    NativeComponent* y = CreateComponent(int32_t(ComponentType::YUV_Y), yuv.ySize, width, NUM_1, nullptr);
    NativeComponent* u = CreateComponent(int32_t(ComponentType::YUV_U), yuv.uvSize, uvStride, NUM_2, nullptr);
    NativeComponent* v = CreateComponent(int32_t(ComponentType::YUV_V), yuv.uvSize, uvStride, NUM_2, nullptr);
    if ((y == nullptr) || (u == nullptr) || (v == nullptr)) {
        IMAGE_LOGE("Create Component failed");
        return ERR_MEDIA_DATA_UNSUPPORT;
    }
    yuv.y = y->raw;
    yuv.u = u->raw;
    yuv.v = v->raw;
    YUV422SPDataCopy(rawBuffer, surfaceSize, yuv, false);
    return SUCCESS;
}

int32_t NativeImage::SplitSurfaceToComponent()
{
    int32_t format = NUM_0;
    auto res = GetFormat(format);
    if (res != SUCCESS) {
        return res;
    }
    switch (format) {
        case int32_t(ImageFormat::YCBCR_422_SP):
        case int32_t(GRAPHIC_PIXEL_FMT_YCBCR_422_SP):
            return SplitYUV422SPComponent();
        case int32_t(ImageFormat::JPEG):
            bool cond = CreateCombineComponent(int32_t(ComponentType::JPEG)) != nullptr;
            CHECK_ERROR_RETURN_RET(cond, SUCCESS);
    }
    // Unsupport split component
    return ERR_MEDIA_DATA_UNSUPPORT;
}

int32_t NativeImage::CombineYUVComponents()
{
    int32_t format = NUM_0;
    auto res = GetFormat(format);
    if (res != SUCCESS) {
        return res;
    }
    if (!IsYUV422SPFormat(format)) {
        IMAGE_LOGI("No need to combine components for NO YUV format now");
        return SUCCESS;
    }

    uint8_t* buffer = GetSurfaceBufferAddr();
    if (buffer == nullptr) {
        IMAGE_LOGE("SurfaceBuffer viraddr is nullptr");
        return ERR_MEDIA_DATA_UNSUPPORT;
    }

    uint64_t bufferSize = NUM_0;
    res = GetDataSize(bufferSize);
    if (res != SUCCESS || bufferSize == NUM_0) {
        IMAGE_LOGE("bufferSize is 0");
        return ERR_MEDIA_DATA_UNSUPPORT;
    }

    auto y = GetComponent(int32_t(ComponentType::YUV_Y));
    auto u = GetComponent(int32_t(ComponentType::YUV_U));
    auto v = GetComponent(int32_t(ComponentType::YUV_V));
    bool cond = (y == nullptr) || (u == nullptr) || (v == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_MEDIA_DATA_UNSUPPORT, "No component need to combine");
    YUVData data;
    data.ySize = y->raw.size();
    data.uvSize = u->raw.size();
    data.y = y->raw;
    data.u = u->raw;
    data.v = v->raw;

    YUV422SPDataCopy(buffer, bufferSize, data, true);
    return SUCCESS;
}

static std::unique_ptr<NativeComponent> BuildComponent(size_t size, int32_t row, int32_t pixel, uint8_t* vir)
{
    if (size == NUM_0 && vir == nullptr) {
        IMAGE_LOGE("Could't create 0 size component data");
        return nullptr;
    }
    std::unique_ptr<NativeComponent> component = std::make_unique<NativeComponent>();
    component->pixelStride = pixel;
    component->rowStride = row;
    component->size = size;
    if (vir != nullptr) {
        component->virAddr = vir;
    } else {
        component->raw.resize(size);
    }
    return component;
}

NativeComponent* NativeImage::GetCachedComponent(int32_t type)
{
    auto iter = components_.find(type);
    if (iter != components_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

NativeComponent* NativeImage::CreateComponent(int32_t type, size_t size, int32_t row,
    int32_t pixel, uint8_t* vir)
{
    NativeComponent* res = GetCachedComponent(type);
    if (res != nullptr) {
        IMAGE_LOGD("Component %{public}d already exist. No need create", type);
        return res;
    }

    std::unique_ptr<NativeComponent> component = BuildComponent(size, row, pixel, vir);
    if (component == nullptr) {
        return nullptr;
    }
    components_.insert(std::map<int32_t, std::unique_ptr<NativeComponent>>::value_type(type,
        std::move(component)));

    return GetCachedComponent(type);
}

NativeComponent* NativeImage::CreateCombineComponent(int32_t type)
{
    uint64_t size = NUM_0;
    GetDataSize(size);
    return CreateComponent(type, static_cast<size_t>(size), buffer_->GetStride(), NUM_1, GetSurfaceBufferAddr());
}
int32_t NativeImage::GetSize(int32_t &width, int32_t &height)
{
    if (buffer_ == nullptr) {
        return ERR_MEDIA_DEAD_OBJECT;
    }
    width = buffer_->GetWidth();
    height = buffer_->GetHeight();
    return SUCCESS;
}

int32_t NativeImage::GetDataSize(uint64_t &size)
{
    if (buffer_ == nullptr) {
        return ERR_MEDIA_DEAD_OBJECT;
    }

    size = static_cast<uint64_t>(buffer_->GetSize());
    auto extraData = buffer_->GetExtraData();
    if (extraData == nullptr) {
        IMAGE_LOGI("Nullptr s extra data. return buffer size %{public}" PRIu64, size);
        return SUCCESS;
    }

    int32_t extraDataSize = NUMI_0;
    auto res = extraData->ExtraGet(DATA_SIZE_TAG, extraDataSize);
    if (res != NUM_0) {
        IMAGE_LOGI("S ExtraGet dataSize error %{public}d", res);
    } else if (extraDataSize <= NUMI_0) {
        IMAGE_LOGI("S ExtraGet dataSize Ok, but size <= 0");
    } else if (static_cast<uint64_t>(extraDataSize) > size) {
        IMAGE_LOGI("S ExtraGet dataSize Ok,but dataSize %{public}d is bigger than bufferSize %{public}" PRIu64,
            extraDataSize, size);
    } else {
        IMAGE_LOGD("S ExtraGet dataSize %{public}d", extraDataSize);
        size = static_cast<uint64_t>(extraDataSize);
    }
    return SUCCESS;
}

int32_t NativeImage::GetFormat(int32_t &format)
{
    if (buffer_ == nullptr) {
        return ERR_MEDIA_DEAD_OBJECT;
    }
    format = buffer_->GetFormat();
    return SUCCESS;
}

int32_t NativeImage::GetTimestamp(int64_t &timestamp)
{
    if (buffer_ == nullptr) {
        return ERR_MEDIA_DEAD_OBJECT;
    }
    timestamp = timestamp_;
    return SUCCESS;
}

int32_t NativeImage::GetColorSpace(int32_t &colorSpace)
{
#if !defined(CROSS_PLATFORM)
    if (buffer_ == nullptr) {
        IMAGE_LOGE("GetColorSpace failed, buffer is nullptr");
        return ERR_MEDIA_DEAD_OBJECT;
    }
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;
    GSError ret = OHOS::MetadataHelper::GetColorSpaceType(buffer_, colorSpaceType);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("GetColorSpaceType failed ret=%{public}d", ret);
        return ERR_MEDIA_DATA_UNSUPPORT;
    }
    colorSpace = static_cast<int32_t>(colorSpaceType);
#else
    colorSpace = NUMI_0;
#endif
    return SUCCESS;
}

static int32_t GetStrides(sptr<SurfaceBuffer> buffer, std::vector<int32_t> &rowStride,
    std::vector<int32_t> &pixelStride)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("Buffer is nullptr");
        return ERR_MEDIA_NULL_POINTER;
    }
    int32_t format = buffer->GetFormat();
    if (format == GRAPHIC_PIXEL_FMT_BLOB) {
        rowStride = { buffer->GetStride() };
        pixelStride = { NUM_1 };
    } else if (format == GRAPHIC_PIXEL_FMT_RGBA_8888) {
        rowStride = { buffer->GetStride() };
        pixelStride = { NUM_4 };
    } else if (SUPPORTED_YUVFORMAT.count(format) != NUM_0) {
        OH_NativeBuffer_Planes* planes = nullptr;
        void* rawPlanes = nullptr;
        GSError retVal = buffer->GetPlanesInfo(&rawPlanes);
        planes = static_cast<OH_NativeBuffer_Planes*>(rawPlanes);
        if (retVal != OHOS::GSERROR_OK || planes == nullptr || planes->planeCount < NUM_2) {
            IMAGE_LOGE("Get planesInfo failed, retVal:%{public}d", retVal);
            return ERR_MEDIA_DATA_UNSUPPORT;
        } else {
            uint32_t uvPlaneIndex = NUM_1;
            uint32_t yRowStride = planes->planes[0].columnStride;
            uint32_t yPixelStride = planes->planes[0].rowStride;
            uint32_t uvRowStride = planes->planes[uvPlaneIndex].columnStride;
            uint32_t uvPixelStride = planes->planes[uvPlaneIndex].rowStride;
            rowStride = { yRowStride, uvRowStride };
            pixelStride = { yPixelStride, uvPixelStride };
        }
    } else {
        IMAGE_LOGE("Unsupported format %{public}d for GetStrides", format);
        return ERR_MEDIA_DATA_UNSUPPORT;
    }
    return SUCCESS;
}

NativeBufferData* NativeImage::GetBufferData()
{
    if (bufferData_ != nullptr) {
        return bufferData_.get();
    }
    bufferData_ = std::make_unique<NativeBufferData>();
    auto res = GetStrides(buffer_, bufferData_->rowStride, bufferData_->pixelStride);
    if (res != SUCCESS) {
        IMAGE_LOGE("GetStrides failed");
        return nullptr;
    }
    uint64_t bufferSize = NUM_0;
    res = GetDataSize(bufferSize);
    if (res != SUCCESS) {
        IMAGE_LOGE("GetDataSize failed");
        return nullptr;
    }
    bufferData_->size = static_cast<size_t>(bufferSize);
    bufferData_->virAddr = GetSurfaceBufferAddr();
    if (bufferData_->virAddr == nullptr) {
        IMAGE_LOGE("GetSurfaceBufferAddr failed");
        return nullptr;
    }
    return bufferData_.get();
}

NativeComponent* NativeImage::GetComponent(int32_t type)
{
    if (buffer_ == nullptr) {
        return nullptr;
    }

    // Find type if it has exist.
    auto component = GetCachedComponent(type);
    if (component != nullptr) {
        return component;
    }

    int32_t format = NUM_0;
    if (GetFormat(format) == SUCCESS && type == format) {
        return CreateCombineComponent(type);
    }
    SplitSurfaceToComponent();
    // Try again
    component = GetCachedComponent(type);

#ifdef COMPONENT_STRICT_CHECK
    return component;
#else // We don't check the input type anymore, return raw format component!!
    if (component == nullptr && GetFormat(format) == SUCCESS) {
        return CreateCombineComponent(format);
    }
    return nullptr;
#endif
}

void NativeImage::release()
{
    if (buffer_ == nullptr) {
        return;
    }
    IMAGE_LOGD("NativeImage release");
    if (components_.size() > 0) {
        components_.clear();
    }
    if (releaser_ != nullptr && buffer_ != nullptr) {
        releaser_->BufferRelease(buffer_);
    }
    releaser_ = nullptr;
    buffer_ = nullptr;
}
} // namespace Media
} // namespace OHOS
