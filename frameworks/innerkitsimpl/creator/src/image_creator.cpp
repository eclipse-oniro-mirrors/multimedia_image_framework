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

#include "image_creator.h"

#include "image_creator_buffer_processor.h"
#include "image_creator_manager.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "imageCreator"

namespace OHOS {
namespace Media {
std::map<uint8_t*, ImageCreator*> ImageCreator::bufferCreatorMap_;
ImageCreator::~ImageCreator()
{
    if (iraContext_ != nullptr) {
        ImageCreatorManager::ReleaseCreatorById(iraContext_->GetCreatorKey());
    }
    creatorConsumerSurface_ = nullptr;
    creatorProducerSurface_ = nullptr;
    iraContext_ = nullptr;
    surfaceBufferReleaseListener_ = nullptr;
    surfaceBufferAvaliableListener_ = nullptr;
}

GSError ImageCreator::OnBufferRelease(sptr<SurfaceBuffer> &buffer)
{
    IMAGE_LOGI("OnBufferRelease");
    if (buffer == nullptr) {
        return GSERROR_NO_ENTRY;
    }
    auto iter = bufferCreatorMap_.find(static_cast<uint8_t*>(buffer->GetVirAddr()));
    if (iter == bufferCreatorMap_.end()) {
        return GSERROR_NO_ENTRY;
    }
    auto icr = iter->second;
    if (icr->surfaceBufferReleaseListener_ == nullptr) {
        IMAGE_LOGI("empty icr");
        return GSERROR_NO_ENTRY;
    }
    icr->surfaceBufferReleaseListener_->OnSurfaceBufferRelease();
    bufferCreatorMap_.erase(iter);
    return GSERROR_NO_ENTRY;
}

std::shared_ptr<ImageCreatorContext> ImageCreatorContext ::CreateImageCreatorContext()
{
    std::shared_ptr<ImageCreatorContext> icc = std::make_shared<ImageCreatorContext>();
    return icc;
}

void ImageCreatorSurfaceListener ::OnBufferAvailable()
{
    IMAGE_LOGD("CreatorBufferAvailable");
    if (ic_->surfaceBufferAvaliableListener_ != nullptr) {
        ic_->surfaceBufferAvaliableListener_->OnSurfaceBufferAvaliable();
    }
}

std::shared_ptr<ImageCreator> ImageCreator::CreateImageCreator(int32_t width,
    int32_t height, int32_t format, int32_t capicity)
{
    std::shared_ptr<ImageCreator> iva = std::make_shared<ImageCreator>();
    iva->iraContext_ = ImageCreatorContext::CreateImageCreatorContext();
    iva->creatorConsumerSurface_ = IConsumerSurface::Create();
    if (iva->creatorConsumerSurface_ == nullptr) {
        IMAGE_LOGD("SurfaceAsConsumer == nullptr");
        return iva;
    }
    iva->creatorConsumerSurface_->SetDefaultWidthAndHeight(width, height);
    iva->creatorConsumerSurface_->SetQueueSize(capicity);
    sptr<ImageCreatorSurfaceListener> listener = new ImageCreatorSurfaceListener();
    listener->ic_ = iva;
    iva->creatorConsumerSurface_->
    RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    auto p = iva->creatorConsumerSurface_->GetProducer();
    iva->creatorProducerSurface_ = Surface::CreateSurfaceAsProducer(p);
    if (iva->creatorProducerSurface_ == nullptr) {
        IMAGE_LOGD("SurfaceAsProducer == nullptr");
        return iva;
    }
    iva->creatorProducerSurface_->SetQueueSize(capicity);
    iva->iraContext_->SetCreatorBufferConsumer(iva->creatorConsumerSurface_);
    iva->iraContext_->SetCreatorBufferProducer(iva->creatorProducerSurface_);
    iva->iraContext_->SetWidth(width);
    iva->iraContext_->SetHeight(height);
    iva->iraContext_->SetFormat(format);
    iva->iraContext_->SetCapicity(capicity);
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    std::string creatorKey = imageCreatorManager.SaveImageCreator(iva);
    iva->iraContext_->SetCreatorKey(creatorKey);
    iva->creatorProducerSurface_->
    RegisterReleaseListener(OnBufferRelease);
    return iva;
}

int64_t CreatorPackImage(uint8_t *tempBuffer, uint32_t bufferSize, std::unique_ptr<PixelMap> pixelMap)
{
    IMAGE_LOGD("PackImage");
    ImagePacker imagePacker;
    PackOption option;
    option.format = ImageReceiver::OPTION_FORMAT;
    option.quality = ImageReceiver::OPTION_QUALITY;
    option.numberHint = ImageReceiver::OPTION_NUMBERHINT;
    std::set<std::string> formats;

    uint32_t ret = imagePacker.GetSupportedFormats(formats);
    if (ret != SUCCESS) {
        IMAGE_LOGE("image packer get supported format failed, ret=%{public}u.", ret);
        return 0;
    } else {
        IMAGE_LOGD("SUCCESS");
    }
    imagePacker.StartPacking(tempBuffer, bufferSize, option);
    imagePacker.AddImage(*pixelMap);
    int64_t packedSize = 0;
    imagePacker.FinalizePacking(packedSize);
    IMAGE_LOGI("packedSize=%{public}lld.", static_cast<long long>(packedSize));
    return packedSize;
}
static const int BIT4 = 4;
static const int PRINT_WIDTH = 100;
static const int PRINT_WIDTH_MOD = 99;
static const uint8_t BIT4_MASK = 0xf;
static void dumpBuffer(const uint8_t* tempBuffer, int64_t size)
{
    std::vector<char> ss;
    char xx[] = "0123456789ABCDEF";
    for (int i = 0; i < size; i++) {
        ss.push_back(xx[(tempBuffer[i]>>BIT4)&BIT4_MASK]);
        ss.push_back(xx[tempBuffer[i]&BIT4_MASK]);
        if (i % PRINT_WIDTH == PRINT_WIDTH_MOD) {
            ss.push_back('\0');
            IMAGE_LOGI("buffer[%{public}d] = [%{public}s]", i, ss.data());
            ss.clear();
            ss.resize(0);
        }
    }
    ss.push_back('\0');
    IMAGE_LOGI("buffer[LAST] = [%{public}s]", ss.data());
    ss.clear();
    ss.resize(0);
}

int32_t ImageCreator::SaveSTP(uint32_t *buffer,
    uint8_t *tempBuffer, uint32_t bufferSize, InitializationOptions initializationOpts)
{
    int64_t errorCode = -1;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(buffer, bufferSize, initializationOpts);
    if (pixelMap.get() != nullptr) {
        ImageInfo imageInfo;
        pixelMap->GetImageInfo(imageInfo);
        IMAGE_LOGD("create pixel map imageInfo.size.width=%{public}u.",
            imageInfo.size.width);
    } else {
        IMAGE_LOGE("pixelMap.get() == nullptr");
        return ERR_MEDIA_INVALID_VALUE;
    }
    ImagePacker imagePacker;
    errorCode = CreatorPackImage(tempBuffer, bufferSize, std::move(pixelMap));
    if (errorCode > 0) {
        int64_t len = errorCode < bufferSize ? errorCode : bufferSize;
        dumpBuffer(tempBuffer, len);
        errorCode = SUCCESS;
    } else {
        errorCode = ERR_MEDIA_INVALID_VALUE;
    }
    return errorCode;
}

static void ReleaseBuffer(AllocatorType allocatorType, uint8_t **buffer)
{
    if (allocatorType == AllocatorType::HEAP_ALLOC) {
        if (*buffer != nullptr) {
            free(*buffer);
            *buffer = nullptr;
        }
        return;
    }
}

static bool AllocHeapBuffer(uint64_t bufferSize, uint8_t **buffer)
{
    if (bufferSize == 0 || bufferSize > MALLOC_MAX_LENTH) {
        IMAGE_LOGE("[PostProc]Invalid value of bufferSize");
        return false;
    }
    *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    if (*buffer == nullptr) {
        IMAGE_LOGE("[PostProc]alloc covert color buffersize[%{public}llu] failed.",
            static_cast<unsigned long long>(bufferSize));
        return false;
    }
    errno_t errRet = memset_s(*buffer, bufferSize, 0, bufferSize);
    if (errRet != EOK) {
        IMAGE_LOGE("[PostProc]memset convertData fail, errorCode = %{public}d", errRet);
        ReleaseBuffer(AllocatorType::HEAP_ALLOC, buffer);
        return false;
    }
    return true;
}

int32_t ImageCreator::SaveSenderBufferAsImage(OHOS::sptr<OHOS::SurfaceBuffer> buffer,
    InitializationOptions initializationOpts)
{
    int32_t errorcode = 0;
    if (buffer != nullptr) {
        uint32_t *addr = static_cast<uint32_t *>(buffer->GetVirAddr());
        uint8_t *addr2 = nullptr;
        int32_t size = buffer->GetSize();
        if (!AllocHeapBuffer(size, &addr2)) {
            IMAGE_LOGE("AllocHeapBuffer failed");
            return ERR_MEDIA_INVALID_VALUE;
        }
        errorcode = SaveSTP(addr, addr2, static_cast<uint32_t>(size), initializationOpts);
        (iraContext_->GetCreatorBufferConsumer())->ReleaseBuffer(buffer, -1);
        IMAGE_LOGI("start release");
    } else {
        IMAGE_LOGD("SaveBufferAsImage buffer == nullptr");
    }
    return errorcode;
}

OHOS::sptr<OHOS::SurfaceBuffer> ImageCreator::DequeueImage()
{
    int32_t flushFence = 0;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer;
    sptr<Surface> creatorSurface = iraContext_->GetCreatorBufferProducer();
    BufferRequestConfig config;
    config.width = iraContext_->GetWidth();
    config.height = iraContext_->GetHeight();
    config.format = PIXEL_FMT_RGBA_8888;
    config.strideAlignment = 0x8;
    config.usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;
    config.timeout = 0;
    SurfaceError surfaceError = creatorSurface->RequestBuffer(buffer, flushFence, config);
    if (surfaceError == SURFACE_ERROR_OK) {
        iraContext_->currentCreatorBuffer_ = buffer;
    } else {
        IMAGE_LOGD("error : request buffer is null");
    }
    if (buffer != nullptr && buffer->GetVirAddr() != nullptr) {
        bufferCreatorMap_.insert(
            std::map<uint8_t*, ImageCreator*>::value_type(static_cast<uint8_t*>(buffer->GetVirAddr()), this));
    }
    return iraContext_->currentCreatorBuffer_;
}

void ImageCreator::QueueImage(OHOS::sptr<OHOS::SurfaceBuffer> &buffer)
{
    IMAGE_LOGI("start Queue Image");
    int32_t flushFence = -1;
    BufferFlushConfig config;
    config.damage.w = iraContext_->GetWidth();
    config.damage.h = iraContext_->GetHeight();
    sptr<Surface> creatorSurface = iraContext_->GetCreatorBufferProducer();
    SurfaceError surfaceError = creatorSurface->FlushBuffer(buffer, flushFence, config);
    IMAGE_LOGI("finish Queue Image");
    if (surfaceError != SURFACE_ERROR_OK) {
        IMAGE_LOGD("Queue fail");
    }
}
sptr<IConsumerSurface> ImageCreator::GetCreatorSurface()
{
    return iraContext_->GetCreatorBufferConsumer();
}

sptr<IConsumerSurface> ImageCreator::getSurfaceById(std::string id)
{
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    sptr<IConsumerSurface> surface = imageCreatorManager.GetSurfaceByKeyId(id);
    IMAGE_LOGD("getSurfaceByCreatorId");
    return surface;
}
void ImageCreator::ReleaseCreator()
{
    ImageCreator::~ImageCreator();
}

std::shared_ptr<IBufferProcessor> ImageCreator::GetBufferProcessor()
{
    if (bufferProcessor_ == nullptr) {
        bufferProcessor_ = std::make_shared<ImageCreatorBufferProcessor>(this);
    }
    return bufferProcessor_;
}
std::shared_ptr<NativeImage> ImageCreator::DequeueNativeImage()
{
    if (GetBufferProcessor() == nullptr) {
        return nullptr;
    }

    auto surfaceBuffer = DequeueImage();
    if (surfaceBuffer == nullptr) {
        return nullptr;
    }
    return std::make_shared<NativeImage>(surfaceBuffer, GetBufferProcessor());
}
void ImageCreator::QueueNativeImage(std::shared_ptr<NativeImage> image)
{
    if (image == nullptr || image->GetBuffer() == nullptr) {
        return;
    }
    auto buffer = image->GetBuffer();
    QueueImage(buffer);
}
} // namespace Media
} // namespace OHOS
