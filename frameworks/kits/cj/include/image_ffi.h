/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef IMAGE_FFI_H
#define IMAGE_FFI_H
 
#include "cj_ffi/cj_common_ffi.h"
#include "pixel_map.h"
#include "image_type.h"
#include "image_utils.h"

extern "C" {
    struct CImageInfo {
        int32_t height;
        int32_t width;
        int32_t density;
    };

    struct CSourceOptions {
        int32_t baseDensity;
        int32_t pixelFormat;
        int32_t height;
        int32_t width;
    };

    struct  CInitializationOptions {
        int32_t alphaType;
        bool editable = false;
        int32_t pixelFormat;
        int32_t scaleMode;
        int32_t width;
        int32_t height;
    };

    struct CDecodingOptions {
        int32_t fitDensity;
        CSize desiredSize;
        CRegion desiredRegion;
        float rotateDegrees;
        uint32_t sampleSize;
        int32_t desiredPixelFormat;
        bool editable;
        int64_t desiredColorSpace;
    };

    struct CPackingOption {
        const char* format;
        uint8_t quality = 100;
        uint64_t bufferSize = 10 * 1024 * 1024;
    };

    // ImageSource
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPath(char* uri, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPathWithOption(char* uri, CSourceOptions opts, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFd(int fd, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFdWithOption(int fd, CSourceOptions opts, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBuffer(uint8_t *data, uint32_t size, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByRawFile(int fd, int32_t offset,
        int32_t length, CSourceOptions opts, uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBufferWithOption(uint8_t *data, uint32_t size, CSourceOptions opts,
        uint32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSCreateIncrementalSource(const uint8_t *data, uint32_t size,
        CSourceOptions opts, uint32_t* errCode);
    FFI_EXPORT CImageInfo FfiOHOSImageSourceGetImageInfo(int64_t id, uint32_t index, uint32_t* errCode);
    FFI_EXPORT CArrString FfiOHOSGetSupportedFormats(int64_t id, uint32_t* errCode);
    FFI_EXPORT char* FfiOHOSGetImageProperty(int64_t id, char* key, uint32_t index, char* defaultValue,
        uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSModifyImageProperty(int64_t id, char* key, char* value);
    FFI_EXPORT RetDataUI32 FfiOHOSGetFrameCount(int64_t id);
    FFI_EXPORT uint32_t FfiOHOSUpdateData(int64_t id, UpdateDataInfo info);
    FFI_EXPORT uint32_t FfiOHOSRelease(int64_t id);
    FFI_EXPORT RetDataI64U32 FfiOHOSImageSourceCreatePixelMap(int64_t id, uint32_t index, CDecodingOptions &opts);
    FFI_EXPORT CArrI64 FfiOHOSImageSourceCreatePixelMapList(int64_t id, uint32_t index, CDecodingOptions opts,
        uint32_t* errorCode);
    FFI_EXPORT CArrI32 FfiOHOSImageSourceGetDelayTime(int64_t id, uint32_t* errorCode);

    // PixelMap
    FFI_EXPORT int64_t FfiOHOSCreatePixelMap(uint8_t *colors, uint32_t colorLength, CInitializationOptions opts);
    FFI_EXPORT bool FfiOHOSGetIsEditable(int64_t id, uint32_t* errCode);
    FFI_EXPORT bool FfiOHOSGetIsStrideAlignment(int64_t id, uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSReadPixelsToBuffer(int64_t id, uint64_t bufferSize, uint8_t *dst);
    FFI_EXPORT uint32_t FfiOHOSWriteBufferToPixels(int64_t id, uint8_t *source, uint64_t bufferSize);
    FFI_EXPORT int32_t FfiOHOSGetDensity(int64_t id, uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSOpacity(int64_t id, float percent);
    FFI_EXPORT uint32_t FfiOHOSCrop(int64_t id, CRegion rect);
    FFI_EXPORT uint32_t FfiOHOSGetPixelBytesNumber(int64_t id, uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSGetBytesNumberPerRow(int64_t id, uint32_t* errCode);
    FFI_EXPORT CImageInfo FfiOHOSGetImageInfo(int64_t id, uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSScale(int64_t id, float xAxis, float yAxis);
    FFI_EXPORT uint32_t FfiOHOSFlip(int64_t id, bool xAxis, bool yAxis);
    FFI_EXPORT uint32_t FfiOHOSRotate(int64_t id, float degrees);
    FFI_EXPORT uint32_t FfiOHOSTranslate(int64_t id, float xAxis, float yAxis);
    FFI_EXPORT uint32_t FfiOHOSReadPixels(int64_t id, CPositionArea area);
    FFI_EXPORT uint32_t FfiOHOSWritePixels(int64_t id, CPositionArea area);
    FFI_EXPORT int64_t FfiOHOSCreateAlphaPixelMap(int64_t id, uint32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSPixelMapRelease(int64_t id);
    FFI_EXPORT uint32_t FfiOHOSPixelMapSetColorSpace(int64_t id, int64_t colorSpaceId);
    FFI_EXPORT int64_t FfiOHOSPixelMapGetColorSpace(int64_t id, int32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSPixelMapApplyColorSpace(int64_t id, int64_t colorSpaceId);

    // Image
    FFI_EXPORT uint32_t FfiOHOSImageGetClipRect(int64_t id, CRegion *retVal);
    FFI_EXPORT uint32_t FfiOHOSImageGetSize(int64_t id, CSize *retVal);
    FFI_EXPORT uint32_t FfiOHOSImageGetFormat(int64_t id, int32_t *retVal);
    FFI_EXPORT uint32_t FfiOHOSGetComponent(int64_t id, int32_t componentType, CRetComponent *ptr);
    FFI_EXPORT void FfiOHOSImageRelease(int64_t id);

    // ImageReceiver
    FFI_EXPORT uint32_t FfiOHOSReceiverGetSize(int64_t id, CSize *retVal);
    FFI_EXPORT uint32_t FfiOHOSReceiverGetCapacity(int64_t id, int32_t *retVal);
    FFI_EXPORT uint32_t FfiOHOSReceiverGetFormat(int64_t id, int32_t *retVal);
    FFI_EXPORT int64_t FfiOHOSCreateImageReceiver(int32_t width, int32_t height, int32_t format, int32_t capacity);
    FFI_EXPORT char* FfiOHOSGetReceivingSurfaceId(int64_t id);
    FFI_EXPORT int64_t FfiOHOSReadNextImage(int64_t id);
    FFI_EXPORT int64_t FfiOHOSReadLatestImage(int64_t id);
    FFI_EXPORT void FfiOHOSReceiverRelease(int64_t id);

    // ImagePacker
    FFI_EXPORT int64_t FFiOHOSImagePackerConstructor();
    FFI_EXPORT uint64_t FfiOHOSGetPackOptionSize();
    FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMap(int64_t id, int64_t source, CPackingOption option);
    FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingImageSource(int64_t id, int64_t source,
        CPackingOption option);
    FFI_EXPORT RetDataCArrString FfiOHOSImagePackerGetSupportedFormats(int64_t id);
    FFI_EXPORT uint32_t FfiOHOSImagePackerPackPixelMapToFile(int64_t id, int64_t source, int fd,
        CPackingOption option);
    FFI_EXPORT uint32_t FfiOHOSImagePackerImageSourcePackToFile(int64_t id, int64_t source, int fd,
        CPackingOption option);
    FFI_EXPORT void FFiOHOSImagePackerRelease(int64_t id);

    // ImageCreator
    FFI_EXPORT int64_t FFiOHOSImageCreatorConstructor(int32_t width, int32_t height, int32_t format, int32_t capacity);
    FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetCapacity(int64_t id);
    FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetformat(int64_t id);
    FFI_EXPORT int64_t FFiOHOSImageCreatorDequeueImage(int64_t id, uint32_t* errCode);
    FFI_EXPORT void FFiOHOSImageCreatorQueueImage(int64_t id, int64_t imageId);
    FFI_EXPORT void FFiOHOSImageCreatorOn(int64_t id);
    FFI_EXPORT void FFiOHOSImageCreatorRelease(int64_t id);
}
 
#endif