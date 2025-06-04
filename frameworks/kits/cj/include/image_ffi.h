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
#include "cj_image_utils.h"
#include "cj_lambda.h"
#include "image_type.h"
#include "napi/native_api.h"
#include "picture_impl.h"
#include "pixel_map.h"

extern "C" {
struct CImageInfo {
    int32_t height;
    int32_t width;
    int32_t density;
};

struct CImageInfoV2 {
    int32_t height;
    int32_t width;
    int32_t density;
    int32_t stride;
    int32_t pixelFormat;
    int32_t alphaType;
    char* mimeType;
    bool isHdr;
};

struct CSourceOptions {
    int32_t baseDensity;
    int32_t pixelFormat;
    int32_t height;
    int32_t width;
};

struct CInitializationOptions {
    int32_t alphaType;
    bool editable = false;
    int32_t pixelFormat;
    int32_t scaleMode;
    int32_t width;
    int32_t height;
};

struct CInitializationOptionsV2 {
    int32_t alphaType;
    bool editable = false;
    int32_t srcPixelFormat;
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

struct CDecodingOptionsV2 {
    int32_t fitDensity;
    CSize desiredSize;
    CRegion desiredRegion;
    float rotateDegrees;
    uint32_t sampleSize;
    int32_t desiredPixelFormat;
    bool editable;
    int64_t desiredColorSpace;
    int32_t desiredDynamicRange;
};

struct CPackingOption {
    const char* format;
    uint8_t quality;
    uint64_t bufferSize;
};

struct CPackingOptionV2 {
    const char* format;
    uint8_t quality;
    uint64_t bufferSize;
    int32_t desiredDynamicRange;
    bool needsPackProperties;
};

struct CjProperties {
    char** key;
    char** value;
    int64_t size;
};

FFI_EXPORT napi_value FfiConvertPixelMap2Napi(napi_env env, uint64_t id);
FFI_EXPORT int64_t FfiCreatePixelMapFromNapi(napi_env env, napi_value pixelmap);

// ImageSource
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPath(char* uri, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPathWithOption(char* uri, CSourceOptions opts, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFd(int fd, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFdWithOption(int fd, CSourceOptions opts, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBuffer(uint8_t* data, uint32_t size, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByRawFile(
    int fd, int32_t offset, int32_t length, CSourceOptions opts, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBufferWithOption(
    uint8_t* data, uint32_t size, CSourceOptions opts, uint32_t* errCode);
FFI_EXPORT int64_t FfiOHOSCreateIncrementalSource(
    const uint8_t* data, uint32_t size, CSourceOptions opts, uint32_t* errCode);
FFI_EXPORT CImageInfo FfiOHOSImageSourceGetImageInfo(int64_t id, uint32_t index, uint32_t* errCode);
FFI_EXPORT CImageInfoV2 FfiOHOSImageSourceGetImageInfoV2(int64_t id, uint32_t index, uint32_t* errCode);
FFI_EXPORT CArrString FfiOHOSGetSupportedFormats(int64_t id, uint32_t* errCode);
FFI_EXPORT char* FfiOHOSGetImageProperty(int64_t id, char* key, uint32_t index, char* defaultValue, uint32_t* errCode);
FFI_EXPORT uint32_t FfiOHOSModifyImageProperty(int64_t id, char* key, char* value);
FFI_EXPORT RetDataUI32 FfiOHOSGetFrameCount(int64_t id);
FFI_EXPORT uint32_t FfiOHOSUpdateData(int64_t id, UpdateDataInfo info);
FFI_EXPORT uint32_t FfiOHOSRelease(int64_t id);
FFI_EXPORT RetDataI64U32 FfiOHOSImageSourceCreatePixelMap(int64_t id, uint32_t index, CDecodingOptions opts);
FFI_EXPORT RetDataI64U32 FfiOHOSImageSourceCreatePixelMapV2(int64_t id, uint32_t index, CDecodingOptionsV2 opts);
FFI_EXPORT CArrI64 FfiOHOSImageSourceCreatePixelMapList(
    int64_t id, uint32_t index, CDecodingOptions opts, uint32_t* errorCode);
FFI_EXPORT CArrI64 FfiOHOSImageSourceCreatePixelMapListV2(
    int64_t id, uint32_t index, CDecodingOptionsV2 opts, uint32_t* errorCode);
FFI_EXPORT CArrI32 FfiOHOSImageSourceGetDelayTime(int64_t id, uint32_t* errorCode);
FFI_EXPORT CArrI32 FfiImageImageSourceImplGetDisposalTypeList(int64_t id, uint32_t* errorCode);
FFI_EXPORT uint32_t FfiImageImageSourceImplModifyImageProperties(int64_t id, CArrString key, CArrString value);
FFI_EXPORT uint32_t FfiImageImageSourceImplGetImageProperties(int64_t id, CArrString key, char** value);

// PixelMap
FFI_EXPORT int64_t FfiOHOSCreatePixelMap(uint8_t* colors, uint32_t colorLength, CInitializationOptions opts);
FFI_EXPORT int64_t FfiOHOSCreatePixelMapV2(uint8_t* colors, uint32_t colorLength, CInitializationOptionsV2 opts);
FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMap(CInitializationOptionsV2 opts);
FFI_EXPORT bool FfiOHOSGetIsEditable(int64_t id, uint32_t* errCode);
FFI_EXPORT bool FfiOHOSGetIsStrideAlignment(int64_t id, uint32_t* errCode);
FFI_EXPORT uint32_t FfiOHOSReadPixelsToBuffer(int64_t id, uint64_t bufferSize, uint8_t* dst);
FFI_EXPORT uint32_t FfiOHOSWriteBufferToPixels(int64_t id, uint8_t* source, uint64_t bufferSize);
FFI_EXPORT int32_t FfiOHOSGetDensity(int64_t id, uint32_t* errCode);
FFI_EXPORT uint32_t FfiOHOSOpacity(int64_t id, float percent);
FFI_EXPORT uint32_t FfiOHOSCrop(int64_t id, CRegion rect);
FFI_EXPORT uint32_t FfiOHOSGetPixelBytesNumber(int64_t id, uint32_t* errCode);
FFI_EXPORT uint32_t FfiOHOSGetBytesNumberPerRow(int64_t id, uint32_t* errCode);
FFI_EXPORT CImageInfo FfiOHOSGetImageInfo(int64_t id, uint32_t* errCode);
FFI_EXPORT CImageInfoV2 FfiOHOSGetImageInfoV2(int64_t id, uint32_t* errCode);
FFI_EXPORT uint32_t FfiOHOSScale(int64_t id, float xAxis, float yAxis);
FFI_EXPORT uint32_t FfiImagePixelMapImplScale(int64_t id, float xAxis, float yAxis, int32_t antiAliasing);
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
FFI_EXPORT uint32_t FfiImagePixelMapImplCreatePremultipliedPixelMap(int64_t srcId, int64_t dstId);
FFI_EXPORT uint32_t FfiImagePixelMapImplCreateUnpremultipliedPixelMap(int64_t srcId, int64_t dstId);
FFI_EXPORT uint32_t FfiImagePixelMapImplSetTransferDetached(int64_t id, bool detached);
FFI_EXPORT uint32_t FfiImagePixelMapImplToSdr(int64_t id);
FFI_EXPORT uint32_t FfiImagePixelMapImplMarshalling(int64_t id, int64_t rpcId);
FFI_EXPORT int64_t FfiImagePixelMapImplUnmarshalling(int64_t id, int64_t rpcId, uint32_t* errCode);
FFI_EXPORT uint32_t FfiImagePixelMapImplConvertPixelMapFormat(int64_t id, int32_t targetFormat);
FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromSurface(
    char* surfaceId, CRegion rect, size_t argc, uint32_t* errCode);
FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromParcel(int64_t rpcId, uint32_t* errCode);

// Image
FFI_EXPORT uint32_t FfiOHOSImageGetClipRect(int64_t id, CRegion* retVal);
FFI_EXPORT uint32_t FfiOHOSImageGetSize(int64_t id, CSize* retVal);
FFI_EXPORT uint32_t FfiOHOSImageGetFormat(int64_t id, int32_t* retVal);
FFI_EXPORT uint32_t FfiOHOSGetComponent(int64_t id, int32_t componentType, CRetComponent* ptr);
FFI_EXPORT int64_t FfiImageImageImplGetTimestamp(int64_t id);
FFI_EXPORT void FfiOHOSImageRelease(int64_t id);

// ImageReceiver
FFI_EXPORT uint32_t FfiOHOSReceiverGetSize(int64_t id, CSize* retVal);
FFI_EXPORT uint32_t FfiOHOSReceiverGetCapacity(int64_t id, int32_t* retVal);
FFI_EXPORT uint32_t FfiOHOSReceiverGetFormat(int64_t id, int32_t* retVal);
FFI_EXPORT int64_t FfiOHOSCreateImageReceiver(int32_t width, int32_t height, int32_t format, int32_t capacity);
FFI_EXPORT char* FfiOHOSGetReceivingSurfaceId(int64_t id);
FFI_EXPORT int64_t FfiOHOSReadNextImage(int64_t id);
FFI_EXPORT int64_t FfiOHOSReadLatestImage(int64_t id);
FFI_EXPORT void FfiOHOSReceiverRelease(int64_t id);
FFI_EXPORT uint32_t FfiImageReceiverImplOn(int64_t id, char* name, int64_t callbackId);

// ImagePacker
FFI_EXPORT int64_t FFiOHOSImagePackerConstructor();
FFI_EXPORT uint64_t FfiOHOSGetPackOptionSize();
FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMap(int64_t id, int64_t source, CPackingOption option);
FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMapV2(int64_t id, int64_t source, CPackingOptionV2 option);
FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingImageSource(int64_t id, int64_t source, CPackingOption option);
FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingImageSourceV2(int64_t id, int64_t source, CPackingOptionV2 option);
FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackToDataPixelMap(
    int64_t id, int64_t source, CPackingOptionV2 option);
FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackToDataImageSource(
    int64_t id, int64_t source, CPackingOptionV2 option);
FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackingPicture(int64_t id, int64_t source, CPackingOptionV2 option);
FFI_EXPORT RetDataCArrString FfiOHOSImagePackerGetSupportedFormats(int64_t id);
FFI_EXPORT uint32_t FfiOHOSImagePackerPackPixelMapToFile(int64_t id, int64_t source, int fd, CPackingOption option);
FFI_EXPORT uint32_t FfiOHOSImagePackerPackPixelMapToFileV2(int64_t id, int64_t source, int fd, CPackingOptionV2 option);
FFI_EXPORT uint32_t FfiOHOSImagePackerImageSourcePackToFile(int64_t id, int64_t source, int fd, CPackingOption option);
FFI_EXPORT uint32_t FfiOHOSImagePackerImageSourcePackToFileV2(
    int64_t id, int64_t source, int fd, CPackingOptionV2 option);
FFI_EXPORT uint32_t FfiImageImagePackerImplPackToFilePicture(
    int64_t id, int64_t source, int fd, CPackingOptionV2 option);
FFI_EXPORT void FFiOHOSImagePackerRelease(int64_t id);

// ImageCreator
FFI_EXPORT int64_t FFiOHOSImageCreatorConstructor(int32_t width, int32_t height, int32_t format, int32_t capacity);
FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetCapacity(int64_t id);
FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetformat(int64_t id);
FFI_EXPORT int64_t FFiOHOSImageCreatorDequeueImage(int64_t id, uint32_t* errCode);
FFI_EXPORT void FFiOHOSImageCreatorQueueImage(int64_t id, int64_t imageId);
FFI_EXPORT void FFiOHOSImageCreatorRelease(int64_t id);
FFI_EXPORT uint32_t FfiImageImageCreatorImplOn(int64_t id, char* name, int64_t callbackId);

// Pictute
FFI_EXPORT int64_t FfiImagePictureImplCreatePicture(int64_t id, uint32_t* errCode);
FFI_EXPORT uint32_t FfiImagePictureImplSetMetadata(int64_t id, int32_t metadataType, int64_t metadataId);
FFI_EXPORT int64_t FfiImagePictureImplGetMetadata(int64_t id, int32_t metadataType, uint32_t* errCode);

// Metadata
FFI_EXPORT CjProperties FfiImageMetadataImplGetAllProperties(int64_t id, uint32_t* errCode);
FFI_EXPORT void FfiImageMetadataImplReleaseProperties(CjProperties* properties);
}

#endif