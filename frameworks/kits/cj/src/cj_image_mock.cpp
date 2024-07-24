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
#define FFI_EXPORT __attribute__((visibility("default")))

extern "C" {
FFI_EXPORT int FfiOHOSCreateImageSourceByPath = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByPathWithOption = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByFd = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByFdWithOption = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByBuffer = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByBufferWithOption = 0;
FFI_EXPORT int FfiOHOSCreateImageSourceByRawFile = 0;
FFI_EXPORT int FfiOHOSCreateIncrementalSource = 0;
FFI_EXPORT int FfiOHOSImageSourceGetImageInfo = 0;
FFI_EXPORT int FfiOHOSGetSupportedFormats = 0;
FFI_EXPORT int FfiOHOSGetImageProperty = 0;
FFI_EXPORT int FfiOHOSModifyImageProperty = 0;
FFI_EXPORT int FfiOHOSGetFrameCount = 0;
FFI_EXPORT int FfiOHOSUpdateData = 0;
FFI_EXPORT int FfiOHOSRelease = 0;
FFI_EXPORT int FfiOHOSImageSourceCreatePixelMap = 0;
FFI_EXPORT int FfiOHOSImageSourceCreatePixelMapList = 0;
FFI_EXPORT int FfiOHOSImageSourceGetDelayTime = 0;

FFI_EXPORT int FfiOHOSCreatePixelMap = 0;
FFI_EXPORT int FfiOHOSGetIsEditable = 0;
FFI_EXPORT int FfiOHOSGetIsStrideAlignment = 0;
FFI_EXPORT int FfiOHOSReadPixelsToBuffer = 0;
FFI_EXPORT int FfiOHOSWriteBufferToPixels = 0;
FFI_EXPORT int FfiOHOSGetDensity = 0;
FFI_EXPORT int FfiOHOSOpacity = 0;
FFI_EXPORT int FfiOHOSCrop = 0;
FFI_EXPORT int FfiOHOSGetPixelBytesNumber = 0;
FFI_EXPORT int FfiOHOSGetBytesNumberPerRow = 0;
FFI_EXPORT int FfiOHOSGetImageInfo = 0;
FFI_EXPORT int FfiOHOSScale = 0;
FFI_EXPORT int FfiOHOSFlip = 0;
FFI_EXPORT int FfiOHOSRotate = 0;
FFI_EXPORT int FfiOHOSTranslate = 0;
FFI_EXPORT int FfiOHOSReadPixels = 0;
FFI_EXPORT int FfiOHOSWritePixels = 0;
FFI_EXPORT int FfiOHOSCreateAlphaPixelMap = 0;
FFI_EXPORT int FfiOHOSPixelMapRelease = 0;
FFI_EXPORT int FfiOHOSImageGetClipRect = 0;
FFI_EXPORT int FfiOHOSImageGetSize = 0;
FFI_EXPORT int FfiOHOSImageGetFormat = 0;
FFI_EXPORT int FfiOHOSGetComponent = 0;
FFI_EXPORT int FfiOHOSImageRelease = 0;
FFI_EXPORT int FfiOHOSPixelMapSetColorSpace = 0;
FFI_EXPORT int FfiOHOSPixelMapGetColorSpace = 0;
FFI_EXPORT int FfiOHOSPixelMapApplyColorSpace = 0;

FFI_EXPORT int FfiOHOSReceiverGetSize = 0;
FFI_EXPORT int FfiOHOSReceiverGetCapacity = 0;
FFI_EXPORT int FfiOHOSReceiverGetFormat = 0;
FFI_EXPORT int FfiOHOSCreateImageReceiver = 0;
FFI_EXPORT int FfiOHOSGetReceivingSurfaceId = 0;
FFI_EXPORT int FfiOHOSReadNextImage = 0;
FFI_EXPORT int FfiOHOSReadLatestImage = 0;
FFI_EXPORT int FfiOHOSReceiverRelease = 0;
FFI_EXPORT int FFiOHOSImagePackerConstructor = 0;
FFI_EXPORT int FfiOHOSGetPackOptionSize = 0;
FFI_EXPORT int FfiOHOSImagePackerPackingPixelMap = 0;
FFI_EXPORT int FfiOHOSImagePackerPackingImageSource = 0;
FFI_EXPORT int FfiOHOSImagePackerGetSupportedFormats = 0;
FFI_EXPORT int FfiOHOSImagePackerPackPixelMapToFile = 0;
FFI_EXPORT int FfiOHOSImagePackerImageSourcePackToFile = 0;
FFI_EXPORT int FFiOHOSImagePackerRelease = 0;
FFI_EXPORT int FFiOHOSImageCreatorConstructor = 0;
FFI_EXPORT int FFiOHOSImageCreatorGetCapacity = 0;
FFI_EXPORT int FFiOHOSImageCreatorGetformat = 0;
FFI_EXPORT int FFiOHOSImageCreatorDequeueImage = 0;
FFI_EXPORT int FFiOHOSImageCreatorQueueImage = 0;
FFI_EXPORT int FFiOHOSImageCreatorOn = 0;
FFI_EXPORT int FFiOHOSImageCreatorRelease = 0;
}