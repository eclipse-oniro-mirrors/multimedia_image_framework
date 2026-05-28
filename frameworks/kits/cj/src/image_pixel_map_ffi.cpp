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
#include "cj_color_manager.h"
#include "cj_ffi/cj_common_ffi.h"
#include "image_ffi.h"
#include "image_log.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "media_errors.h"
#include "pixel_map_impl.h"
#include "pixel_map_napi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
extern "C" {
static Rect ParseCRegion(CRegion region)
{
    Rect rt = {
        .left = region.x,
        .top = region.y,
        .width = region.size.width,
        .height = region.size.height,
    };
    return rt;
}

static InitializationOptions ParseCInitializationOptionsV2(CInitializationOptionsV2 opts)
{
    InitializationOptions option;
    option.alphaType = AlphaType(opts.alphaType);
    option.editable = opts.editable;
    option.srcPixelFormat = PixelFormat(opts.srcPixelFormat);
    option.pixelFormat = PixelFormat(opts.pixelFormat);
    option.scaleMode = ScaleMode(opts.scaleMode);
    option.size.height = opts.height;
    option.size.width = opts.width;
    return option;
}

static CInitializationOptionsV2 ConvertCInitializationOptionsToV2(CInitializationOptions opts)
{
    return {
        .alphaType = opts.alphaType,
        .editable = opts.editable,
        .srcPixelFormat = opts.pixelFormat,
        .pixelFormat = opts.pixelFormat,
        .scaleMode = opts.scaleMode,
        .width = opts.width,
        .height = opts.height,
    };
}

FFI_EXPORT int64_t FfiOHOSCreatePixelMapV2(uint8_t* colors, uint32_t colorLength, CInitializationOptionsV2 opts)
{
    InitializationOptions option = ParseCInitializationOptionsV2(opts);
    std::unique_ptr<PixelMap> ptr_ =
        PixelMapImpl::CreatePixelMap(reinterpret_cast<uint32_t*>(colors), colorLength, option);
    if (!ptr_) {
        return INIT_FAILED;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(ptr_));
    if (!native) {
        return INIT_FAILED;
    }
    return native->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreatePixelMap(uint8_t* colors, uint32_t colorLength, CInitializationOptions opts)
{
    return FfiOHOSCreatePixelMapV2(colors, colorLength, ConvertCInitializationOptionsToV2(opts));
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMap(CInitializationOptionsV2 opts)
{
    InitializationOptions option = ParseCInitializationOptionsV2(opts);
    std::unique_ptr<PixelMap> ptr_ = PixelMapImpl::CreatePixelMap(option);
    if (!ptr_) {
        return INIT_FAILED;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(ptr_));
    if (!native) {
        return INIT_FAILED;
    }
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSPixelMapRelease(int64_t id)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
    ptr_.reset();
    return SUCCESS_CODE;
}

FFI_EXPORT int64_t FfiOHOSCreateAlphaPixelMap(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return 0;
    }
    std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
    if (!ptr_) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("ptr null");
        return 0;
    }
    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    auto tmpPixelMap = PixelMapImpl::CreateAlphaPixelMap(*ptr_, opts);
    if (!tmpPixelMap) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("tmp pm null");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(tmpPixelMap));
    if (!native) {
        IMAGE_LOGE("alpha pm fail");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    *errCode = SUCCESS_CODE;
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSReadPixelsToBuffer(int64_t id, uint64_t bufferSize, uint8_t* dst)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->ReadPixelsToBuffer(bufferSize, dst);
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSWriteBufferToPixels(int64_t id, uint8_t* source, uint64_t bufferSize)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->WriteBufferToPixels(source, bufferSize);
    return ret;
}

FFI_EXPORT int32_t FfiOHOSGetDensity(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    int32_t ret = instance->GetDensity();
    *errCode = SUCCESS_CODE;
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSOpacity(int64_t id, float percent)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->Opacity(percent);
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSCrop(int64_t id, CRegion rect)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(rect);
    uint32_t ret = instance->Crop(rt);
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSGetPixelBytesNumber(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    uint32_t ret = instance->GetPixelBytesNumber();
    *errCode = SUCCESS_CODE;
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSGetBytesNumberPerRow(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    uint32_t ret = instance->GetBytesNumberPerRow();
    *errCode = SUCCESS_CODE;
    return ret;
}

FFI_EXPORT CImageInfo FfiOHOSGetImageInfo(int64_t id, uint32_t* errCode)
{
    CImageInfo ret = {};
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    instance->GetImageInfo(info);
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    return ret;
}

static CImageInfoV2 ParsePixelMapImageInfo(ImageInfo info, PixelMap* pixelMap)
{
    CImageInfoV2 ret = {};
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    ret.pixelFormat = static_cast<int32_t>(info.pixelFormat);
    ret.alphaType = static_cast<int32_t>(info.alphaType);
    ret.stride = static_cast<int32_t>(pixelMap->GetRowStride());
    ret.mimeType = Utils::MallocCString(info.encodedFormat);
    ret.isHdr = pixelMap->IsHdr();
    return ret;
}

FFI_EXPORT CImageInfoV2 FfiOHOSGetImageInfoV2(int64_t id, uint32_t* errCode)
{
    CImageInfoV2 ret = {};
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    instance->GetImageInfo(info);
    ret = ParsePixelMapImageInfo(info, instance->GetRealPixelMap().get());
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSScale(int64_t id, float xAxis, float yAxis)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Scale(xAxis, yAxis);
    return SUCCESS_CODE;
}

static AntiAliasingOption ParseAntiAliasingOption(int32_t val)
{
    if (val <= static_cast<int32_t>(AntiAliasingOption::SPLINE)) {
        return AntiAliasingOption(val);
    }
    return AntiAliasingOption::NONE;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplScale(int64_t id, float xAxis, float yAxis, int32_t antiAliasing)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    AntiAliasingOption option = ParseAntiAliasingOption(antiAliasing);
    instance->Scale(xAxis, yAxis, option);
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSFlip(int64_t id, bool xAxis, bool yAxis)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Flip(xAxis, yAxis);
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSRotate(int64_t id, float degrees)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Rotate(degrees);
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSTranslate(int64_t id, float xAxis, float yAxis)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Translate(xAxis, yAxis);
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSReadPixels(int64_t id, CPositionArea area)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(area.region);
    uint32_t ret = instance->ReadPixels(area.bufferSize, area.offset, area.stride, rt, area.dst);
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSWritePixels(int64_t id, CPositionArea area)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(area.region);
    uint32_t ret = instance->WritePixels(area.dst, area.bufferSize, area.offset, area.stride, rt);
    return ret;
}

FFI_EXPORT bool FfiOHOSGetIsEditable(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    bool ret = false;
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ret = instance->GetIsEditable();
    *errCode = SUCCESS_CODE;
    return ret;
}

FFI_EXPORT bool FfiOHOSGetIsStrideAlignment(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    bool ret = false;
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ret = instance->GetIsStrideAlignment();
    *errCode = SUCCESS_CODE;
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSPixelMapSetColorSpace(int64_t id, int64_t colorSpaceId)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("pmImpl no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
    if (!colorSpace) {
        IMAGE_LOGE("color no inst %{public}" PRId64, colorSpaceId);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t ret = instance->SetColorSpace(colorSpace->GetColorSpaceToken());
    return ret;
}

FFI_EXPORT int64_t FfiOHOSPixelMapGetColorSpace(int64_t id, int32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        *errCode = ERR_IMAGE_DATA_ABNORMAL;
        return 0;
    }
    auto colorSpace = instance->GetColorSpace();
    if (!colorSpace) {
        *errCode = ERR_IMAGE_DATA_UNSUPPORT;
        return 0;
    }
    auto native = FFIData::Create<ColorManager::CjColorManager>(colorSpace);
    if (!native) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }

    *errCode = SUCCESS_CODE;
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSPixelMapApplyColorSpace(int64_t id, int64_t colorSpaceId)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
    if (!colorSpace) {
        IMAGE_LOGE("color no inst %{public}" PRId64, colorSpaceId);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->ApplyColorSpace(colorSpace->GetColorSpaceToken());
    return ret;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplCreatePremultipliedPixelMap(int64_t srcId, int64_t dstId)
{
    auto src = FFIData::GetData<PixelMapImpl>(srcId);
    auto dst = FFIData::GetData<PixelMapImpl>(dstId);
    if (!src || !dst) {
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    return PixelMapImpl::CreatePremultipliedPixelMap(src->GetRealPixelMap(), dst->GetRealPixelMap());
}

FFI_EXPORT uint32_t FfiImagePixelMapImplCreateUnpremultipliedPixelMap(int64_t srcId, int64_t dstId)
{
    auto src = FFIData::GetData<PixelMapImpl>(srcId);
    auto dst = FFIData::GetData<PixelMapImpl>(dstId);
    if (!src || !dst) {
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    return PixelMapImpl::CreateUnpremultipliedPixelMap(src->GetRealPixelMap(), dst->GetRealPixelMap());
}

FFI_EXPORT uint32_t FfiImagePixelMapImplSetTransferDetached(int64_t id, bool detached)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->SetTransferDetach(detached);
    return SUCCESS;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplToSdr(int64_t id)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    return instance->ToSdr();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplMarshalling(int64_t id, int64_t rpcId)
{
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("pm no %{public}" PRId64, id);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return pixelMap->Marshalling(rpcId);
}

FFI_EXPORT int64_t FfiImagePixelMapImplUnmarshalling(int64_t id, int64_t rpcId, uint32_t* errCode)
{
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("pm no %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INVALID_PARAMETER;
        return 0;
    }
    auto retPixelMap = pixelMap->Unmarshalling(rpcId, *errCode);
    if (!retPixelMap) {
        IMAGE_LOGE("ret pm null");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(retPixelMap));
    if (!native) {
        IMAGE_LOGE("native null");
        *errCode = ERR_IMAGE_NAPI_ERROR;
        return 0;
    }
    return native->GetID();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplConvertPixelMapFormat(int64_t id, int32_t targetFormat)
{
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("pm no %{public}" PRId64, id);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    PixelFormat format = PixelFormat(targetFormat);
    return pixelMap->ConvertPixelMapFormat(format);
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromSurface(
    char* surfaceId, CRegion rect, size_t argc, uint32_t* errCode)
{
    Rect rt = ParseCRegion(rect);
    auto pixelMap = PixelMapImpl::CreatePixelMapFromSurface(surfaceId, rt, argc, *errCode);
    if (!pixelMap) {
        IMAGE_LOGE("pm null");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (!native) {
        IMAGE_LOGE("native null");
        *errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        return 0;
    }
    return native->GetID();
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromParcel(int64_t rpcId, uint32_t* errCode)
{
    auto pixelMap = PixelMapImpl::CreatePixelMapFromParcel(rpcId, *errCode);
    if (!pixelMap) {
        IMAGE_LOGE("pm null");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (!native) {
        IMAGE_LOGE("native null");
        *errCode = ERR_IMAGE_NAPI_ERROR;
        return 0;
    }
    return native->GetID();
}

FFI_EXPORT napi_value FfiConvertPixelMap2Napi(napi_env env, uint64_t id)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (instance == nullptr || instance->GetRealPixelMap() == nullptr) {
        IMAGE_LOGE("no inst %{public}" PRId64, id);
        return undefined;
    }

    napi_value result = PixelMapNapi::CreatePixelMap(env, instance->GetRealPixelMap());
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, result, &type) != napi_ok || type == napi_undefined) {
        IMAGE_LOGE("napi create fail");
        return undefined;
    }
    PixelMapNapi* pixelMapNapi = nullptr;
    napi_status status = napi_unwrap(env, result, reinterpret_cast<void**>(&pixelMapNapi));
    if (status != napi_ok || pixelMapNapi == nullptr) {
        IMAGE_LOGE("unwrap fail");
        return undefined;
    }
    pixelMapNapi->setPixelNapiEditable(instance->GetPixelMapImplEditable());
    pixelMapNapi->SetTransferDetach(instance->GetTransferDetach());
    return result;
}

FFI_EXPORT int64_t FfiCreatePixelMapFromNapi(napi_env env, napi_value pixelmap)
{
    if (env == nullptr || pixelmap == nullptr) {
        IMAGE_LOGE("param null");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, pixelmap, &type) != napi_ok || type != napi_object) {
        IMAGE_LOGE("param type err");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    PixelMapNapi* obj = nullptr;
    napi_status status = napi_unwrap(env, pixelmap, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        IMAGE_LOGE("unwrap fail");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    std::shared_ptr<PixelMap>* nativeObj = obj->GetPixelMap();
    if (nativeObj == nullptr) {
        IMAGE_LOGE("pm released");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto native = FFIData::Create<PixelMapImpl>(*nativeObj, obj->GetPixelNapiEditable(), obj->GetTransferDetach());
    if (native == nullptr) {
        IMAGE_LOGE("FFI create fail");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    return native->GetID();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplApplyScale(int64_t id, float x, float y, int32_t antiAliasing)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (instance == nullptr) {
        IMAGE_LOGE("instance null");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    AntiAliasingOption option = AntiAliasingOption(antiAliasing);
    return instance->ApplyScale(x, y, option);
}

FFI_EXPORT int64_t FfiImagePixelMapImplClone(int64_t id, uint32_t* errCode)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (instance == nullptr) {
        IMAGE_LOGE("instance null");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    int32_t errorCode = 0;
    auto clonePixelMap = instance->Clone(errorCode);
    if (clonePixelMap == nullptr) {
        *errCode = static_cast<uint32_t>(errorCode);
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(clonePixelMap));
    if (native == nullptr) {
        IMAGE_LOGE("FFI create fail");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    return native->GetID();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplSetMemoryName(int64_t id, char* name)
{
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (instance == nullptr) {
        IMAGE_LOGE("instance null");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::string pixelMapName = (name != nullptr) ? name : "";
    return instance->SetMemoryName(pixelMapName);
}
}
} // namespace Media
} // namespace OHOS