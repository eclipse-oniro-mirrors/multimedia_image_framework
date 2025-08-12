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

#include <dlfcn.h>
#include <mutex>
#include "auxiliary_picture_taihe.h"
#include "image_creator_taihe.h"
#include "image_log.h"
#include "image_packer_taihe.h"
#include "image_receiver_taihe.h"
#include "image_source_taihe.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "picture_taihe.h"
#include "pixel_map_taihe.h"
#include "transfer_taihe.h"

using namespace ANI::Image;

namespace {
const std::string LIB_IMAGE_NAPI_SO = "libimage_napi.z.so";

// function pointer type for napi functions
using GetImageSourceNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::ImageSource>);
using GetImagePackerNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::ImagePacker>);
using GetPictureNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::Picture>);
using GetAuxiliaryPictureNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::AuxiliaryPicture>);
using GetImageReceiverNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::ImageReceiver>);
using GetImageCreatorNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::ImageCreator>);
using GetPixelMapNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::PixelMap>);

using GetNativeImageSourceFn = bool (*)(void*, std::shared_ptr<OHOS::Media::ImageSource>&);
using GetNativeImagePackerFn = bool (*)(void*, std::shared_ptr<OHOS::Media::ImagePacker>&);
using GetNativePictureFn = bool (*)(void*, std::shared_ptr<OHOS::Media::Picture>&);
using GetNativeAuxiliaryPictureFn = bool (*)(void*, std::shared_ptr<OHOS::Media::AuxiliaryPicture>&);
using GetNativeImageReceiverFn = bool (*)(void*, std::shared_ptr<OHOS::Media::ImageReceiver>&);
using GetNativeImageCreatorFn = bool (*)(void*, std::shared_ptr<OHOS::Media::ImageCreator>&);
using GetNativePixelMapFn = bool (*)(void*, std::shared_ptr<OHOS::Media::PixelMap>&);

// custom deleter for handle to auto dlclose
struct DlHandleDeleter {
    void operator()(void* handle) const
    {
        if (handle) {
            dlclose(handle);
        }
    }
};
using UniqueDlHandle = std::unique_ptr<void, DlHandleDeleter>;
}

namespace ANI::Image {

void* GetNapiFunction(const char* name)
{
    static std::once_flag flag;
    static UniqueDlHandle handle(nullptr);
    std::call_once(flag, [&]() {
        void* newHandle = dlopen(LIB_IMAGE_NAPI_SO.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (!newHandle) {
            IMAGE_LOGE("%{public}s dlopen failed, path: %{public}s, error: %{public}s", __func__,
                LIB_IMAGE_NAPI_SO.c_str(), dlerror());
            return;
        }
        handle.reset(newHandle);
    });

    if (!handle) {
        IMAGE_LOGE("%{public}s handle is nullptr, please make sure %{public}s is loaded", __func__,
            LIB_IMAGE_NAPI_SO.c_str());
        return nullptr;
    }

    void* symbol = dlsym(handle.get(), name);
    if (!symbol) {
        IMAGE_LOGE("%{public}s dlsym failed, name: %{public}s, error: %{public}s", __func__, name, dlerror());
        return nullptr;
    }
    IMAGE_LOGI("%{public}s dlsym success, name: %{public}s, symbol: %{public}p", __func__, name, symbol);
    return symbol;
}

ImageSource ImageSourceTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<ImageSourceImpl, ImageSource>();
    }

    void* napiFunc = GetNapiFunction("GetNativeImageSource");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<ImageSourceImpl, ImageSource>();
    }

    std::shared_ptr<OHOS::Media::ImageSource> nativeImageSource = nullptr;
    bool ret = (*reinterpret_cast<GetNativeImageSourceFn>(napiFunc))(nativePtr, nativeImageSource);
    if (!ret || nativeImageSource == nullptr) {
        IMAGE_LOGE("%{public}s GetNativeImageSource failed", __func__);
        return make_holder<ImageSourceImpl, ImageSource>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<ImageSourceImpl, ImageSource>(nativeImageSource);
}

uintptr_t ImageSourceTransferDynamicImpl(ImageSource input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    ImageSourceImpl* thisPtr = reinterpret_cast<ImageSourceImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetImageSourceNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetImageSourceNapiFn>(napiFunc))(jsEnv, thisPtr->nativeImgSrc);
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetImageSourceNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

ImagePacker ImagePackerTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<ImagePackerImpl, ImagePacker>();
    }

    void* napiFunc = GetNapiFunction("GetNativeImagePacker");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<ImagePackerImpl, ImagePacker>();
    }

    std::shared_ptr<OHOS::Media::ImagePacker> nativeImagePacker = nullptr;
    bool ret = (*reinterpret_cast<GetNativeImagePackerFn>(napiFunc))(nativePtr, nativeImagePacker);
    if (!ret || nativeImagePacker == nullptr) {
        IMAGE_LOGE("%{public}s GetNativeImagePacker failed", __func__);
        return make_holder<ImagePackerImpl, ImagePacker>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<ImagePackerImpl, ImagePacker>(nativeImagePacker);
}

uintptr_t ImagePackerTransferDynamicImpl(ImagePacker input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    ImagePackerImpl* thisPtr = reinterpret_cast<ImagePackerImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetImagePackerNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetImagePackerNapiFn>(napiFunc))(jsEnv, thisPtr->GetNativeImagePacker());
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetImagePackerNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

Picture PictureTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<PictureImpl, Picture>();
    }

    void* napiFunc = GetNapiFunction("GetNativePicture");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<PictureImpl, Picture>();
    }

    std::shared_ptr<OHOS::Media::Picture> nativePicture = nullptr;
    bool ret = (*reinterpret_cast<GetNativePictureFn>(napiFunc))(nativePtr, nativePicture);
    if (!ret || nativePicture == nullptr) {
        IMAGE_LOGE("%{public}s GetNativePicture failed", __func__);
        return make_holder<PictureImpl, Picture>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<PictureImpl, Picture>(nativePicture);
}

uintptr_t PictureTransferDynamicImpl(Picture input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    PictureImpl* thisPtr = reinterpret_cast<PictureImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetPictureNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    std::shared_ptr<OHOS::Media::Picture> nativePicture = thisPtr->GetNativePtr();
    napi_value result = (*reinterpret_cast<GetPictureNapiFn>(napiFunc))(jsEnv, nativePicture);
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetPictureNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

AuxiliaryPicture AuxiliaryPictureTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }

    void* napiFunc = GetNapiFunction("GetNativeAuxiliaryPicture");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }

    std::shared_ptr<OHOS::Media::AuxiliaryPicture> nativeAuxiliaryPicture = nullptr;
    bool ret = (*reinterpret_cast<GetNativeAuxiliaryPictureFn>(napiFunc))(nativePtr, nativeAuxiliaryPicture);
    if (!ret || nativeAuxiliaryPicture == nullptr) {
        IMAGE_LOGE("%{public}s GetNativeAuxiliaryPicture failed", __func__);
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>(nativeAuxiliaryPicture);
}

uintptr_t AuxiliaryPictureTransferDynamicImpl(AuxiliaryPicture input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    AuxiliaryPictureImpl* thisPtr = reinterpret_cast<AuxiliaryPictureImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetAuxiliaryPictureNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetAuxiliaryPictureNapiFn>(napiFunc))(jsEnv,
        thisPtr->GetNativeAuxiliaryPic());
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetAuxiliaryPictureNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

ImageReceiver ImageReceiverTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<ImageReceiverImpl, ImageReceiver>();
    }

    void* napiFunc = GetNapiFunction("GetNativeImageReceiver");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<ImageReceiverImpl, ImageReceiver>();
    }

    std::shared_ptr<OHOS::Media::ImageReceiver> nativeImageReceiver = nullptr;
    bool ret = (*reinterpret_cast<GetNativeImageReceiverFn>(napiFunc))(nativePtr, nativeImageReceiver);
    if (!ret || nativeImageReceiver == nullptr) {
        IMAGE_LOGE("%{public}s GetNativeImageReceiver failed", __func__);
        return make_holder<ImageReceiverImpl, ImageReceiver>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<ImageReceiverImpl, ImageReceiver>(nativeImageReceiver);
}

uintptr_t ImageReceiverTransferDynamicImpl(ImageReceiver input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    ImageReceiverImpl* thisPtr = reinterpret_cast<ImageReceiverImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetImageReceiverNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetImageReceiverNapiFn>(napiFunc))(jsEnv,
        thisPtr->GetNativeImageReceiver());
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetImageReceiverNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

ImageCreator ImageCreatorTransferStaticImpl(uintptr_t input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<ImageCreatorImpl, ImageCreator>();
    }

    void* napiFunc = GetNapiFunction("GetNativeImageCreator");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<ImageCreatorImpl, ImageCreator>();
    }

    std::shared_ptr<OHOS::Media::ImageCreator> nativeImageCreator = nullptr;
    bool ret = (*reinterpret_cast<GetNativeImageCreatorFn>(napiFunc))(nativePtr, nativeImageCreator);
    if (!ret || nativeImageCreator == nullptr) {
        IMAGE_LOGE("%{public}s GetNativeImageCreator failed", __func__);
        return make_holder<ImageCreatorImpl, ImageCreator>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<ImageCreatorImpl, ImageCreator>(nativeImageCreator);
}

uintptr_t ImageCreatorTransferDynamicImpl(ImageCreator input)
{
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    ImageCreatorImpl* thisPtr = reinterpret_cast<ImageCreatorImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetImageCreatorNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetImageCreatorNapiFn>(napiFunc))(jsEnv, thisPtr->GetNativeImageCreator());
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetImageCreatorNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}

PixelMap PixelMapTransferStaticImpl(uintptr_t input) {
    IMAGE_LOGD("[%{public}s] IN", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);

    void* nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        IMAGE_LOGE("%{public}s unwrap esValue failed", __func__);
        return make_holder<PixelMapImpl, PixelMap>();
    }

    void* napiFunc = GetNapiFunction("GetNativePixelMap");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        return make_holder<PixelMapImpl, PixelMap>();
    }

    std::shared_ptr<OHOS::Media::PixelMap> nativePixelMap = nullptr;
    bool ret = (*reinterpret_cast<GetNativePixelMapFn>(napiFunc))(nativePtr, nativePixelMap);
    if (!ret || nativePixelMap == nullptr) {
        IMAGE_LOGE("%{public}s GetNativePixelMap failed", __func__);
        return make_holder<PixelMapImpl, PixelMap>();
    }
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return make_holder<PixelMapImpl, PixelMap>(nativePixelMap);
}

uintptr_t PixelMapTransferDynamicImpl(weak::PixelMap input) {
    IMAGE_LOGD("[%{public}s] IN", __func__);
    if (input.is_error()) {
        IMAGE_LOGE("%{public}s input is error", __func__);
        return 0;
    }
    PixelMapImpl* thisPtr = reinterpret_cast<PixelMapImpl*>(input->GetImplPtr());
    if (thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return 0;
    }

    napi_env jsEnv;
    if (!arkts_napi_scope_open(get_env(), &jsEnv)) {
        IMAGE_LOGE("%{public}s arkts_napi_scope_open failed", __func__);
        return 0;
    }

    void* napiFunc = GetNapiFunction("GetPixelMapNapi");
    if (napiFunc == nullptr) {
        IMAGE_LOGE("%{public}s GetNapiFunction failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value result = (*reinterpret_cast<GetPixelMapNapiFn>(napiFunc))(jsEnv, thisPtr->GetNativePtr());
    if (result == nullptr) {
        IMAGE_LOGE("%{public}s GetPixelMapNapi failed, result is nullptr", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t ref = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &result, reinterpret_cast<ani_ref*>(&ref));
    IMAGE_LOGD("[%{public}s] OUT", __func__);
    return ref;
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_ImageSourceTransferStaticImpl(ImageSourceTransferStaticImpl);
TH_EXPORT_CPP_API_ImageSourceTransferDynamicImpl(ImageSourceTransferDynamicImpl);
TH_EXPORT_CPP_API_ImagePackerTransferStaticImpl(ImagePackerTransferStaticImpl);
TH_EXPORT_CPP_API_ImagePackerTransferDynamicImpl(ImagePackerTransferDynamicImpl);
TH_EXPORT_CPP_API_PictureTransferStaticImpl(PictureTransferStaticImpl);
TH_EXPORT_CPP_API_PictureTransferDynamicImpl(PictureTransferDynamicImpl);
TH_EXPORT_CPP_API_AuxiliaryPictureTransferStaticImpl(AuxiliaryPictureTransferStaticImpl);
TH_EXPORT_CPP_API_AuxiliaryPictureTransferDynamicImpl(AuxiliaryPictureTransferDynamicImpl);
TH_EXPORT_CPP_API_ImageReceiverTransferStaticImpl(ImageReceiverTransferStaticImpl);
TH_EXPORT_CPP_API_ImageReceiverTransferDynamicImpl(ImageReceiverTransferDynamicImpl);
TH_EXPORT_CPP_API_ImageCreatorTransferStaticImpl(ImageCreatorTransferStaticImpl);
TH_EXPORT_CPP_API_ImageCreatorTransferDynamicImpl(ImageCreatorTransferDynamicImpl);
TH_EXPORT_CPP_API_PixelMapTransferStaticImpl(PixelMapTransferStaticImpl);
TH_EXPORT_CPP_API_PixelMapTransferDynamicImpl(PixelMapTransferDynamicImpl);