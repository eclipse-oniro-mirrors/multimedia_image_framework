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

#include "native_module_ohos_image.h"

#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "NAPITEST"

namespace OHOS {
namespace Media {
/*
 * Function registering all props and functions of ohos.medialibrary module
 */
static napi_value Export(napi_env env, napi_value exports)
{
    IMAGE_LOGD("ImagePackerNapi CALL");
    ImagePackerNapi::Init(env, exports);
    IMAGE_LOGD("PixelMapNapi CALL");
    PixelMapNapi::Init(env, exports);
    IMAGE_LOGD("ImageSourceNapi CALL");
    ImageSourceNapi::Init(env, exports);
    IMAGE_LOGD("PictureNapi CALL");
    PictureNapi::Init(env, exports);
    IMAGE_LOGD("AuxiliaryPictureNapi CALL");
    AuxiliaryPictureNapi::Init(env, exports);
    IMAGE_LOGD("MetadataNapi CALL");
    MetadataNapi::Init(env, exports);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    IMAGE_LOGD("ImageReceiverNapi CALL");
    ImageReceiverNapi::Init(env, exports);
    IMAGE_LOGD("ImageCreatorNapi CALL");
    ImageCreatorNapi::Init(env, exports);
    IMAGE_LOGD("ImageNapi CALL");
    ImageNapi::Init(env, exports);
#endif
    return exports;
}

/*
 * module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "multimedia.image",
    .nm_priv = (reinterpret_cast<void *>(0)),
    .reserved = {0}
};

/*
 * module register
 */
extern "C" __attribute__((constructor)) void ImageRegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace Media
} // namespace OHOS
