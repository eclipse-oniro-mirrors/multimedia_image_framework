/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_JPEG_YUVDATA_CONVERTER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_JPEG_YUVDATA_CONVERTER_H

#include <cstdint>

namespace OHOS {
namespace ImagePlugin {

#define YUVCOMPONENT_MAX 4
enum YuvComponentIndex {
    YCOM = 0,
    UCOM = 1,
    VCOM = 2,
    UVCOM = 3
};

struct YuvPlaneInfo {
    uint32_t imageWidth = 0;
    uint32_t imageHeight = 0;
    uint32_t planeWidth[YUVCOMPONENT_MAX] = { 0 };
    uint32_t planeHeight[YUVCOMPONENT_MAX] = { 0 };
    uint32_t strides[YUVCOMPONENT_MAX] = { 0 };
    unsigned char *planes[YUVCOMPONENT_MAX] = { 0 };
};

int I444ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I444ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I422ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I422ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I420ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I420ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I440ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I440ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I411ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
int I411ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);

int I400ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest);
}
}
#endif