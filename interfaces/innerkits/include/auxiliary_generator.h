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

#ifndef INTERFACE_INNERKITS_INCLUDE_AUXILIARY_GENERATOR_H
#define INTERFACE_INNERKITS_INCLUDE_AUXILIARY_GENERATOR_H

#include "abs_image_decoder.h"
#include "auxiliary_picture.h"
#include "auxiliary_picture.h"
#include "image_type.h"
#include "image/input_data_stream.h"
#include "plugin_server.h"

namespace OHOS {
namespace Media {
using namespace ImagePlugin;
using namespace MultimediaPlugin;

class AuxiliaryGenerator {
public:
    static std::shared_ptr<AuxiliaryPicture> GenerateAuxiliaryPicture(ImageHdrType hdrType, AuxiliaryPictureType type,
        const std::string &format, std::unique_ptr<AbsImageDecoder> &extDecoder, uint32_t &errorCode);
};
} // namespace Media
} // namespace OHOS

#endif //INTERFACE_INNERKITS_INCLUDE_AUXILIARY_GENERATOR_H