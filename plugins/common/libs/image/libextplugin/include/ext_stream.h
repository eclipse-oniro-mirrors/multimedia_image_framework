/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_STREAM_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_STREAM_H

#include <cstddef>

#include "include/core/SkStream.h"
#include "input_data_stream.h"
#include "nocopyable.h"

namespace OHOS {
namespace ImagePlugin {
class ExtStream : public SkStream, NoCopyable {
public:
    ExtStream() = default;
    explicit ExtStream(InputDataStream *stream);
    virtual ~ExtStream() override
    {
        stream_ = nullptr;
    }

    size_t read(void *buffer, size_t size) override;
    size_t peek(void *buffer, size_t size) const override;
    size_t getLength() const override;
    bool isAtEnd() const override;
private:
    ImagePlugin::InputDataStream *stream_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_STREAM_H
