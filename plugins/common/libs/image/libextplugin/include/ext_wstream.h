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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_WSTREAM_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_WSTREAM_H

#include <cstddef>
#include <vector>
#include "include/core/SkStream.h"
#include "output_data_stream.h"
#include "nocopyable.h"
#include "buffer_metadata_stream.h"

namespace OHOS {
namespace ImagePlugin {
class ExtWStream : public SkWStream, NoCopyable {
public:
    ExtWStream() = default;
    explicit ExtWStream(OutputDataStream *stream);
    virtual ~ExtWStream() override
    {
        stream_ = nullptr;
    }
    bool write(const void* buffer, size_t size) override;
    void flush() override;
    size_t bytesWritten() const override;
private:
    ImagePlugin::OutputDataStream *stream_;
};

class MetadataWStream : public SkWStream, NoCopyable {
public:
    MetadataWStream() {stream_ = new Media::BufferMetadataStream();};
    virtual ~MetadataWStream() override
    {
        delete stream_;
        stream_ = nullptr;
    }
    bool write(const void* buffer, size_t size) override;
    void flush() override{};
    size_t bytesWritten() const override;
    uint8_t* GetAddr();
private:
    Media::BufferMetadataStream *stream_;
};

} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_WSTREAM_H
