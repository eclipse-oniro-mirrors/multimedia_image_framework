/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef BMP_STREAM_H
#define BMP_STREAM_H

#include <cstdint>
#include <string>
#include "include/core/SkStream.h"
#include "input_data_stream.h"
#include "nocopyable.h"

namespace OHOS {
namespace ImagePlugin {
class BmpStream : public SkStream {
public:
    BmpStream() = default;
    explicit BmpStream(InputDataStream *stream);
    virtual ~BmpStream() override {};
    /**
     * Reads or skips size number of bytes.
     * if buffer is null, skip size bytes, return how many bytes skipped.
     * else copy size bytes into buffer, return how many bytes copied.
     */
    size_t read(void *buffer, size_t size) override;
    /**
     * Peeks size number of bytes.
     */
    size_t peek(void *buffer, size_t size) const override;
    /**
     * Returns true when all the bytes in the stream have been read.
     */
    bool isAtEnd() const override;

private:
    DISALLOW_COPY_AND_MOVE(BmpStream);
    ImagePlugin::InputDataStream *inputStream_ = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // BMP_STREAM_H
