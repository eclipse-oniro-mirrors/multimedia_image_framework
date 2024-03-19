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

#ifndef MOCK_DATA_STREAM_H
#define MOCK_DATA_STREAM_H

#include "source_stream.h"

namespace OHOS {
namespace ImagePlugin {
static constexpr size_t NUMBER_ONE = 1;
static constexpr size_t NUMBER_TWO = 2;
class MockInputDataStream : public Media::SourceStream {
public:
    MockInputDataStream() = default;
    ~MockInputDataStream() {}

    uint32_t UpdateData(const uint8_t *data, uint32_t size, bool isCompleted) override
    {
        return Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    bool Read(uint32_t desiredSize, DataStreamBuffer &outData) override
    {
        if (streamSize == NUMBER_ONE) {
            streamBuffer = std::make_shared<uint8_t>(streamSize);
            outData.inputStreamBuffer = streamBuffer.get();
        } else if (streamSize == NUMBER_TWO) {
            outData.dataSize = streamSize;
        }
        return returnValue_;
    }

    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        return returnValue_;
    }

    bool Peek(uint32_t desiredSize, DataStreamBuffer &outData) override
    {
        return returnValue_;
    }

    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        return returnValue_;
    }

    uint32_t Tell() override
    {
        return 0;
    }

    bool Seek(uint32_t position) override
    {
        return returnValue_;
    }

    uint32_t GetStreamType() override
    {
        return -1;
    }

    uint8_t *GetDataPtr() override
    {
        return nullptr;
    }

    bool IsStreamCompleted() override
    {
        return returnValue_;
    }

    size_t GetStreamSize() override
    {
        return streamSize;
    }

    void SetReturn(bool returnValue)
    {
        returnValue_ = returnValue;
    }

    void SetStreamSize(size_t size)
    {
        streamSize = size;
    }

private:
    bool returnValue_ = false;
    size_t streamSize = 0;
    std::shared_ptr<uint8_t> streamBuffer = nullptr;
};

class MockOutputDataStream : public OutputDataStream {
public:
    MockOutputDataStream() = default;
    ~MockOutputDataStream() {}

    bool Write(const uint8_t *buffer, uint32_t size)
    {
        return bool_;
    }

private:
    bool bool_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // MOCK_DATA_STREAM_H