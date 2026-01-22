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

#ifndef MOCK_HISPEED_FUNCTIONS_H
#define MOCK_HISPEED_FUNCTIONS_H

#include <cstdint>
#include <cstdlib>

// Mock 编码器句柄类型
using YuvJpegEncoder = void*;

// 回调函数类型定义
typedef bool (*WriteFunc)(void* opaque, const void* buffer, size_t size);
typedef void (*FlushFunc)(void* opaque);

// Mock 编码器实现类
class MockJpegEncoderImpl {
public:
    static MockJpegEncoderImpl& GetInstance()
    {
        static MockJpegEncoderImpl instance;
        return instance;
    }

    void SetEncodeResult(int result)
    {
        encodeResult_ = result;
    }

    int GetEncodeResult() const
    {
        return encodeResult_;
    }

    void SetCreateResult(YuvJpegEncoder result)
    {
        createResult_ = result;
    }

    YuvJpegEncoder GetCreateResult() const
    {
        return createResult_;
    }

    void Reset()
    {
        encodeResult_ = 0;                                     // SUCCESS
        createResult_ = reinterpret_cast<YuvJpegEncoder>(0x1); // 非空指针
        destroyed_ = false;
    }

    bool IsDestroyed() const
    {
        return destroyed_;
    }

    void MarkDestroyed()
    {
        destroyed_ = true;
    }

private:
    MockJpegEncoderImpl() : encodeResult_(0), createResult_(reinterpret_cast<YuvJpegEncoder>(0x1)), destroyed_(false) {}

    int encodeResult_;            // Mock 编码函数返回值
    YuvJpegEncoder createResult_; // Mock 创建函数返回值
    bool destroyed_;              // 标记编码器是否被销毁
};

// Mock 编码器创建函数
inline YuvJpegEncoder MockJpegEncoderCreate()
{
    return MockJpegEncoderImpl::GetInstance().GetCreateResult();
}

// Mock 编码器设置质量函数
inline int MockJpegEncoderSetQuality(YuvJpegEncoder encoder, int quality)
{
    if (encoder == nullptr) {
        return -1;
    }
    return 0; // SUCCESS
}

// Mock 编码器设置子采样函数
inline int MockJpegEncoderSetSubsampling(YuvJpegEncoder encoder, int subsampling)
{
    if (encoder == nullptr) {
        return -1;
    }
    return 0; // SUCCESS
}

// Mock 编码器设置 ICC 元数据函数
inline int MockJpegEncoderSetIccMetadata(YuvJpegEncoder encoder, const uint8_t* data, size_t size)
{
    if (encoder == nullptr) {
        return -1;
    }
    return 0; // SUCCESS
}

// 辅助函数：执行写入回调
inline void MockInvokeWriteCallback(WriteFunc write, FlushFunc flush, void* opaque)
{
    if (write != nullptr && opaque != nullptr) {
        static const uint8_t dummyData[] = {0xFF, 0xD8, 0xFF, 0xE0}; // JPEG SOI + APP0 标记
        write(opaque, dummyData, sizeof(dummyData));
    }
    if (flush != nullptr && opaque != nullptr) {
        flush(opaque);
    }
}

// Mock 编码函数 - 可控制返回值
inline int MockJpegEncoderEncode(YuvJpegEncoder encoder,
                                 const uint8_t* yuvData,
                                 int width,
                                 int height,
                                 int yuvFormat,
                                 WriteFunc write,
                                 FlushFunc flush,
                                 void* opaque)
{
    if (encoder == nullptr) {
        return -1;
    }
    MockInvokeWriteCallback(write, flush, opaque);
    return MockJpegEncoderImpl::GetInstance().GetEncodeResult();
}

// Mock 编码器销毁函数
inline void MockJpegEncoderDestroy(YuvJpegEncoder encoder)
{
    if (encoder != nullptr) {
        MockJpegEncoderImpl::GetInstance().MarkDestroyed();
    }
}

// 辅助函数：设置 Mock 编码结果
inline void SetMockEncodeResult(int result)
{
    MockJpegEncoderImpl::GetInstance().SetEncodeResult(result);
}

// 辅助函数：设置 Mock 创建结果
inline void SetMockCreateResult(YuvJpegEncoder result)
{
    MockJpegEncoderImpl::GetInstance().SetCreateResult(result);
}

// 辅助函数：重置 Mock 状态
inline void ResetMockState()
{
    MockJpegEncoderImpl::GetInstance().Reset();
}

// 辅助函数：检查编码器是否被销毁
inline bool IsEncoderDestroyed()
{
    return MockJpegEncoderImpl::GetInstance().IsDestroyed();
}

#endif // MOCK_HISPEED_FUNCTIONS_H
