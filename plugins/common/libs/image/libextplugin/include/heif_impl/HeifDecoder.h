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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H

#include <cstddef>
#include <cstdint>
#include <vector>

enum SkHeifColorFormat {
    kHeifColorFormat_RGB565,
    kHeifColorFormat_RGBA_8888,
    kHeifColorFormat_BGRA_8888,
    kHeifColorFormat_NV12,
    kHeifColorFormat_NV21,
};

struct HeifStream {
    virtual ~HeifStream() {}

    virtual size_t read(void*, size_t) = 0;
    virtual bool   rewind()            = 0;
    virtual bool   seek(size_t)        = 0;
    virtual bool   hasLength() const   = 0;
    virtual size_t getLength() const   = 0;
    virtual bool   hasPosition() const = 0;
    virtual size_t getPosition() const = 0;
};

struct HeifNclxColor {
    uint16_t colorPrimaries;
    uint16_t transferCharacteristics;
    uint16_t matrixCoefficients;
    uint8_t fullRangeFlag;
};

struct HeifFrameInfo {
    uint32_t mWidth;
    uint32_t mHeight;
    int32_t  mRotationAngle;           // Rotation angle, clockwise, should be multiple of 90
    uint32_t mBytesPerPixel;           // Number of bytes for one pixel
    int64_t mDurationUs;               // Duration of the frame in us
    std::vector<uint8_t> mIccData;     // ICC data array
    bool hasNclxColor = false;
    HeifNclxColor nclxColor;
};

enum class HeifImageHdrType {
    UNKNOWN = 0,
    VIVID_DUAL = 1,
    VIVID_SINGLE,
    ISO_DUAL,
    ISO_SINGLE,
};

struct HeifDecoder {
    HeifDecoder() {}

    virtual ~HeifDecoder() {}

    virtual bool init(HeifStream* stream, HeifFrameInfo* frameInfo) = 0;

    virtual bool getSequenceInfo(HeifFrameInfo* frameInfo, size_t *frameCount) = 0;

    virtual bool decode(HeifFrameInfo* frameInfo) = 0;

    virtual bool decodeSequence(int frameIndex, HeifFrameInfo* frameInfo) = 0;

    virtual bool setOutputColor(SkHeifColorFormat colorFormat) = 0;

    virtual void setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context) = 0;

    virtual bool getScanline(uint8_t* dst) = 0;

    virtual size_t skipScanlines(int count) = 0;
    virtual bool getImageInfo(HeifFrameInfo *frameInfo) = 0;
    virtual bool decodeGainmap() = 0;
    virtual void setGainmapDstBuffer(uint8_t* dstBuffer, size_t rowStride) = 0;
    virtual bool getGainmapInfo(HeifFrameInfo* frameInfo) = 0;
    virtual bool getTmapInfo(HeifFrameInfo* frameInfo) = 0;
    virtual HeifImageHdrType getHdrType() = 0;
    virtual void getVividMetadata(std::vector<uint8_t>& uwaInfo, std::vector<uint8_t>& displayInfo,
        std::vector<uint8_t>& lightInfo) = 0;
    virtual void getISOMetadata(std::vector<uint8_t>& isoMetadata) = 0;
    virtual void getErrMsg(std::string& errMsg) = 0;
};

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H
