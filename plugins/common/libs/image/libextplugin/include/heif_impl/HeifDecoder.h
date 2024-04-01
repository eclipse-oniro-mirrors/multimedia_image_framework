//
// Created by canx on 3/29/24.
//

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H

#include <cstddef>
#include <cstdint>
#include <vector>

enum SkHeifColorFormat {
    kHeifColorFormat_RGB565,
    kHeifColorFormat_RGBA_8888,
    kHeifColorFormat_BGRA_8888,
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

struct HeifFrameInfo {
    uint32_t mWidth;
    uint32_t mHeight;
    int32_t  mRotationAngle;           // Rotation angle, clockwise, should be multiple of 90
    uint32_t mBytesPerPixel;           // Number of bytes for one pixel
    int64_t mDurationUs;               // Duration of the frame in us
    std::vector<uint8_t> mIccData;     // ICC data array
};

struct HeifDecoder {
    HeifDecoder() {}

    virtual ~HeifDecoder() {}

    virtual bool init(HeifStream* stream, HeifFrameInfo* frameInfo) = 0;

    virtual bool getSequenceInfo(HeifFrameInfo* frameInfo, size_t *frameCount) = 0;

    virtual bool decode(HeifFrameInfo* frameInfo) = 0;

    virtual bool decodeSequence(int frameIndex, HeifFrameInfo* frameInfo) = 0;

    virtual bool setOutputColor(SkHeifColorFormat colorFormat) = 0;

    virtual void setDstBuffer(uint8_t *dstBuffer, size_t rowStride) = 0;

    virtual bool getScanline(uint8_t* dst) = 0;

    virtual size_t skipScanlines(int count) = 0;
};

#endif //PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_DECODER_H
