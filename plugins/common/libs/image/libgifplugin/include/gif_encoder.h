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
#ifndef GIF_ENCODER_H
#define GIF_ENCODER_H
#include <vector>
#include "abs_image_encoder.h"
#include "plugin_class_base.h"
namespace OHOS {
namespace ImagePlugin {

const int NUM_OF_RGB = 3;
const int DICTIONARY_SIZE = 8192;

typedef struct ColorType {
    uint8_t red;
    uint8_t green;
    uint8_t blue;
} ColorType;

typedef struct ColorCoordinate {
    uint8_t rgb[NUM_OF_RGB];
    uint8_t newColorIndex;
    long pixelNum;
    struct ColorCoordinate *next;
} ColorCoordinate;

typedef struct ColorSubdivMap {
    uint8_t rgbMin[NUM_OF_RGB];
    uint8_t rgbWidth[NUM_OF_RGB];
    uint32_t colorNum;
    long pixelNum;
    ColorCoordinate *coordinate;
} ColorSubdivMap;

class GifEncoder : public AbsImageEncoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    GifEncoder();
    ~GifEncoder() override;
    uint32_t StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option) override;
    uint32_t AddImage(Media::PixelMap &pixelMap) override;
    uint32_t FinalizeEncode() override;
    bool Write(const uint8_t* data, size_t data_size);

private:
    DISALLOW_COPY_AND_MOVE(GifEncoder);
    uint32_t DoEncode();
    uint32_t WriteFileInfo();
    uint32_t WriteFrameInfo(int index);
    uint32_t processFrame(int index);
    uint32_t colorQuantize(int index, uint16_t width, uint16_t height,
                           uint8_t *outputBuffer, ColorType *outputColorMap);
    uint32_t separateRGB(int index, uint16_t width, uint16_t height,
                         uint8_t *redBuffer, uint8_t *greenBuffer, uint8_t *blueBuffer);
    uint32_t doColorQuantize(uint16_t width, uint16_t height,
                             const uint8_t *redInput, const uint8_t *greenInput, const uint8_t *blueInput,
                             uint8_t *outputBuffer, ColorType *outputColorMap);
    uint32_t BuildColorSubdivMap(ColorSubdivMap *colorSubdivMap, uint32_t *colorSubdivMapSize);
    int SortCmpRtn(const void *Entry1, const void *Entry2);
    void InitDictionary();
    int IsInDictionary(uint32_t Key);
    void AddToDictionary(uint32_t Key, int Code);
    uint32_t LZWEncodeFrame(uint8_t *outputBuffer, uint16_t width, uint16_t height);
    uint32_t LZWEncode(uint8_t *buffer, int length);
    uint32_t LZWWriteOut(int Code);
    uint32_t LZWBufferOutput(int c);

private:
    OutputDataStream *outputStream_ {nullptr};
    std::vector<Media::PixelMap*> pixelMaps_;
    PlEncodeOptions encodeOpts_;
    int lastCode_;
    int eofCode_;
    int runningCode_;
    int clearCode_;
    int runningBits_;
    int maxCode_;
    int crntShiftState_;
    uint32_t crntShiftDWord_;
    uint32_t dictionary_[DICTIONARY_SIZE];
    uint8_t outputLZWBuffer_[256];
};

} // namespace ImagePlugin
} // namespace OHOS

#endif // GIF_ENCODER_H