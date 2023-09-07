/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JPEG_MARKER_H
#define JPEG_MARKER_H

#include <array>

namespace JpegMarker {
    constexpr unsigned int MARKER_LEN = 2;
    constexpr uint16_t MIN_MARKER = 0xFF01;
    constexpr uint16_t MAX_MARKER = 0xFFFE;
    constexpr uint16_t SOS = 0xFFDA;
    constexpr unsigned int STAND_ALONE_MARKER_LEN = 11;
    constexpr std::array<uint16_t, STAND_ALONE_MARKER_LEN> STAND_ALONE_MARKER = {
        0xFF01, // TEM
        0xFFD0, 0xFFD1, 0xFFD2, 0xFFD3, 0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7, // RST
        0xFFD8, // SOI
        0xFFD9 // EOI
    };
} // JpegMarker

#endif // JPEG_MARKER_H