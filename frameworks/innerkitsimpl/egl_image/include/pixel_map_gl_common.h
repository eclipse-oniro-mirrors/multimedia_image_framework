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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_COMMON_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_COMMON_H

#include <iostream>
#include "GLES/gl.h"
#include "image_trace.h"
#include "image_log.h"
#include "image_type.h"
#include "image_trace.h"
#include "image_utils.h"

namespace OHOS {
namespace Media {
static const int NUM_1 = 1;
static const int NUM_2 = 2;
static const int NUM_3 = 3;
static const int NUM_4 = 4;
static const int NUM_5 = 5;
static const int NUM_6 = 6;
static const float DEGREES_90 = 90.0f;
static const float DEGREES_180 = 180.0f;

class Mat4 {
public:
    Mat4()
    {
        for (int i = 0; i < NUM_4; ++i) {
            for (int j = 0; j < NUM_4; ++j) {
                data[i][j] = (i == j) ? 1.0f : 0.0f;
            }
        }
    }

    Mat4(float value)
    {
        for (int i = 0; i < NUM_4; ++i) {
            for (int j = 0; j < NUM_4; ++j) {
                data[i][j] = value;
            }
        }
    }

    Mat4(const std::array<std::array<float, NUM_4>, NUM_4>& values)
    {
        data = values;
    }

    Mat4(const Mat4& m, float degrees, const std::array<float, 3>& axis)
    {
        float radians = degrees * (M_PI / 180.0f);  // degrees to radians

        float length = std::sqrt(axis[0] * axis[0] + axis[1] * axis[1] + axis[2] * axis[2]);
        if (std::abs(length) < 1e-6 || length == 0.0f) {
            length = 1.0f;
        }
        float x = axis[0] / length;
        float y = axis[1] / length;
        float z = axis[NUM_2] / length;

        float cos_theta = std::cos(radians);
        float sin_theta = std::sin(radians);

        Mat4 rotation;
        rotation.data[0][0] = cos_theta + x * x * (1 - cos_theta);
        rotation.data[0][1] = x * y * (1 - cos_theta) - z * sin_theta;
        rotation.data[0][NUM_2] = x * z * (1 - cos_theta) + y * sin_theta;
        rotation.data[0][NUM_3] = 0;

        rotation.data[1][0] = y * x * (1 - cos_theta) + z * sin_theta;
        rotation.data[1][1] = cos_theta + y * y * (1 - cos_theta);
        rotation.data[1][NUM_2] = y * z * (1 - cos_theta) - x * sin_theta;
        rotation.data[1][NUM_3] = 0;

        rotation.data[NUM_2][0] = z * x * (1 - cos_theta) - y * sin_theta;
        rotation.data[NUM_2][1] = z * y * (1 - cos_theta) + x * sin_theta;
        rotation.data[NUM_2][NUM_2] = cos_theta + z * z * (1 - cos_theta);
        rotation.data[NUM_2][NUM_3] = 0;

        rotation.data[NUM_3][0] = 0;
        rotation.data[NUM_3][1] = 0;
        rotation.data[NUM_3][NUM_2] = 0;
        rotation.data[NUM_3][NUM_3] = 1;

        *this = multiply(m, rotation);
    }

    Mat4 multiply(const Mat4& a, const Mat4& b)
    {
        Mat4 result;
        for (int i = 0; i < NUM_4; ++i) {
            for (int j = 0; j < NUM_4; ++j) {
                result.data[i][j] = 0;
                for (int k = 0; k < NUM_4; ++k) {
                    result.data[i][j] += a.data[i][k] * b.data[k][j];
                }
            }
        }
        return result;
    }

    Mat4 operator*(const Mat4& other) const
    {
        Mat4 result;

        for (int i = 0; i < NUM_4; ++i) {
            for (int j = 0; j < NUM_4; ++j) {
                result.data[i][j] = 0.0f;
                for (int k = 0; k < NUM_4; ++k) {
                    result.data[i][j] += data[i][k] * other.data[k][j];
                }
            }
        }
        return result;
    }

    float& at(int row, int col)
    {
        return data[row][col];
    }

    const float& at(int row, int col) const
    {
        return data[row][col];
    }

    const float* GetDataPtr()
    {
        return &data[0][0];
    }
private:
    std::array<std::array<float, NUM_4>, NUM_4> data;
};

enum TransformationType {
    SCALE = 1,
    ROTATE = 2,
};

struct GlImageInfo {
    Size size;
    int32_t stride;
    int pixelBytes;
    const uint8_t *addr = nullptr;
    void *context = nullptr;
    void *outdata = nullptr;
};
typedef struct {
    float rotateDegreeZ;
    Mat4 rotateTrans;
    TransformationType transformationType;
    GLenum glFormat;
    bool isDma;
    GlImageInfo sourceInfo_;
    GlImageInfo targetInfo_;
} GPUTransformData;
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_COMMON_H
