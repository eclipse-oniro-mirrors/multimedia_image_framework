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

#include "pixel_map_gl_shader.h"

#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "Shader"
#define PI 3.1415926

namespace OHOS {
namespace Media {
namespace PixelMapGlShader {
using namespace GlCommon;
const int MAX_SLR_WIN_SIZE = 12;
std::string g_shaderPath = "/data/storage/el1/base/";
static int g_shaderVersion = 2;
const std::string &g_rotateFilePath = g_shaderPath + "pixelMapRotate.shader";
unsigned char *RotateShader::shaderBinary_ = nullptr;
GLenum RotateShader::binaryFormat_ = 0;
GLuint RotateShader::binarySize_ = 0;

const std::string &g_SlrFilePath = g_shaderPath + "pixelMapSlr.shader";
unsigned char *SLRShader::shaderBinary_ = nullptr;
GLenum SLRShader::binaryFormat_ = 0;
GLuint SLRShader::binarySize_ = 0;

const std::string &g_LapFilePath = g_shaderPath + "pixelMapLap.shader";
unsigned char *LapShader::shaderBinary_ = nullptr;
GLenum LapShader::binaryFormat_ = 0;
GLuint LapShader::binarySize_ = 0;

float GeSLRFactor(float x, int a)
{
    if (x >= a || x < -a) {
        return 0.0f;
    }
    if (std::abs(x) < 1e-16) {
        return 0.0f;
    }
    x *= PI;
    if (std::abs(x * x) < 1e-6 || x * x == 0.0f ||
        std::abs(a) < 1e-6 || a == 0.0f) {
        return 0.0f;
    }
    return a * std::sin(x) * std::sin(x / a) / (x * x);
}

static std::shared_ptr<float[]> getWeights(float coeff, int n)
{
    if (std::abs(coeff) < 1e-6 || coeff == 0.0f) {
        coeff = 1.0f;
    }
    float tao = 1.0f / coeff;
    int a = std::max(2, static_cast<int>(std::floor(tao)));

    int width = 2 * a;
    width = std::min(width, MAX_SLR_WIN_SIZE);
    std::shared_ptr<float[]> weights = std::make_shared<float>(n * MAX_SLR_WIN_SIZE);
    for (auto i = 0; i < n; i++) {
        if (std::abs(coeff) < 1e-6 || coeff == 0.0f) {
            coeff = 1.0f;
        }
        float eta_i = (i + 0.5) / coeff - 0.5;
        int eta_i_int = std::floor(eta_i);
        float sum = 0;

        int k = eta_i_int - a + 1;
        for (auto j = 0; j < width; ++j) {
            float f = GeSLRFactor(coeff * (eta_i - (k + j)), a);
            weights[i * MAX_SLR_WIN_SIZE + j] = f;
            sum += f;
        }
        for (auto j = 0; j < width; ++j) {
            weights[i * MAX_SLR_WIN_SIZE + j] /= sum;
        }
        for (auto h = width; h < MAX_SLR_WIN_SIZE; ++h) {
            weights[i * MAX_SLR_WIN_SIZE + h]  = 0;
        }
    }
    return weights;
}

static bool checkProgram(GLuint &programId)
{
    GLint linked;
    glGetProgramiv(programId, GL_LINK_STATUS, &linked);
    if (!linked) {
        GLint infoLen = 0;
        glGetProgramiv(programId, GL_INFO_LOG_LENGTH, &infoLen);
        if (infoLen > 0) {
            char *infoLog = new char[infoLen];
            if (infoLog == nullptr) {
                return false;
            }
            glGetProgramInfoLog(programId, infoLen, NULL, infoLog);
            IMAGE_LOGE("slr_gpu checkProgram faied info:%{public}s", infoLog);
            delete[] infoLog;
        }
        IMAGE_LOGE("slr_gpu checkProgram %{public}s %{public}d %{public}x", __func__, __LINE__, glGetError());
        return false;
    }
    return true;
}

static bool loadShaderFromFile(unsigned char*&shaderBinary, GLenum &binaryFormat, GLuint &binarySize,
    const char* filePath, int version)
{
    if (shaderBinary != nullptr) {
        return true;
    }

    struct stat fileStat;
    if (stat(filePath, &fileStat) != 0) {
        IMAGE_LOGE("slr_gpu shader cache is not exist! error %{public}d", errno);
        return false;
    }

    const size_t minSize = sizeof(GLenum) + sizeof(version);
    if (fileStat.st_size < minSize) {
        IMAGE_LOGE("slr_gpu shader cache file size failed! size:%{public}lld", fileStat.st_size);
        return false;
    }

    int binaryFd = open(filePath, O_RDONLY);
    if (binaryFd <= 0) {
        IMAGE_LOGE("slr_gpu shader cache open failed! error %{public}d", errno);
        return false;
    }

    unsigned char *binaryData = new unsigned char[fileStat.st_size];
    if (binaryData == nullptr) {
        return false;
    }
    int readLen = read(binaryFd, binaryData, fileStat.st_size);
    close(binaryFd);

    if (readLen != fileStat.st_size) {
        delete[] binaryData;
        IMAGE_LOGE("slr_gpu shader cache read failed! error "
            "%{public}d readnum %{public}d", errno, readLen);
        return false;
    }
    binarySize = static_cast<uint32_t>(fileStat.st_size - minSize);
    binaryFormat = *reinterpret_cast<int *>(binaryData + binarySize);
    int oldVersion = *reinterpret_cast<int *>(binaryData + fileStat.st_size - sizeof(version));
    if (oldVersion != version) {
        IMAGE_LOGI("slr_gpu oldVersion != version:%{public}d binaryFormat:%{public}d  "
            "size:%{public}d oldVersion:%{public}d", version, binaryFormat, binarySize, oldVersion);
        delete []binaryData;
        return false;
    }
    shaderBinary = binaryData;
    return true;
}

bool saveShaderToFile(unsigned char*&shaderBinary, GLenum &binaryFormat,
    GLuint &binarySize, const char* filePath, GLuint &programId)
{
    if (shaderBinary == nullptr) {
        GLint size = 0;
        glGetProgramiv(programId, GL_PROGRAM_BINARY_LENGTH, &size);
        if (size <= 0) {
            return false;
        }
        unsigned char *binary = new unsigned char[size];
        if (binary == nullptr) {
            return false;
        }
        glGetProgramBinary(programId, size, NULL, &binaryFormat, binary);
        binarySize = static_cast<uint32_t>(size);
        shaderBinary = binary;
    }
    if (shaderBinary == nullptr) {
        IMAGE_LOGE("slr_gpu shaderBinary == nullptr saveShaderToFile failed");
        return false;
    }
    if (std::filesystem::exists(filePath)) {
        std::filesystem::remove(filePath);
    }
    int binaryFd = open(filePath, O_WRONLY | O_CREAT, 0644);
    if (binaryFd <= 0) {
        IMAGE_LOGE("slr_gpu shader cache open(write) failed! error %{public}d", errno);
        return false;
    }
    write(binaryFd, shaderBinary, binarySize);
    write(binaryFd, &binaryFormat, sizeof(GLenum));
    write(binaryFd, &g_shaderVersion, sizeof(g_shaderVersion));
    close(binaryFd);
    return true;
}

Shader::Shader()
{
    glGenFramebuffers(1, &writeFbo_);
}


Shader::~Shader()
{
    glDeleteFramebuffers(1, &writeFbo_);
}

bool Shader::Clear()
{
    ImageTrace imageTrace("Shader::Clear");
    glBindTexture(GL_TEXTURE_2D, 0);
    if (programId_ != 0) {
        glDeleteProgram(programId_);
    }
    glDeleteShader(vShader_);
    glDeleteShader(fShader_);
    if (readTexId_ != 0) {
        glDeleteTextures(1, &readTexId_);
    }
    if (writeTexId_ != 0) {
        glDeleteTextures(1, &writeTexId_);
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu Shader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

GLuint Shader::loadShader(GLenum type, const char *shaderSrc)
{
    ImageTrace imageTrace("Shader::loadShader");
    GLuint shader = glCreateShader(type);
    if (shader == 0) {
        IMAGE_LOGE("slr_gpu %{public}s create shader failed (type:%{public}x)", __func__, shader);
        return 0;
    }
    glShaderSource(shader, 1, &shaderSrc, NULL);
    glCompileShader(shader);
    GLint compiled;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        GLint infoLen = 0;
        glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &infoLen);
        if (infoLen > 1) {
            char *infoLog = new char[infoLen];
            if (infoLog == nullptr) {
                return false;
            }
            glGetShaderInfoLog(shader, infoLen, NULL, infoLog);
            IMAGE_LOGE("slr_gpu Shader::LoadShader failed. info:%{public}s\n", infoLog);

            delete[] infoLog;
        }
        glDeleteShader(shader);
        IMAGE_LOGE("slr_gpu %{public}s create shader failed (type:%{public}x)", __func__, shader);
        return 0;
    }
    return shader;
}

bool Shader::buildFromSource()
{
    ImageTrace imageTrace("Shader::buildFromSource");
    if (programId_ == 0) {
        IMAGE_LOGE("slr_gpu Shader::buildFromSource  glCreateProgram");
        programId_ = glCreateProgram();
    }
    glAttachShader(programId_, vShader_);
    glAttachShader(programId_, fShader_);
    glLinkProgram(programId_);
    GLint linked;
    glGetProgramiv(programId_, GL_LINK_STATUS, &linked);
    if (!linked) {
        GLint infoLen = 0;
        glGetProgramiv(programId_, GL_INFO_LOG_LENGTH, &infoLen);
        if (infoLen > 1) {
            char *infoLog = new char[infoLen];
            if (infoLog == nullptr) {
                return false;
            }
            glGetProgramInfoLog(programId_, infoLen, NULL, infoLog);
            IMAGE_LOGE("Shader faied info:%{public}s", infoLog);
            delete[] infoLog;
        }
        IMAGE_LOGE("Shader %{public}s %{public}d %{public}x", __func__, __LINE__, glGetError());
        return false;
    }
    return true;
}

bool Shader::buildFromBinary(unsigned char*&shaderBinary, GLenum &binaryFormat, GLuint &binarySize)
{
    ImageTrace imageTrace("Shader::buildFromBinary");
    if (programId_ == 0) {
        IMAGE_LOGE("slr_gpu BuildLapProgram programLapId_ err ");
        return false;
    }
    if (shaderBinary == nullptr) {
        IMAGE_LOGE("slr_gpu BuildLapProgram g_shaderBinary is nullptr");
        return false;
    } else {
        glProgramBinary(programId_, binaryFormat, shaderBinary, binarySize);
    }
    GLint linked;
    glGetProgramiv(programId_, GL_LINK_STATUS, &linked);
    if (!linked) {
        IMAGE_LOGE("slr_gpu buildFromBinary linked failed");
        return false;
    }
    return true;
}

bool Shader::BuildWriteTexture()
{
    ImageTrace imageTrace("Shader::BuildWriteTexture");
    
    if (writeTexId_ != 0) {
        glDeleteTextures(1, &writeTexId_);
    }
    glGenTextures(1, &writeTexId_);
    glBindTexture(GL_TEXTURE_2D, writeTexId_);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, targetSize_.width, targetSize_.height,
        0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);

    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu Shader %{public}s failed gl error: %{public}d %{public}x", __func__, __LINE__, err);
        return false;
    }
    return true;
}

VertexShader::VertexShader()
{
    ImageTrace imageTrace("VertexShader::VertexShader()");
    type_ = SHADER_VERTEX;
    glGenBuffers(1, &vbo_);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_);
}
VertexShader::~VertexShader()
{
}

bool VertexShader::Clear()
{
    glDeleteBuffers(1, &vbo_);
    return true;
}

bool VertexShader::Build()
{
    ImageTrace imageTrace("VertexShader::Build");
    GLfloat quadVertices[] = {
        -1.0f, 1.0f, 0.0f, 0.0f, 1.0f,
        -1.0f, -1.0f, 0.0f, 0.0f, 0.0f,
        1.0f, -1.0f, 0.0f, 1.0f, 0.0f,
        -1.0f, 1.0f, 0.0f, 0.0f, 1.0f,
        1.0f, -1.0f, 0.0f, 1.0f, 0.0f,
        1.0f, 1.0f, 0.0f, 1.0f, 1.0f
    };
    glBufferData(GL_ARRAY_BUFFER, sizeof(quadVertices), &quadVertices, GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, NUM_3, GL_FLOAT, GL_FALSE, NUM_5 * sizeof(GLfloat), (GLvoid *)0);
    glEnableVertexAttribArray(1);
    glVertexAttribPointer(1, NUM_2, GL_FLOAT, GL_FALSE,
        NUM_5 * sizeof(GLfloat), (GLvoid *)(NUM_3 * sizeof(GLfloat)));

    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu VertexShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool VertexShader::LoadProgram()
{
    return Build();
}

RotateShader::RotateShader()
{
    type_ = SHADER_ROTATE;
}

RotateShader::~RotateShader()
{
}

bool RotateShader::Clear()
{
    return Shader::Clear();
}

bool RotateShader::Build()
{
    ImageTrace imageTrace("RotateShader::Build");
    static const char vShaderStr[] =
        "#version 320 es\n"
        "layout (location = 0) in vec3 position;\n"
        "layout (location = 1) in vec2 texCoords;\n"
        "uniform mat4 transform;\n"
        "uniform vec2 texClipRatio;\n"
        "out vec2 vTexCoords;\n"
        "void main()\n"
        "{\n"
        "    gl_Position = transform * vec4(position.x, position.y, position.z, 1.0f);\n"
        "    vTexCoords = texCoords * texClipRatio + 0.5 * (vec2(1.0, 1.0) - texClipRatio);\n"
        "}\n";
    static const char fShaderStr[] =
        "#version 320 es\n"
        "#extension GL_OES_EGL_image_external_essl3 : require\n"
        "precision mediump float;\n"
        "in vec2 vTexCoords;\n"
        "layout (binding = 0) uniform samplerExternalOES nativeTexture;\n"
        "layout (binding = 1) uniform sampler2D normalTexture;\n"
        "uniform int useNative;\n"
        "out vec4 vFragColor;\n"
        "void main()\n"
        "{\n"
        "   if (useNative == 1) {\n"
        "       vFragColor = texture(nativeTexture, vTexCoords);\n"
        "   } else {\n"
        "       vFragColor = texture(normalTexture, vTexCoords);\n"
        "   }\n"
        "}\n";
    vShader_ = loadShader(GL_VERTEX_SHADER, vShaderStr);
    fShader_ = loadShader(GL_FRAGMENT_SHADER, fShaderStr);
    if (vShader_ == 0 || fShader_ == 0) {
        IMAGE_LOGE("slr_gpu RotateShader LoadShader failed");
        return false;
    }
    if (!buildFromSource()) {
        return false;
    }
    transformLoc_ = glGetUniformLocation(programId_, "transform");
    texClipRatioLoc_ = glGetUniformLocation(programId_, "texClipRatio");
    useNativeLoc_ = glGetUniformLocation(programId_, "useNative");
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu RotateShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool RotateShader::LoadProgram()
{
    ImageTrace imageTrace("RotateShader::LoadProgram");
    if (programId_ == 0) {
        programId_ = glCreateProgram();
    }
    if (loadShaderFromFile(shaderBinary_,  binaryFormat_, binarySize_, g_rotateFilePath.c_str(), g_shaderVersion) &&
        buildFromBinary(shaderBinary_,  binaryFormat_, binarySize_)) {
        transformLoc_ = glGetUniformLocation(programId_, "transform");
        texClipRatioLoc_ = glGetUniformLocation(programId_, "texClipRatio");
        useNativeLoc_ = glGetUniformLocation(programId_, "useNative");
        if (!checkProgram(programId_)) {
            return false;
        }
        return true;
    }
    if (!Build()) {
        IMAGE_LOGE("slr_gpu RotateShader::LoadProgram Build failed");
        return false;
    }
    if (!saveShaderToFile(shaderBinary_,  binaryFormat_, binarySize_,
        g_rotateFilePath.c_str(), programId_)) {
        IMAGE_LOGE("slr_gpu RotateShader saveShaderToFile failed");
        return false;
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu RotateShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool RotateShader::Use()
{
    ImageTrace imageTrace("RotateShader::Use");
    if (!Shader::BuildWriteTexture()) {
        return false;
    }
    if (!checkProgram(programId_)) {
        return false;
    }
    glUseProgram(programId_);
    glBindFramebuffer(GL_FRAMEBUFFER, writeFbo_);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, writeTexId_, 0); //绑定
    glClearColor(0, 1, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
    uint32_t calculationTargetHeight =  rotateDegreeZ_ !=0 ?
        static_cast<uint32_t>(targetSize_.width) : static_cast<uint32_t>(targetSize_.height);
    uint32_t calculationTargetWidth =  rotateDegreeZ_ !=0 ?
        static_cast<uint32_t>(targetSize_.height) : static_cast<uint32_t>(targetSize_.width);
    float clipRatioX = sourceSize_.width > sourceSize_.height ?
        (sourceSize_.height * 1.0f / calculationTargetHeight) * calculationTargetWidth / sourceSize_.width : 1;
    float clipRatioY = sourceSize_.height > sourceSize_.width ?
        (sourceSize_.width * 1.0f / calculationTargetWidth) * calculationTargetHeight / sourceSize_.height : 1;
    glUniform2f(texClipRatioLoc_, clipRatioX, clipRatioY);
    if (eglImage_ != EGL_NO_IMAGE) {
        glUniform1i(useNativeLoc_, 1);
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_EXTERNAL_OES, readTexId_);
    } else {
        glUniform1i(useNativeLoc_, 0);
        glBindTexture(GL_TEXTURE_2D, 0);
        glActiveTexture(GL_TEXTURE1);
        glBindTexture(GL_TEXTURE_2D, readTexId_);
    }
    glViewport(0, 0, targetSize_.width, targetSize_.height);
    glUniformMatrix4fv(transformLoc_, 1, GL_FALSE, rotateTrans_.GetDataPtr());
    glDrawArrays(GL_TRIANGLES, 0, NUM_6);
    glFlush();
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu RotateShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

SLRShader::SLRShader()
{
    type_ = SHADER_SLR;
}

SLRShader::~SLRShader()
{
}

bool SLRShader::Clear()
{
    if (texture_[0] != 0) {
        glDeleteTextures(1, &texture_[0]);
    }
    if (texture_[1] != 0) {
        glDeleteTextures(1, &texture_[1]);
    }
    return Shader::Clear();
}

bool SLRShader::Build()
{
    static const char vSlrShaderStr[] =
        "#version 320 es\n"
        "layout (location = 0) in vec3 position;\n"
        "layout (location = 1) in vec2 texCoords;\n"
        "uniform mat4 transform;\n"
        "uniform vec2 texClipRatio;\n"
        "out vec2 vTexCoords;\n"
        "void main()\n"
        "{\n"
        "    gl_Position = vec4(position.x, position.y, position.z, 1.0f);\n"
        "    vTexCoords = texCoords;\n"
        "}\n";
    static const char fSlrShaderStr[] = R"(#version 320 es
        precision mediump float;
        in vec2 vTexCoords;
        layout (binding = 1) uniform sampler2D utexture;
        layout (binding = 2) uniform sampler2D utexturew;
        layout (binding = 3) uniform sampler2D utextureh;
        uniform ivec2 srcSize;
        uniform ivec2 dstSize;
        uniform ivec2 slr_a;
        uniform ivec2 slr_max;
        uniform vec2 slr_coeff;
        uniform vec2 slr_coeff_tao;
        out vec4 FragColor;
        void main()
        {
            vec2 eta = (gl_FragCoord.xy + vec2(0.5)) * slr_coeff_tao  - vec2(0.5);
            ivec2 eta_c = ivec2(floor(eta.x), floor(eta.y));
            ivec2 coord_s = ivec2(eta_c.x - slr_a.x + 1, eta_c.y - slr_a.y + 1);
            vec4 color = vec4(0, 0, 0, 0);
            for (int i = 0; i < slr_max.y; i++) {
                float w_i = texelFetch(utextureh, ivec2(i, gl_FragCoord.y), 0).r;
                vec4 t = vec4(0, 0, 0, 0);
                for (int j = 0; j < slr_max.x; j++) {
                    float w_j = texelFetch(utexturew, ivec2(j, gl_FragCoord.x), 0).r;
                    t += w_j * texelFetch(utexture, coord_s + ivec2(j, i), 0);
                }
                color += t * w_i;
            }
            FragColor = color;
        }
    )";
    ImageTrace imageTrace("SLRShader::Build");
    vShader_ = loadShader(GL_VERTEX_SHADER, vSlrShaderStr);
    fShader_ = loadShader(GL_FRAGMENT_SHADER, fSlrShaderStr);
    if (vShader_ == 0 || fShader_ == 0) {
        IMAGE_LOGE("slr_gpu SLRShader LoadShader failed");
        return false;
    }
    if (!buildFromSource()) {
        IMAGE_LOGE("slr_gpu SLRShader LoadShader failed");
        return false;
    }
    utexture_ = glGetUniformLocation(programId_, "utexture");
    utexturew_ = glGetUniformLocation(programId_, "utexturew");
    utextureh_ = glGetUniformLocation(programId_, "utextureh");
    slrA_ = glGetUniformLocation(programId_, "slr_a");
    slrAMax_ = glGetUniformLocation(programId_, "slr_max");
    slrCoeff_ = glGetUniformLocation(programId_, "slr_coeff");
    slrCoeffTao_ = glGetUniformLocation(programId_, "slr_coeff_tao");
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu SLRShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool SLRShader::LoadProgram()
{
    ImageTrace imageTrace("SLRShader::LoadProgram");
    if (programId_ == 0) {
        programId_ = glCreateProgram();
    }
    if (loadShaderFromFile(shaderBinary_,  binaryFormat_, binarySize_, g_SlrFilePath.c_str(), g_shaderVersion) &&
        buildFromBinary(shaderBinary_,  binaryFormat_, binarySize_)) {
        utexture_ = glGetUniformLocation(programId_, "utexture");
        utexturew_ = glGetUniformLocation(programId_, "utexturew");
        utextureh_ = glGetUniformLocation(programId_, "utextureh");
        slrA_ = glGetUniformLocation(programId_, "slr_a");
        slrAMax_ = glGetUniformLocation(programId_, "slr_max");
        slrCoeff_ = glGetUniformLocation(programId_, "slr_coeff");
        slrCoeffTao_ = glGetUniformLocation(programId_, "slr_coeff_tao");
        return true;
    }

    if (!Build()) {
        IMAGE_LOGE("slr_gpu SLRShader::LoadProgram Build failed");
        return false;
    }

    if (!saveShaderToFile(shaderBinary_,  binaryFormat_, binarySize_,
        g_SlrFilePath.c_str(), programId_)) {
        IMAGE_LOGE("slr_gpu SLRShader saveShaderToFile failed");
        return false;
    }

    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu SLRShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool SLRShader::SetParams(GPUTransformData transformData)
{
    if (texture_[0] == 0U) {
        glGenTextures(NUM_2, texture_);
    }
    return Shader::SetParams(transformData);
}

bool SLRShader::Use()
{
    ImageTrace imageTrace("SLRShader::Use");
    if (!Shader::BuildWriteTexture()) {
        return false;
    }
    glUseProgram(programId_);
    glBindFramebuffer(GL_FRAMEBUFFER, writeFbo_);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, writeTexId_, 0);
    glClearColor(0, 1, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
    int texture_index = 0;
    if (eglImage_ != EGL_NO_IMAGE) {
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_EXTERNAL_OES, readTexId_);
    } else {
        glBindTexture(GL_TEXTURE_2D, 0);
        glActiveTexture(GL_TEXTURE1);
        glBindTexture(GL_TEXTURE_2D, readTexId_);
        texture_index = 1;
    }
    float coeff_w = ((float)targetSize_.width) / sourceSize_.width;
    float coeff_h = ((float)targetSize_.height) / sourceSize_.height;
    float tao_w = 1.0f / coeff_w;
    int a_w = std::clamp(int(std::floor(tao_w)), 2, MAX_SLR_WIN_SIZE / 2);
    float tao_h = 1.0f / coeff_h;
    int a_h = std::clamp(int(std::floor(tao_h)), 2, MAX_SLR_WIN_SIZE / 2);
    auto h_x2 = getWeights(coeff_w, targetSize_.width);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, texture_[0]);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R32F, MAX_SLR_WIN_SIZE, targetSize_.width, 0, GL_RED, GL_FLOAT, h_x2.get());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    auto h_y2 = getWeights(coeff_h, targetSize_.height);
    glActiveTexture(GL_TEXTURE3);
    glBindTexture(GL_TEXTURE_2D, texture_[1]);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R32F, MAX_SLR_WIN_SIZE, targetSize_.height, 0, GL_RED, GL_FLOAT, h_y2.get());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glUniform2i(slrA_, a_w, a_h);
    glUniform2i(slrAMax_, a_w * NUM_2, a_h * NUM_2);
    glUniform2f(slrCoeff_, coeff_w, coeff_h);
    glUniform2f(slrCoeffTao_, tao_w, tao_h);
    glViewport(0, 0, targetSize_.width, targetSize_.height);
    glDrawArrays(GL_TRIANGLES, 0, NUM_6);
    glFlush();
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu SLRShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

LapShader::LapShader()
{
    type_ = SHADER_LAP;
}

LapShader::~LapShader()
{
}

bool LapShader::Clear()
{
    return Shader::Clear();
}

bool LapShader::Build()
{
    ImageTrace imageTrace("LapShader::Build");
    static const char vShaderStr[] =
        "#version 320 es\n"
        "layout (location = 0) in vec3 position;\n"
        "layout (location = 1) in vec2 texCoords;\n"
        "out vec2 vTexCoords;\n"
        "void main()\n"
        "{\n"
        "    gl_Position = vec4(position.x, position.y, position.z, 1.0f);\n"
        "    vTexCoords = texCoords;\n"
        "}\n";

    static const char fShaderStr[] = R"(#version 320 es
        precision mediump float;
        in vec2 vTexCoords;
        uniform sampler2D utexture;
        uniform float alpha;
        out vec4 FragColor;
        void main()
        {
            vec2 screenSize = vec2(textureSize(utexture, 0));
            vec2 uv = gl_FragCoord.xy / screenSize.xy, ps = 1. / screenSize.xy; // pixel size
            vec4 c = texture(utexture, uv);
            vec4 top = texture(utexture, uv + vec2(0.0, ps.y));
            vec4 bottom = texture(utexture, uv - vec2(0.0, ps.y));
            vec4 left = texture(utexture, uv - vec2(ps.x, 0.0));
            vec4 right = texture(utexture, uv + vec2(ps.x, 0.0));
            FragColor = c + alpha* (4.0 * c - top - bottom - left - right);
        }
    )";

    vShader_ = loadShader(GL_VERTEX_SHADER, vShaderStr);
    fShader_ = loadShader(GL_FRAGMENT_SHADER, fShaderStr);
    if (vShader_ == 0 || fShader_ == 0) {
        IMAGE_LOGE("slr_gpu LapShader LoadShader failed");
        return false;
    }
    if (!buildFromSource()) {
        IMAGE_LOGE("slr_gpu LapShader LoadShader failed");
        return false;
    }
    utexture_ = glGetUniformLocation(programId_, "utexture");
    alpha_ = glGetUniformLocation(programId_, "alpha");
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu LapShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool LapShader::LoadProgram()
{
    ImageTrace imageTrace("LapShader::LoadProgram");
    if (programId_ == 0) {
        programId_ = glCreateProgram();
    }
    if (loadShaderFromFile(shaderBinary_,  binaryFormat_, binarySize_, g_LapFilePath.c_str(), g_shaderVersion) &&
        buildFromBinary(shaderBinary_,  binaryFormat_, binarySize_)) {
        utexture_ = glGetUniformLocation(programId_, "utexture");
        alpha_ = glGetUniformLocation(programId_, "alpha");
        return true;
    }
    if (!Build()) {
        IMAGE_LOGE("slr_gpu LapShader::LoadProgram Build failed");
        return false;
    }
    if (!saveShaderToFile(shaderBinary_,  binaryFormat_, binarySize_,
        g_LapFilePath.c_str(), programId_)) {
        IMAGE_LOGE("slr_gpu LapShader saveShaderToFile failed");
        return false;
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu LapShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool LapShader::SetParams(GPUTransformData transformData)
{
    float coeff = ((float)targetSize_.width) / sourceSize_.width;
    if (coeff > 0.8f) {
        param_ = 0;
    } else if (coeff > 0.6f) {
        param_ = 0.06f;
    } else if (coeff > 0.5f) {
        param_ = 0.1f;
    } else {
        param_ = 0.15f;
    }
    return Shader::SetParams(transformData);
}

bool LapShader::Use()
{
    ImageTrace imageTrace("LapShader::Use");
    if (!Shader::BuildWriteTexture()) {
        return false;
    }
    glUseProgram(programId_);
    glBindFramebuffer(GL_FRAMEBUFFER, writeFbo_);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, writeTexId_, 0);
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, readTexId_);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glUniform1f(alpha_, param_);
    glViewport(0, 0, targetSize_.width, targetSize_.height);
    glDrawArrays(GL_TRIANGLES, 0, NUM_6);
    glFlush();
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu LapShader %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}
}
} // namespace Media
} // namespace OHOS
