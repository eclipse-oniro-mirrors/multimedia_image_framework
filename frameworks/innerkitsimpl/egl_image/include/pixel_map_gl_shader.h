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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_H

#include <iostream>
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/GrTypes.h"
#else
#include "include/gpu/GrTypes.h"
#endif
#include "pixel_map_gl_context.h"

namespace OHOS {
namespace Media {
namespace PixelMapGlShader {
class PixelMap;
enum ShaderType {
    SHADER_INVALID = -1,
    SHADER_VERTEX,
    SHADER_ROTATE,
    SHADER_SLR,
    SHADER_LAP,
    SHADER_MAX,
};

class Shader {
public:
    Shader();
    virtual ~Shader();

    virtual bool Build() { return false; }
    virtual bool LoadProgram() { return false; }
    virtual bool SetParams(GPUTransformData transformData)
    {
        transformData_ = transformData;
        targetSize_ = transformData_.targetInfo_.size;
        sourceSize_ = transformData_.sourceInfo_.size;
        return true;
    }
    virtual bool Use() { return false; }
    virtual bool Clear() = 0;
    GLuint &GetReadTexId()
    {
        return readTexId_;
    }
    void SetReadTexId(GLuint readTexId)
    {
        readTexId_ = readTexId;
    }
    GLuint &GetWriteTexId()
    {
        return writeTexId_;
    }
    void SetWriteTexId(GLuint writeTexId)
    {
        writeTexId_ = writeTexId;
    }
    GLuint &GetWriteFbo()
    {
        return writeFbo_;
    }
    bool BuildWriteTexture();
    ShaderType GetShaderType()
    {
        return type_;
    }

protected:
    GLuint loadShader(GLenum type, const char *shaderSrc);
    bool buildFromSource();
    bool buildFromBinary(unsigned char*& shaderBinary, GLenum &binaryFormat, GLuint &binarySize);

    ShaderType type_ = SHADER_INVALID;
    GLuint programId_ = 0U;
    GLuint vShader_ = 0U;
    GLuint fShader_ = 0U;
    GLuint readTexId_ = 0U;
    GLuint writeFbo_ = 0U;
    GLuint writeTexId_ = 0U;
    EGLImageKHR eglImage_ = EGL_NO_IMAGE_KHR;
    Size targetSize_;
    Size sourceSize_;
    GPUTransformData transformData_;
};

class VertexShader : public Shader {
public:
    VertexShader();
    ~VertexShader();

    bool Build() override;
    bool LoadProgram() override;
    bool Clear() override;
private:
    GLuint vbo_ = 0U;
};

class RotateShader : public Shader {
public:
    RotateShader();
    ~RotateShader() override;

    bool Build() override;
    bool Use() override;
    bool Clear() override;
    bool LoadProgram() override;
    bool SetParams(GPUTransformData transformData) override
    {
        rotateDegreeZ_ = transformData.rotateDegreeZ;
        rotateTrans_ = transformData.rotateTrans;
        return Shader::SetParams(transformData);
    }

private:
    static unsigned char *shaderBinary_;
    static GLenum binaryFormat_;
    static GLuint binarySize_;
    GLint transformLoc_ = 0;
    GLint texClipRatioLoc_ = 0;
    GLint useNativeLoc_ = 0;
    float rotateDegreeZ_ = 0.0f;
    GlCommon::Mat4 rotateTrans_ = GlCommon::Mat4(1.0f);
};

class SLRShader : public Shader {
public:
    SLRShader();
    ~SLRShader() override;

    bool Build() override;
    bool LoadProgram() override;
    bool SetParams(GPUTransformData transformData) override;
    bool Use() override;
    bool Clear() override;
    void SetEglImage(EGLImageKHR eglImage)
    {
        eglImage_ = eglImage;
    }

private:
    static unsigned char *shaderBinary_;
    static GLenum binaryFormat_;
    static GLuint binarySize_;
    GLint utexture_ = 0;
    GLint utexturew_ = 0;
    GLint utextureh_ = 0;
    GLint slrA_ = 0;
    GLint slrAMax_ = 0;
    GLint slrCoeff_ = 0;
    GLint slrCoeffTao_ = 0;
    GLuint texture_[2] = {0U, 0U};
    EGLImageKHR eglImage_ = EGL_NO_IMAGE;
};

class LapShader : public Shader {
public:
    LapShader();
    ~LapShader() override;

    bool Build() override;
    bool LoadProgram() override;
    bool SetParams(GPUTransformData transformData) override;
    bool Use() override;
    bool Clear() override;

private:
    static unsigned char *shaderBinary_;
    static GLenum binaryFormat_;
    static GLuint binarySize_;
    GLint utexture_ = 0;
    GLint alpha_ = 0;
    float param_ = 0.15;
};

class ShaderFactory {
public:
    static ShaderFactory &GetInstance() noexcept
    {
        static ShaderFactory instance;
        return instance;
    }
    std::shared_ptr<PixelMapGlShader::Shader> Get(ShaderType type)
    {
        std::shared_ptr<PixelMapGlShader::Shader> shader {nullptr};
        switch (type) {
            case SHADER_VERTEX: {
                shader = std::make_shared<PixelMapGlShader::VertexShader>();
                break;
            }
            case SHADER_ROTATE: {
                shader = std::make_shared<PixelMapGlShader::RotateShader>();
                break;
            }
            case SHADER_SLR: {
                shader = std::make_shared<PixelMapGlShader::SLRShader>();
                break;
            }
            case SHADER_LAP: {
                shader = std::make_shared<PixelMapGlShader::LapShader>();
                break;
            }
            default: {
                break;
            }
        }
        return shader;
    }
};

}
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_H
