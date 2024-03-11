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

#ifndef PLUGIN_METADATA_H
#define PLUGIN_METADATA_H

namespace OHOS {
namespace MultimediaPlugin {
const std::vector<std::string> META_DATA = {
    R"(
        {
          "packageName":"LibJpegPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libjpegplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::JpegDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/jpeg"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::JpegEncoder",
              "services": [
                {
                  "interfaceID":3,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/jpeg"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibPngPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libpngplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::PngDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/png"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibRawPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"librawplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::RawDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/x-raw"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibSvgPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libsvgplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::SvgDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/svg+xml"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibWebpPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libwebpplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::WebpDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/webp"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::WebpEncoder",
              "services": [
                {
                  "interfaceID":3,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/webp"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibBmpPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libbmpplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::BmpDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/bmp"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibGifPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libgifplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::GifDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/gif"
                }
              ]
            }
          ]
        }
    )",
    R"(
        {
          "packageName":"LibExtPlugin",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libextplugin.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::ExtDecoder",
              "services": [
                {
                  "interfaceID":2,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/extended"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::ExtEncoder",
              "services": [
                {
                  "interfaceID":3,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/extended"
                }
              ]
            }
        ]
      }

    )",

    R"(
        {
          "packageName":"LibImageFormatAgent",
          "version":"1.0.0.0",
          "targetVersion":"1.0.0.0",
          "libraryPath":"libimageformatagent.z.so",
          "classes": [
            {
              "className":"OHOS::ImagePlugin::JpegFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/jpeg"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::PngFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/png"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::GifFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/gif"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::HeifFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/heif"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::WebpFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/webp"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::BmpFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/bmp"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::WbmpFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/vnd.wap.wbmp"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::SvgFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/svg+xml"
                }
              ]
            },
            {
              "className":"OHOS::ImagePlugin::RawFormatAgent",
              "services": [
                {
                  "interfaceID":1,
                  "serviceType":0
                }
              ],
              "priority":100,
              "capabilities": [
                {
                  "name":"encodeFormat",
                  "type":"string",
                  "value": "image/x-raw"
                }
              ]
            }
          ]
        }
    )"
};
} // namespace MultimediaPlugin
} // namespace OHOS

#endif // PLUGIN_METADATA_H
