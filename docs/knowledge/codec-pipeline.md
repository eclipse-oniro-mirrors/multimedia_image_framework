# ImageSource/ImagePacker 与编解码主链路知识入口

## 适用范围

涉及 `ImageSource`、`ImagePacker`、输入输出流、解码、编码、渐进式输入、区域解码、缩放解码、硬件编解码或插件编解码选择时，先读本文档。

## 快速代码地图

- 公开 Native inner API：`interfaces/innerkits/include/image_source.h`、`interfaces/innerkits/include/image_packer.h`、`interfaces/innerkits/include/image_type.h`。
- 主链路实现：`frameworks/innerkitsimpl/codec/`。
- 输入输出流和数据源封装：`frameworks/innerkitsimpl/stream/`。
- 编解码插件和格式扩展：`plugins/common/libs/image/`、`plugins/manager/`。
- 测试资源和目标：`frameworks/innerkitsimpl/test/`、`test/resource/`。

## 术语触发词

`ImageSource`、`ImagePacker`、incremental、region decode、sample size、desired size、desired pixel format、orientation、硬解、软解、`Heif`、`Avif`、`SkCodec`、`ImageStream`、`ImagePackerOption`。

## 先判断的问题

- 输入来自文件、fd、buffer、stream 还是应用侧增量写入。
- 输出目标是 `PixelMap`、`Picture`、编码文件、buffer 还是跨语言 API 返回值。
- 是否涉及 region decode、sample size、desired size、desired pixel format、EXIF orientation、HDR 或色彩空间。
- 是否依赖硬件 codec 能力，或需要在不同产品形态上表现一致。
- 失败路径要返回公开错误码，还是内部错误码只在本层消费。

## 关键边界

- `ImageSource`/`ImagePacker` 是公开能力入口，行为变化通常会传导到 JS、NDK、CJ、ANI、Taihe 等绑定层。
- 格式识别不是单点逻辑，通常同时依赖 stream 探测、format agent、decoder/encoder 插件和 `.pluginmeta`。
- 解码链路读取的是不可信输入，所有尺寸、offset、stride、chunk 长度、metadata 长度都要防溢出和越界。
- 编码链路要区分输入 `PixelMap` 的真实像素格式、alpha、row stride、allocator 和硬件可访问性。
- 硬件 codec 能力、插件是否可加载、第三方库编译宏开关都可能随产品变化，不能只按单机现象改默认行为。

## 常见风险

- 只改某个格式插件，遗漏 format agent 或能力查询，导致 `GetSupportedFormats` 和实际解码能力不一致。
- 在错误码转换前吞掉底层错误，导致外部 API 只能看到泛化失败。
- 对大图、畸形图片或截断流缺少长度校验，引入 OOM、越界读写或长时间阻塞。
- 对 EXIF orientation、色彩空间、HDR metadata 的处理只在解码路径生效，编码或跨语言路径没有同步。
- 在热点路径增加重复格式探测、全量 buffer 拷贝或高频 INFO 日志，影响图片加载性能。

## Ask before / 必须人工确认

- 修改公开支持格式、MIME、后缀、默认解码格式、默认缩放策略或错误码。
- 改硬件 codec 优先级、硬解 fallback、产品裁剪宏或三方库依赖。
- 改增量解码、region decode、EXIF orientation、HDR 或色彩空间默认行为。
- 改会影响 JS/NDK/CJ/ANI/Taihe 的参数校验、返回对象或异常行为。
- 无法确认 XTS 或真实设备验证路径，但改动影响公开 API 或硬件 codec 行为。

## 验证建议

- 基础构建：从 OpenHarmony 源码根目录构建 `image_framework` 和相关插件目标。
- 常用单测命令模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> imagesourcetest streamtest
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> jpegdecoderextest heif_decode_impl_test heif_hw_encoder_test
```

- 近端单测：优先选择 `imagesourcetest`、`streamtest`、对应格式 decoder/encoder 单测，以及 `imagepacker` 相关 `BUILD.gn` 目标。
- 插件相关改动：补跑 `formatagentplugintest`、`pluginsmanagersrcframeworktest` 或对应插件单测。
- 解析安全改动：补跑 ImageSource、decode、encode 相关 fuzz 目标，例如 `ImageFwkImageSourceFuzzTest`、`ImageFwkDecodeJpegFuzzTest`、`ImageFwkDecodePngFuzzTest`、`ImageFwkDecodeGifFuzzTest`、`ImageFwkDecodeSvgFuzzTest`、`ImageFwkDecodeHeifFuzzTest`、`Imagefwkencodejpeg2FuzzTest`。
- 对外 API 行为变化：补充对应 XTS 用例验证。
- 硬件 codec 或显示效果相关：需要真实设备验证，并记录产品名、输入样例、输出格式和失败/成功现象。

## 待补充背景

- 各格式在不同产品上的硬解优先级和 fallback 策略。
- 团队常用的图片样例集、异常样例集和 XTS 目标名。
- 历史线上问题中与格式探测、增量流、硬解 fallback、EXIF orientation 相关的典型案例。
