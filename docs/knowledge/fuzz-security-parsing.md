# Fuzz、安全解析与传输边界知识入口

## 适用范围

涉及图片文件解析、metadata 解析、插件 header 探测、Parcel/TLV 反序列化、跨进程传输、fuzz 目标或安全攻击面分析时，先读本文档。

## 快速代码地图

- Fuzz 目标：`frameworks/innerkitsimpl/test/fuzztest/`。
- 编解码和流解析：`frameworks/innerkitsimpl/codec/`、`frameworks/innerkitsimpl/stream/`。
- metadata 解析：`frameworks/innerkitsimpl/accessor/`。
- 插件解析：`plugins/common/libs/image/`、`plugins/manager/`。
- PixelMap/Picture 传输：`frameworks/innerkitsimpl/common/`、`frameworks/innerkitsimpl/picture/` 中 Parcel/TLV 相关实现。

## 术语触发词

fuzz、AFL、libFuzzer、TLV、Parcel、unmarshal、marshalling、越界、溢出、OOM、截断流、恶意图片、畸形 metadata、fd 泄漏、double free、UAF、`PixelMapRecordParcel`。

## 先判断的问题

- 输入是否来自应用、文件、网络下载内容、跨进程 Parcel/TLV 或第三方库回调。
- 数据长度、offset、stride、维度、metadata size、chunk size 是否全部有上限和溢出保护。
- 解析失败后是否能释放已申请资源，并保持对象处于可析构状态。
- 改动是否扩大了某类格式或 metadata 的可接受范围。
- 是否需要新增 fuzz 样例或把历史崩溃样例纳入回归。

## 关键边界

- 图片文件、metadata、Parcel/TLV 反序列化内容都应按不可信输入处理。
- 修改传输相关函数时，要重点考虑安全攻击问题，包括越界读写、整数溢出、资源耗尽、fd 泄漏、重复释放和类型混淆。
- `PixelMapRecordParcel` 仅用于 RS 侧图片录制回放逻辑，是测试框架相关代码；业务分析和普通代码适配中，可以忽略此文件下的函数，除非任务明确涉及 RS 录制回放。
- Fuzz 目标要覆盖成功路径和失败路径，不能只验证正常样例。
- 调用第三方库前要先完成框架侧尺寸、长度和参数保护，不能假设第三方库会兜底。

## 常见风险

- 反序列化先分配大内存，再校验尺寸合法性，导致 OOM 攻击。
- `width * height * bytesPerPixel`、row stride、metadata 长度计算缺少溢出保护。
- 截断流导致状态机进入半初始化状态，析构或重试时崩溃。
- TLV/Parcel 新增字段没有版本或长度兼容处理，旧数据读取失败。
- fuzz 只跑当前模块，遗漏插件、metadata 或多语言入口的组合路径。

## Ask before / 必须人工确认

- 改 Parcel/TLV 格式、字段顺序、长度语义、兼容策略或反序列化入口。
- 改 fuzz harness、触发样例、历史漏洞回归样例或安全修复判断标准。
- 放宽图片、metadata、插件 header、尺寸、stride、offset 或 chunk 长度的接受范围。
- 删除边界检查、内存上限、溢出保护、fd 释放保护或异常路径清理。
- 安全修复无法复现原始问题或无法确认对应回归用例。

## 验证建议

- 全量 fuzz 构建模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> fuzztest
```

- 单项 fuzz 构建模板：从 `frameworks/innerkitsimpl/test/fuzztest/**/BUILD.gn` 读取 `ohos_fuzztest("<target>")`，再执行 `prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> <target>`。
- 编解码解析：选择 ImageSource、decode、encode 相关 fuzz 目标，例如 `ImageFwkImageSourceFuzzTest`、`ImageFwkImageSource2FuzzTest`、`ImageFwkDecodeJpegFuzzTest`、`ImageFwkDecodePngFuzzTest`、`ImageFwkDecodeGifFuzzTest`、`ImageFwkDecodeSvgFuzzTest`、`ImageFwkDecodeHeifFuzzTest`。
- metadata：选择 EXIF、XMP、HEIF metadata、DNG metadata、image accessor 相关 fuzz，例如 `ImageFwkExifJpegFuzzTest`、`ImageFwkExifPngFuzzTest`、`ImageFwkExifWebpFuzzTest`、`ImageHeifsMetadataFuzzTest`、`ImageDngExifMetadataFuzzTest`、`ImageAccessor2FuzzTest`。
- 插件：选择 JPEG/PNG/GIF/SVG/TIFF/RAW/EXT 插件相关 fuzz，例如 `ImagePlugin2FuzzTest`、`ImagePlugin3FuzzTest`、`ImageTiffPluginFuzzTest`、`ImageRawPluginFuzzTest`、`ImageJpegYuvPluginFuzzTest`。
- Creator/Receiver 和跨进程：选择 `ImageReceiverFuzzTest` 及 Parcel/TLV 相关 fuzz。
- 公开 API 入口：补充 JS/NDK/CJ 等最近单测和 XTS，确认异常输入对外表现一致。
- 安全修复：记录触发样例、修复前后现象、资源释放路径和新增回归用例。

## 待补充背景

- 团队维护的历史崩溃样例集和安全问题归档方式。
- 各 fuzz 目标与模块能力之间的映射表。
- Parcel/TLV 格式演进策略和旧数据兼容要求。
