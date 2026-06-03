# Metadata、Picture 与辅助图知识入口

## 适用范围

涉及 EXIF、XMP、metadata key、HDR metadata、`Picture`、`AuxiliaryPicture`、gainmap、fragment metadata 或图片附加信息解析与传输时，先读本文档。

## 快速代码地图

- metadata/accessor 实现：`frameworks/innerkitsimpl/accessor/`。
- `Picture` 和辅助图实现：`frameworks/innerkitsimpl/picture/`。
- 通用工具和 HDR/色彩相关处理：`frameworks/innerkitsimpl/utils/`。
- Native inner 头文件：`interfaces/innerkits/include/` 中 `metadata`、`picture`、`auxiliary_picture`、`image_type` 相关文件。
- 语言绑定：`frameworks/kits/js/`、`frameworks/kits/native/`、`frameworks/kits/cj/`、`frameworks/kits/ani/`、`frameworks/kits/taihe/`。

## 术语触发词

EXIF、XMP、metadata key、`PropertyKey`、`ImageMetadata`、`Picture`、`AuxiliaryPicture`、gainmap、HDR metadata、fragment metadata、HEIF metadata、DNG、GPS、orientation。

## 先判断的问题

- 处理的是容器级 metadata、像素相关 metadata，还是 `Picture`/辅助图结构。
- key 是否是公开行为的一部分，是否已暴露到 JS、NDK、CJ、ANI 或 Taihe。
- metadata 来源是可信内部结构，还是来自图片文件、Parcel/TLV 或应用输入。
- 修改是否影响编码、解码、拷贝、序列化、反序列化和跨进程传输。
- HDR/gainmap/辅助图是否需要与主图尺寸、色彩空间、像素格式保持约束关系。

## 关键边界

- metadata key、错误码和公开结构体字段属于 API 行为，新增、删除或改名要同步检查多语言映射。
- EXIF/XMP 等解析面对不可信输入，必须限制长度、层级、字符串编码和数值范围。
- `Picture` 可能携带主图、辅助图、metadata 和 HDR 信息，改动时要同时看创建、拷贝、编码、Parcel/TLV 和释放路径。
- 辅助图和 HDR metadata 与图形显示链路有关，真实显示效果需要设备验证。
- 修改 metadata 写入逻辑时，要确认原图格式是否支持该字段，以及不支持时的错误码和 fallback。

## 常见风险

- 只改 C++ metadata key，遗漏 JS/NDK/CJ/ANI/Taihe 常量或错误码映射。
- EXIF 数值单位、旋转方向、时间字段或 GPS 字段在读写两端不一致。
- `Picture` 深拷贝和序列化遗漏辅助图或 metadata，导致跨进程后信息丢失。
- HDR/gainmap 只在解码路径保留，编码或显示路径被静默丢弃。
- 对异常 metadata 长度缺少保护，引入越界、OOM 或解析耗时攻击。

## Ask before / 必须人工确认

- 新增、删除、重命名公开 metadata key，或改变 key 的类型、单位、取值范围、默认值。
- 改 EXIF orientation、GPS、时间、色彩、HDR/gainmap 的读写语义。
- 改 `Picture`/`AuxiliaryPicture` 的序列化、拷贝、编码、解码或跨进程传输结构。
- 改影响 JS/NDK/CJ/ANI/Taihe 常量、错误码或返回对象的行为。
- 没有真实设备或显示链路，但改动影响 HDR/gainmap/辅助图显示效果。

## 验证建议

- metadata 改动：优先跑 `imageaccessortest`、`exifmetadatatest`、`xmpmetadatatest`、`metadatatest`。
- `Picture`/辅助图改动：优先跑 `picturetest`、`auxiliarypicturetest`、`picture_ext_test`。
- 常用单测命令模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> imageaccessortest exifmetadatatest xmpmetadatatest metadatatest
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> picturetest auxiliarypicturetest picture_ext_test
```

- 解析安全改动：补跑 EXIF、XMP、HEIF metadata、DNG metadata、Picture decode 相关 fuzz，例如 `ImageFwkExifJpegFuzzTest`、`ImageFwkExifPngFuzzTest`、`ImageFwkExifWebpFuzzTest`、`ImageFwkExifDngFuzzTest`、`ImageHeifsMetadataFuzzTest`、`ImageDngExifMetadataFuzzTest`、`ImageExifMetadataFormatterFuzzTest`、`ImageFwkDecodePictureFuzzTest`。
- 公开 key 或错误码变化：补充对应 XTS 用例，并检查各语言绑定常量和错误码转换。
- HDR/显示相关：补充真实设备验证，记录输入样例、显示链路和对比结果。

## 待补充背景

- 团队认可的 metadata key 命名和兼容策略。
- HDR/gainmap 辅助图在不同产品和显示链路上的支持矩阵。
- EXIF/XMP 历史兼容问题、线上异常样例和安全问题案例。
