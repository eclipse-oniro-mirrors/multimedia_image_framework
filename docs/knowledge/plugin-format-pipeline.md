# 插件框架与格式能力知识入口

## 适用范围

涉及图片格式识别、插件加载、`.pluginmeta`、`AbsImageFormatAgent`、`AbsImageDecoder`、`AbsImageEncoder`、扩展格式支持或插件能力查询时，先读本文档。

## 快速代码地图

- 插件管理：`plugins/manager/`。
- 公共插件接口：`plugins/common/libs/image/`。
- 格式识别插件：`plugins/common/libs/image/formatagentplugin/`。
- 扩展插件：`plugins/common/libs/image/libextplugin/`、`librawplugin/`、`libsvgplugin/`、`libtiffplugin/`。
- 插件测试：`plugins/manager/test/`、`frameworks/innerkitsimpl/test/`。

## 术语触发词

`.pluginmeta`、`AbsImageFormatAgent`、`AbsImageDecoder`、`AbsImageEncoder`、format agent、decoder plugin、encoder plugin、plugin manager、MIME、extension、RAW、SVG、TIFF、EXT、third-party codec。

## 先判断的问题

- 任务是新增格式、修改格式识别、修改解码/编码能力，还是调整插件加载机制。
- 能力是否需要出现在公开查询接口中，例如支持格式、编码格式、MIME 或后缀能力。
- `.pluginmeta`、format agent、decoder、encoder 是否需要同步修改。
- 插件是否依赖第三方库、编译宏、系统能力或产品裁剪。
- 失败时应 fallback 到其他插件，还是返回明确错误。

## 关键边界

- 插件能力由元数据、format agent 和实际 decoder/encoder 共同决定，不能只改一个入口。
- 格式探测通常发生在不可信输入的最前面，读取 header 时必须限制长度并处理截断数据。
- 插件加载失败、符号缺失、第三方库不可用时，要保持主框架可控失败，不能影响其他格式。
- 新增或调整三方库依赖时，需要确认 license、bundle 依赖、产品裁剪和安全风险。
- 修改插件对外能力会影响 `ImageSource`、`ImagePacker` 和多语言 API 的查询结果。

## 常见风险

- `.pluginmeta` 宣称支持某格式，但 decoder/encoder 未注册或编译宏未打开。
- format agent 探测过宽，把其他格式误识别为新格式。
- 插件内部错误码没有映射到框架错误码，外部 API 难以定位问题。
- 新增格式只在本地样例通过，没有覆盖畸形 header、空文件、截断流和超大尺寸。
- 插件初始化时做重操作，拖慢普通图片路径。

## Ask before / 必须人工确认

- 新增、删除或调整公开格式能力、MIME、后缀、编码能力或解码能力。
- 修改 `.pluginmeta` 字段语义、插件加载路径、插件优先级或 fallback 策略。
- 引入、升级、裁剪第三方库，或改变 license、编译宏、产品启用矩阵。
- 改格式探测边界，可能影响其他格式误判或能力查询结果。
- 无法确认对应 XTS、插件矩阵或产品配置，但改动会影响对外能力。

## 验证建议

- 插件管理改动：优先跑 `PluginManagerTest`、`pluginsmanagersrcframeworktest`。
- 格式识别改动：优先跑 `formatagentplugintest`、`format_agent_plugin_src_test`。
- 扩展格式改动：选择对应插件单测和 ImageSource 解码用例。
- 常用单测命令模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> PluginManagerTest pluginsmanagersrcframeworktest
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> formatagentplugintest format_agent_plugin_src_test
```

- 安全解析改动：补跑对应格式 fuzz 目标，例如 `ImagePlugin2FuzzTest`、`ImagePlugin3FuzzTest`、`ImageTiffPluginFuzzTest`、`ImageRawPluginFuzzTest`、`ImageJpegYuvPluginFuzzTest`、`ImageFwkDecodeSvgFuzzTest`、`ImageFwkDecodeExtFuzzTest`。
- 能力查询变化：检查 JS/NDK/Native 查询接口和 XTS 预期。
- 第三方库或硬件能力相关：记录编译宏、产品配置和真实设备验证情况。

## 待补充背景

- 各插件在不同产品上的默认启用矩阵。
- `.pluginmeta` 字段含义、命名规范和历史兼容要求。
- 格式误判、插件加载失败、三方库漏洞修复相关的典型案例。
