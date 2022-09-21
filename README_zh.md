

# Image组件

- [简介](#introduction)
- [目录](#index)
- [使用说明](#usage-guidelines)
  - [读像素到数组](#readPixelsToBuffer)
  - [从区域读像素](readpixels)
  - [写像素到区域](#writePixels)
  - [写buffer到像素](#writeBufferToPixels)
  - [获取图片基本信息](#getImageInfo1)
  - [获取字节](#getBytesNumberPerRow)
  - [获取位图buffer](#getPixelBytesNumber)
  - [释放位图](#release1)
  - [从图片源获取信息](#getImageInfo)
  - [获取整型值](#getImagePropertyInt)
  - [获取string类型值](#String)
  - [创建位图](#createPixelMap)
  - [更新数据](#updateData)
  - [释放图片源实例](#release2)
  - [打包图片](#packing)
  - [释放packer实例](#release3)
  - [createIncrementalSource](#createIncrementalSource)
  - [创建ImageSource实例](#createImageSource2)
  - [创建PixelMap实例](#createPixelMap2)
  - [创建imagepacker实例](#createImagePacker2)

## 简介<a name="introduction"></a>

**image_standard仓库**提供了一系列易用的接口用于存放image的源码信息，提供创建图片源和位图管理能力，支持运行标准系统的设备使用。

**图1** Image组件架构图

![](https://gitee.com/openharmony/multimedia_image_standard/raw/master/figures/Image%E7%BB%84%E4%BB%B6%E6%9E%B6%E6%9E%84%E5%9B%BE.png)



支持能力列举如下：

- 创建、释放位图。
- 读写像素。
- 获取位图信息。
- 创建、释放图片源。
- 获取图片源信息。
- 创建、释放packer实例。

## 目录<a name="index"></a>

仓目录结构如下：

```
/foundation/multimedia/image_standard  
├── frameworks                                  # 框架代码
│   ├── innerkitsimpl                           # 内部接口实现
│   │   └──image                                # Native 实现
│   └── kitsimpl                                # 外部接口实现
│       └──image                                # 外部  NAPI 实现
├── interfaces                                  # 接口代码
│   ├── innerkits                               # 内部 Native 接口
│   └── kits                                    # 外部 JS 接口
├── LICENSE                                     # 证书文件
├── ohos.build                                  # 编译文件
├── sa_profile                                  # 服务配置文件
└── services                                    # 服务实现
```

## 使用说明<a name="usage-guidelines"></a>

### 1.读像素到数组<a name="readPixelsToBuffer"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何将像素读到缓冲区。

通过调用readPixelsToBuffer读pixels到buffer。

```
readPixelsToBuffer(dst: ArrayBuffer): Promise<void>;
readPixelsToBuffer(dst: ArrayBuffer, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.readPixelsToBuffer(readBuffer).then(() => {})
```

### 2.读pixels<a name="readPixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何按照区域读像素。

通过调用readPixels读pixels。

```
readPixels(area: PositionArea): Promise<void>;
readPixels(area: PositionArea, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.readPixels(area).then(() => {})
```

### 3.写pixels<a name="writePixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何写像素。

通过调用writepixels写到指定区域。

```
writePixels(area: PositionArea): Promise<void>;
writePixels(area: PositionArea, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.writePixels(area, () => {})
```

### 4.writeBufferToPixels<a name="writeBufferToPixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何将数据写进pixels。

通过调用writeBufferToPixels写到pixel。

```
writeBufferToPixels(src: ArrayBuffer): Promise<void>;
writeBufferToPixels(src: ArrayBuffer, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.writeBufferToPixels(writeColor, () => {})
```

### 5.getImageInfo<a name="getImageInfo1"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取图片信息。

通过调用getImageInfo获取图片基本信息。

1.使用create通过属性创建pixelmap。

```
image.createPixelMap(color, opts, pixelmap =>{})
```

2.使用getImageInfo获取图片基本信息。

```
pixelmap.getImageInfo( imageInfo => {})
```

### 6.getBytesNumberPerRow<a name="getBytesNumberPerRow"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取每行字节数。

通过调用getBytesNumberPerRow获取字节数。

```
getBytesNumberPerRow(): Promise<number>;
getBytesNumberPerRow(callback: AsyncCallback<number>): void;
```

示例：

```
pixelmap.getBytesNumberPerRow((num) => {})
```

### 7.getPixelBytesNumber<a name="getPixelBytesNumber"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取buffer。

通过调用getPixelBytesNumber获取buffer数。

```
getPixelBytesNumber(): Promise<number>;
getPixelBytesNumber(callback: AsyncCallback<number>): void;
```

示例：

```
pixelmap.getPixelBytesNumber().then((num) => {
          console.info('TC_026 num is ' + num)
          expect(num == expectNum).assertTrue()
          done()
        })
```

### 8.release<a name="release1"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何释放pixelmap实例。

通过调用release释放pixelmap。

1.使用create通过属性创建pixelmap。

```
image.createPixelMap(color, opts, pixelmap =>{}
```

2.使用release释放pixelmap实例

```
pixelmap.release(()=>{
            expect(true).assertTrue();
            console.log('TC_027-1 suc');
            done();
        })  
```

### 9.getImageInfo<a name="getImageInfo"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据特定数字获取图片信息。

```
getImageInfo(index: number, callback: AsyncCallback<ImageInfo>): void;
getImageInfo(callback: AsyncCallback<ImageInfo>): void;
getImageInfo(index?: number): Promise<ImageInfo>;
```

1.创建imagesource。

```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg')
```

2.获取图片信息。

```
imageSourceApi.getImageInfo((imageInfo) => {
        console.info('TC_045 imageInfo')
        expect(imageInfo !== null).assertTrue()
        done()
      })
```

### 10.getImagePropertyInt<a name="getImagePropertyInt"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据索引获取属性的整型值。

```
getImagePropertyInt(index:number, key: string, defaultValue: number): Promise<number>;
getImagePropertyInt(index:number, key: string, defaultValue: number, callback: AsyncCallback<number>): void;
```

### 11.getImagePropertyString<a name="String"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据索引获取属性的字符型值。

```
getImagePropertyString(key: string): Promise<string>;
getImagePropertyString(key: string, callback: AsyncCallback<string>): void;
```

### 12.createPixelMap<a name="createPixelMap"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何创建pixelmap实例。

1.使用createImageSource创建图片源。

```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg')
```

2.使用createPixelMap创建pixelmap

```
imageSourceApi.createPixelMap(decodingOptions, (pixelmap) => {})
```

### 13.updateData<a name="updateData"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何更新图片数据源。

1.使用createIncrementalSource创建imagesource。

```
const dataBuffer = new ArrayBuffer(96)
const imageSourceIncrementalSApi = image.createIncrementalSource(dataBuffer)
```

2.使用updateData更新图片源。

```
imageSourceIncrementalSApi.updateData(array, false, (error, data) => {})
```

### 14.release<a name="release2"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放图片源实例。

```
release(): Promise<void>;
```

### 15.packing<a name="packing"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何压缩图片。

1.使用createImageSource创建图片源。

```
const imageSourceApi = image.createImageSource('/sdcard/test.png')
```

2.创建packer实例。

```
imagePackerApi.packing(imageSourceApi, packOpts).then((data) => {})
```

### 16.release<a name="release3"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放packer实例。

1.使用createImagePacker创建packer实例。

```
const imagePackerApi = image.createImagePacker()
```

2.使用release释放packer实例。

```
imagePackerApi.release()
```

### 17.createIncrementalSource<a name="createIncrementalSource"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何创建增量imagesource。

1.创建buffer。

```
const data = new ArrayBuffer(96)
```

2.使用createIncrementalSource创建imagesource。

```
const imageSourceApi = image.createIncrementalSource(data)
```

### 18.创建ImageSource实例<a name="createImageSource2"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何通过不同方式创建imagesource。

1.通过文件路径创建imagesource。

```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg')
```

2.通过fd创建imagesource。

```
const imageSourceApi = image.createImageSource(fd)
```

3.通过buffer创建imagesource。

```
const data = new ArrayBuffer(112)
const imageSourceApi = image.createImageSource(data)
```

### 19.创建PixelMap实例<a name="createPixelMap2"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何通过属性创建pixelmap。

1.设置属性。

```
const Color = new ArrayBuffer(96)
let opts = {
  alphaType: 0,
  editable: true,
  pixelFormat: 4,
  scaleMode: 1,
  size: { height: 2, width: 3 },
}
```

2.调用createpixelmap通过属性创建pixelmap实例。

```
image.createPixelMap(Color, opts)
      .then((pixelmap) => {
        expect(pixelmap !== null).assertTrue()
        console.info('TC_001 success')
        done()
      })
```

### 20.创建imagepacker实例<a name="createImagePacker2"></a>

image提供了操作imagepacker的接口，以下展示了如何通过属性创建imagepacker。

1.创建imagesource。

```
const imageSourceApi = image.createImageSource('/sdcard/test.png')
```

2.创建imagepacker。

```
const imagePackerApi = image.createImagePacker()
```

