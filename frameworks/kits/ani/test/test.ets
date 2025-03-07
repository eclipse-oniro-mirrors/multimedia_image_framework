/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

import { image } from "../ets/@ohos.multimedia.image.ets";

function main() {
  loadLibrary("image_ani");

  // test createPixemap & getImageInfo
  console.log("Test PixelMap START 22222222");
   const opts: image.InitializationOptions = {
     size: { width: 480, height: 360 },
     editable: true,
     pixelFormat: 4,
   };

  const pixelMap = image.createPixelMapSync(opts);
  if (pixelMap) {
    console.log("Create PixelMap success");
  }
  //  console.log(`PixelMap create with size: ${pixelMap.getImageInfoSync().size.width}, ${pixelMap.getImageInfoSync().size.height}`);
  let retImageInfo:image.ImageInfo = pixelMap.GetImageInfoSync();
  console.log("Test PixelMap end, width: ", retImageInfo.size.width, retImageInfo.size.height, retImageInfo.pixelFormat, retImageInfo.mimeType);
  if (retImageInfo.isHdr) {
      console.log("Test PixelMap hdr ");
  } else {
      console.log("Test PixelMap not hdr ");
  }

  let imageSource: image.ImageSource = image.createImageSource(1); //"/data/local/tmp/test.png"
  if (imageSource) {
    console.log("Create ImageSource success");
  }
  let imagesourceImageInfo: image.ImageInfo  = imageSource.getImageInfo(1);
  console.log("Test ImageSource.getImageInfoSync width: ", imagesourceImageInfo.size.width, imagesourceImageInfo.size.height, imagesourceImageInfo.pixelFormat, imagesourceImageInfo.density, imagesourceImageInfo.mimeType);
    const decodeOpt: image.DecodingOptions = {
        editable: 1,
    };
  let pixelmap2: image.PixelMap = imageSource.createPixelMapSync(decodeOpt);
  if (pixelmap2) {
    console.log("Create imageSource.createPixelMapSync success");
  }
  imageSource.modifyImageProperty("Orientation", "Right-top");
  let map: Record<string, string> = {
    "Orientation": "Right-top",
    "Software" : "",
    "test" : "xxxxx",
    };
  imageSource.modifyImageProperties(map);
  let array:Array<string> = new Array<string>(4);
    array[0] = "aa"
    array[1] = "bb"
    array[2] = "cc"
    array[3] = "dd"
  let propertys: Record<string, string> = imageSource.getImageProperties(array);
  console.log("Create imageSource.getImageProperties :" + propertys);
  imageSource.release();
  const imagePacker = image.createImagePacker();
  let packOpts: image.PackingOption = new image.PackingOption(); 
  packOpts.format = "image/jpeg";
  packOpts.quality = 90;
  let arrayBuffer:ArrayBuffer = new ArrayBuffer(opts.size.width * opts.size.height *4);
  pixelMap.readPixelsToBuffer(arrayBuffer);
  console.log("pixelMap.readPixelsToBuffer sucess");
}