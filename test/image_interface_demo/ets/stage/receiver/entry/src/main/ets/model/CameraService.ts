/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
import camera from '@ohos.multimedia.camera'
import fileio from '@ohos.fileio'
import image from '@ohos.multimedia.image'
import media from '@ohos.multimedia.media'
import mediaLibrary from '@ohos.multimedia.mediaLibrary'
import Logger from '../model/Logger'
import MediaUtils from '../model/MediaUtils'

const CameraMode = {
  MODE_PHOTO: 0, // 拍照模式
  MODE_VIDEO: 1 // 录像模式
}

const CameraSize = {
  WIDTH: 1920,
  HEIGHT: 1080
}

class CameraService {
  private tag: string = 'CameraService'
  private static instance: CameraService = new CameraService()
  private mediaUtil = MediaUtils.getInstance()
  private cameraManager: camera.CameraManager = undefined
  private cameras: Array<camera.Camera> = undefined
  private cameraId: string = ''
  private cameraInput: camera.CameraInput = undefined
  private previewOutput: camera.PreviewOutput = undefined
  private photoOutPut: camera.PhotoOutput = undefined
  private captureSession: camera.CaptureSession = undefined
  private mReceiver: image.ImageReceiver = undefined
  private photoUri: string = ''
  private fileAsset: mediaLibrary.FileAsset = undefined
  private fd: number = -1
  private curMode = CameraMode.MODE_PHOTO
  private handleTakePicture: (photoUri: string) => void = undefined

  constructor() {
    Logger.info(this.tag, 'q_y1 createImageReceiver')
    this.mReceiver = image.createImageReceiver(CameraSize.WIDTH, CameraSize.HEIGHT, 4, 8)
    Logger.info(this.tag, 'q_y1 createImageReceiver')
    this.mReceiver.on('imageArrival', () => {
      Logger.info(this.tag, 'q_y2 imageArrival')

////      从ImageReceiver读取最新的图片，并使用callback返回结果。 success
//      this.mReceiver.readLatestImage((err, image) => {
//        Logger.info(this.tag, 'q_y3 readLatestImage')
//        image.getComponent(4, (errMsg, img) => {
//          Logger.info(this.tag, 'q_y5 getComponent')
//          let buffer = new ArrayBuffer(4096)
//          this.savePicture(buffer, image)
//        })
//      })

////      从ImageReceiver读取最新的图片，并使用promise返回结果。 success
//      this.mReceiver.readLatestImage().then(image => {
//        Logger.info(this.tag, 'q_y8 readLatestImage')
//        image.getComponent(4, (errMsg, img) => {
//          Logger.info(this.tag, 'q_y10 getComponent')
//          let buffer = new ArrayBuffer(4096)
//          this.savePicture(buffer, image)
//        })
     })

//      从ImageReceiver读取下一张图片，并使用callback返回结果。 success
//      this.mReceiver.readNextImage((err, image) => {
//        Logger.info(this.tag, 'q_y14 readNextImage')
//        image.getComponent(4, (errMsg, img) => {
//          Logger.info(this.tag, 'q_y16 getComponent')
//          let buffer = new ArrayBuffer(4096)
//          this.savePicture(buffer, image)
//        })
//      })

//      从ImageReceiver读取下一张图片，并使用callback返回结果。
      this.mReceiver.readNextImage().then(image => {
        Logger.info(this.tag, 'q_y19 readNextImage')
        if (image === undefined) {
          Logger.error(this.tag, 'q_y20 failed to get valid image')
          return
        }
        image.getComponent(4, (errMsg, img) => {
          Logger.info(this.tag, 'q_y21 getComponent')
          if (errMsg || img === undefined) {
            Logger.info(this.tag, 'q_y22 failed to get valid buffer')
            return
          }
          let buffer = new ArrayBuffer(4096)
          if (img.byteBuffer) {
            buffer = img.byteBuffer
          } else {
            Logger.error(this.tag, ' q_y23 img.byteBuffer is undefined')
          }
          this.savePicture(buffer, image)
        })
      }).catch(error => {
        console.log('q_y24 readNextImage failed.');
      })

//      用于获取一个surface id供Camera或其他组件使用。使用callback返回结果。 success
      this.mReceiver.getReceivingSurfaceId((err, id) => {
        if(err) {
          Logger.error('q_y25 getReceivingSurfaceId failed.')
        } else {
          Logger.info('q_y26 getReceivingSurfaceId succeeded and id is ' + id)
        }
      })

//      //      用于获取一个surface id供Camera或其他组件使用。使用promise返回结果。 success
//      this.mReceiver.getReceivingSurfaceId().then( id => {
//        Logger.info('q_y27 getReceivingSurfaceId succeeded and id is ' + id)
//      }).catch(error => {
//        Logger.error('q_y28 getReceivingSurfaceId failed.')
//      })
    })

//    释放ImageReceiver实例并使用promise返回结果.  success
//    this.mReceiver.release().then(() => {})
//    释放ImageReceiver实例并使用callback返回结果.  success
//    this.mReceiver.release(() => {})
  }

  async savePicture(buffer: ArrayBuffer, img: image.Image) {
    Logger.info(this.tag, 'savePicture')
    this.fileAsset = await this.mediaUtil.createAndGetUri(mediaLibrary.MediaType.IMAGE)
    this.photoUri = this.fileAsset.uri
    Logger.info(this.tag, `this.photoUri = ${this.photoUri}`)
    this.fd = await this.mediaUtil.getFdPath(this.fileAsset)
    Logger.info(this.tag, `this.fd = ${this.fd}`)
    await fileio.write(this.fd, buffer)
    await this.fileAsset.close(this.fd)
    await img.release()
    Logger.info(this.tag, 'save image done')
    if (this.handleTakePicture) {
      this.handleTakePicture(this.photoUri)
    }
  }

  async initCamera(surfaceId: number) {
    Logger.info(this.tag, 'initCamera')
    if (this.curMode === CameraMode.MODE_VIDEO) {
      await this.releaseCamera()
      this.curMode = CameraMode.MODE_PHOTO
    }
    this.cameraManager = await camera.getCameraManager(globalThis.abilityContext)
    Logger.info(this.tag, 'getCameraManager')
    this.cameras = await this.cameraManager.getCameras()
    Logger.info(this.tag, `get cameras ${this.cameras.length}`)
    if (this.cameras.length === 0) {
      Logger.info(this.tag, 'cannot get cameras')
      return
    }
    this.cameraId = this.cameras[0].cameraId
    this.cameraInput = await this.cameraManager.createCameraInput(this.cameraId)
    Logger.info(this.tag, 'createCameraInput')
    this.previewOutput = await camera.createPreviewOutput(surfaceId.toString())
    Logger.info(this.tag, 'createPreviewOutput')
    let mSurfaceId = await this.mReceiver.getReceivingSurfaceId()
    this.photoOutPut = await camera.createPhotoOutput(mSurfaceId)
    this.captureSession = await camera.createCaptureSession(globalThis.abilityContext)
    Logger.info(this.tag, 'createCaptureSession')
    await this.captureSession.beginConfig()
    Logger.info(this.tag, 'beginConfig')
    await this.captureSession.addInput(this.cameraInput)
    await this.captureSession.addOutput(this.previewOutput)
    await this.captureSession.addOutput(this.photoOutPut)
    await this.captureSession.commitConfig()
    await this.captureSession.start()
    Logger.info(this.tag, 'captureSession start')
  }

  setTakePictureCallback(callback) {
    this.handleTakePicture = callback
  }

  async takePicture() {
    Logger.info(this.tag, 'takePicture')
    if (this.curMode === CameraMode.MODE_VIDEO) {
      this.curMode = CameraMode.MODE_PHOTO
    }
    let photoSettings = {
      rotation: camera.ImageRotation.ROTATION_0,
      quality: camera.QualityLevel.QUALITY_LEVEL_MEDIUM,
      location: { // 位置信息，经纬度
        latitude: 12.9698,
        longitude: 77.7500,
        altitude: 1000
      },
      mirror: false
    }
    await this.photoOutPut.capture(photoSettings)
    Logger.info(this.tag, 'takePicture done')
  }




  async releaseCamera() {
    Logger.info(this.tag, 'releaseCamera')
    await this.captureSession.stop()
    if (this.cameraInput) {
      await this.cameraInput.release()
    }
    if (this.previewOutput) {
      await this.previewOutput.release()
    }
    if (this.photoOutPut) {
      await this.photoOutPut.release()
    }
    await this.cameraInput.release()
    await this.captureSession.release()
  }
}

export default new CameraService()