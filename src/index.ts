'use strict'
import fs from 'fs'
import express, { Application, Router } from 'express'
import { Module } from './modules/module-interface'
import cors from 'cors'
import { verifyToken } from './core/middlewares/auth/verifyToken'
import { Config } from './core/config/env'
import AuthModule from './modules/auth/auth-module'
import morgan from 'morgan'
import path from 'path'

export type {
  SearchDatabase,
  SearchGetPayload,
  SearchPayload,
} from './core/interfaces/global-interface'
export { onSuccess, onError } from './core/helpers/response'
export { Global } from './core/helpers/_globals'
export { sendEmail } from './core/providers/nodemailer'
export * from './core/helpers/error'
export { verifyToken } from './core/middlewares/auth/verifyToken'
export interface Bootstrap {
  modules: Array<Module>
  context: string
  version: string
}
export class PullupModules implements Bootstrap {
  public modules: Array<Module> = [new AuthModule('auth')]
  public context: string
  public version: string
  private _env: Config

  constructor(modules: Array<Module>) {
    this._env = Config.instance
    this.modules = this.modules.concat(modules)
    this.context = this._env.config.apiContext || 'api'
    this.version = this._env.config.apiVersion || 'v1'
  }

  public bootstrap() {
    const router: Router = Router()
    const app: Application = express()

    app.disable('x-powered-by')
    app.use(morgan('dev'))
    app.use(
      cors({
        allowedHeaders: [
          'Origin',
          'X-Requested-With',
          'Content-Type',
          'queue-token',
          'Accept',
          'X-Access-Token',
          'Authorization',
        ],
        credentials: true,
        methods: 'GET,HEAD,OPTIONS,PUT,PATCH,POST,DELETE',
        origin: '*',
        preflightContinue: false,
      })
    )
    app.use(express.json({ limit: '300mb' }))
    app.use(express.urlencoded({ extended: true }))

    const moduleOcurrencies = this.modules.filter(
      (module) => module.moduleName === 'auth'
    )
    if (moduleOcurrencies.length > 1) this.modules.shift()

    this.modules.forEach((module) => {
      router.use(
        `/${this.context}/${this.version}/${module.moduleName}`,
        -!module.isPublic ? verifyToken : (_, __, next) => next(),
        module.router.router
      )
    })
    app.use(router)

    app
      .listen(process.env.PORT || this._env.config.serverPort, () => {
        console.log(
          `Server up and running on port: ${this._env.config.serverPort} `
        )
      })
      .on('error', (error) => console.error(`Error: ${error}`))

    return app
  }
}

export class StartModules {
  modules: Array<string>
  folderName: string = 'unknow'
  constructor(modules: Array<string>, folderName: string = 'unknowContext') {
    this.folderName = folderName
    this.modules = modules
  }

  async createModules(srcDirName: string) {
    const moduleFiles: string[] = []
    let files: any
    if (!fs.existsSync(`${srcDirName}/modules`)) {
      fs.mkdirSync(`${srcDirName}/modules`, { recursive: true })
    }

    files = fs.readdirSync(`${srcDirName}/modules`)

    this.modules.forEach((module) => {
      let isOk = true
      for (const file in files) {
        if (file === module) {
          isOk = false
        }
      }
      if (isOk) {
        moduleFiles.push(module)
      }
    })

    moduleFiles.forEach((moduleFile) => {
      let modelName = moduleFile.charAt(0).toUpperCase() + moduleFile.slice(1)
      if (!fs.existsSync(path.resolve(srcDirName, 'modules', moduleFile))) {
        fs.mkdir(
          `${srcDirName}/modules/${moduleFile}`,
          { recursive: true },
          (err) => {
            if (err) console.error(err)
          }
        )

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-controller.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(
                  `${modelName} Controller File written successfully`
                )
              }
            }
          )
        } else {
          console.info('Controller File not written')
        }

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/router-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/router-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-router.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(`${modelName} Router File written successfully`)
              }
            }
          )
        } else {
          console.info('Router File not written')
        }

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/service-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/service-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-service.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(`${modelName} Service File written successfully`)
              }
            }
          )
        } else {
          console.info('Service File not written')
        }

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-repository.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(
                  `${modelName} Repository File written successfully`
                )
              }
            }
          )
        } else {
          console.info('Repository File not written')
        }

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/module-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/module-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-module.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(`${modelName} Module File written successfully`)
              }
            }
          )
        } else {
          console.info('Module File not written')
        }

        if (
          fs.existsSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt'
          )
        ) {
          let controller = fs.readFileSync(
            srcDirName +
              '/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt'
          )
          const controllerCode = Buffer.from(controller)
            .toString()
            .replace(/{{MODULE_NAME}}/g, moduleFile)
            .replace(/{{MODEL_NAME}}/g, modelName)
          fs.writeFile(
            `${srcDirName}/modules/${moduleFile}/${moduleFile}-interfaces.ts`,
            controllerCode,
            (err) => {
              if (err) console.error(err)
              else {
                console.info(
                  `${modelName} Interfaces File written successfully`
                )
                console.info(
                  '\n-----------------------------------------------------------------\n'
                )
              }
            }
          )
        } else {
          console.info('Interfaces File not written')
          console.info(
            '\n-----------------------------------------------------------------\n'
          )
        }
      }
    })
  }

  removeModule(srcDirName: string, name: string) {
    if (fs.existsSync(`${srcDirName}/modules/${name}`)) {
      fs.rmdir(
        `${srcDirName}/modules/${name}`,
        { recursive: true },
        (error) => {
          if (error) {
            console.error(error)
          } else {
            console.log('Folder Deleted!')
          }
        }
      )
    }
  }
}
