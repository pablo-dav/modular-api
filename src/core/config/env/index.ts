import fs from 'fs'
import path from 'path'
export interface BaseConfig {
  apiContext: string
  apiVersion: string
  serverPort: number
  smtpHost: string
  smtpPort: number
  smtpSecure: boolean
  smtpPass: string
  smtpUser: string
  mailFrom: string
  frontURL: string
  jwtSecret: string
}
export class Config {
  private readonly _config: BaseConfig
  private static _instance: Config

  public static get instance() {
    if (!Config._instance) {
      Config._instance = new Config()
    }

    return Config._instance
  }

  public get config() {
    return this._config
  }

  private constructor() {
    this._config = this.readConfigFile()
  }

  private readConfigFile() {
    let config = null

    if (process.cwd().includes('dist')) {
      config = fs.readFileSync(path.resolve('../config.json'))
    } else {
      config = fs.readFileSync(path.resolve('config.json'))
    }

    return JSON.parse(config.toString())
  }
}
