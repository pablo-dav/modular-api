import * as configcat from 'configcat-node'

const { configCatKey } = require('../config/env/index')

export class ConfigCatProvider {
  private _client: any
  private _key: string
  private _value: string
  private _flag: string

  constructor(flag: string, key: string, value: string) {
    this._client = configcat.createClientWithAutoPoll(configCatKey, {
      pollIntervalSeconds: 60,
      logger: configcat.createConsoleLogger(3),
    })
    this._key = key
    this._value = value
    this._flag = flag
  }

  private mountKey() {
    return {
      identifier: '##O2O##',
      custom: {
        [this._key]: [this._value],
      },
    }
  }

  public async isEnable() {
    try {
      const valueIsEnable = await this._client.getValueAsync(
        this._flag,
        false,
        this.mountKey()
      )
      return valueIsEnable
    } catch (error) {
      console.error(error)
      return false
    }
  }
}
