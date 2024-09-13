export interface ResponseError extends Error {
  get status(): number
}

export class BadRequestError extends Error implements ResponseError {
  private readonly _status: number
  constructor(message: string) {
    super(message)
    this._status = 400
  }

  public get status() {
    return this._status
  }
}

export class AuthenticationError extends Error implements ResponseError {
  private readonly _status: number
  constructor(message: string) {
    super(message)
    this._status = 401
  }

  public get status() {
    return this._status
  }
}

export class ForbiddenError extends Error implements ResponseError {
  private readonly _status: number
  constructor(message: string) {
    super(message)
    this._status = 403
  }

  public get status() {
    return this._status
  }
}

export class NotFoundError extends Error implements ResponseError {
  private _status: number

  constructor(message: string) {
    super(message)
    this._status = 404
  }

  public get status() {
    return this._status
  }
}

export class UnprocessableEntityError extends Error implements ResponseError {
  private readonly _status: number
  constructor(message: string) {
    super(message)
    this._status = 422
  }

  public get status() {
    return this._status
  }
}
