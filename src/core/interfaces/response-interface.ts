import { Response } from 'express'
import { ResponseError } from '../helpers/error'

export interface ResponseDTO {
  response: Response
}

export interface SuccessDTO extends ResponseDTO {
  statusCode: number
  data: Object
}

export interface ErrorDTO extends ResponseDTO {
  error: ResponseError
}
