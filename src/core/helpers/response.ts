import { Response } from 'express'
import { ErrorDTO, SuccessDTO } from '../interfaces/response-interface'

import { ResponseError } from './error'

export function onError(response: Response, error: ResponseError) {
  const errorResponse: ErrorDTO = { response, error }
  console.error(`${errorResponse.error.message}`)
  response
    .status(errorResponse.error.status || 500)
    .json({ success: false, message: errorResponse.error.message })
}

export function onSuccess(
  response: Response,
  statusCode: number,
  data: Object
) {
  const successResponse: SuccessDTO = { response, statusCode, data }
  successResponse.response
    .status(successResponse.statusCode)
    .json({ success: true, ...successResponse.data })
}
