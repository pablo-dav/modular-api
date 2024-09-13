import { PrismaClient } from '@prisma/client'
import { Request, Response } from 'express'
import { onError, onSuccess } from '../../core/helpers/response'
import AuthService from './auth-service'

export default class AuthController {
  private readonly service: AuthService

  constructor(public prismaClient: PrismaClient) {
    this.service = new AuthService(prismaClient)
  }

  public async login(request: Request, response: Response) {
    try {
      const loginResponse = await this.service.login(request.body)

      return onSuccess(response, 200, loginResponse)
    } catch (error: any) {
      return onError(response, error)
    }
  }

  public async register(request: Request, response: Response) {
    try {
      const user = await this.service.register(request.body)

      return onSuccess(response, 201, user)
    } catch (error: any) {
      return onError(response, error)
    }
  }

  public async me(request: any, response: Response) {
    try {
      const user = await this.service.me(request.user)

      return onSuccess(response, 200, user)
    } catch (error: any) {
      return onError(response, error)
    }
  }

  public async forgotPassword(request: Request, response: Response) {
    try {
      const message = await this.service.forgotPassword(request.body)

      return onSuccess(response, 200, { message })
    } catch (error: any) {
      return onError(response, error)
    }
  }

  public async updatePassword(request: Request, response: Response) {
    try {
      const message = await this.service.updatePassword(request.body)

      return onSuccess(response, 200, { message })
    } catch (error: any) {
      return onError(response, error)
    }
  }

  public async resetPassword(request: Request, response: Response) {
    try {
      const message = await this.service.resetPassword(request.body)

      return onSuccess(response, 200, { message })
    } catch (error: any) {
      return onError(response, error)
    }
  }
}
