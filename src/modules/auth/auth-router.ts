import { PrismaClient } from '@prisma/client'
import { Request, Response, Router } from 'express'
import { verifyToken } from '../../core/middlewares/auth/verifyToken'
import { AppRouter } from '../module-interface'
import AuthController from './auth-controller'
export default class AuthRouter implements AppRouter {
  public readonly router: Router = Router()
  private readonly controller: AuthController

  constructor(public prismaClient: PrismaClient) {
    this.controller = new AuthController(prismaClient)
  }
  public login() {
    this.router.post('/login', (request: Request, response: Response) => {
      this.controller.login(request, response)
    })
    return this
  }

  public register() {
    this.router.post('/register', (request: Request, response: Response) => {
      this.controller.register(request, response)
    })
    return this
  }

  public me() {
    this.router.get(
      '/me',
      verifyToken,
      (request: Request, response: Response) => {
        this.controller.me(request, response)
      }
    )
    return this
  }

  public forgotPassword() {
    this.router.post(
      '/forgot-password',
      (request: Request, response: Response) => {
        this.controller.forgotPassword(request, response)
      }
    )
    return this
  }

  public updatePassword() {
    this.router.patch(
      '/update-password',
      (request: Request, response: Response) => {
        this.controller.updatePassword(request, response)
      }
    )
    return this
  }

  public resetPassword() {
    this.router.patch(
      '/reset-password',
      (request: Request, response: Response) => {
        this.controller.resetPassword(request, response)
      }
    )
    return this
  }
}
