import { Module } from '../module-interface'
import AuthRouter from './auth-router'
import { PrismaClient } from '@prisma/client'
export default class AuthModule implements Module {
  public readonly moduleName: string
  public readonly router: AuthRouter
  public isPublic: boolean = true

  constructor(moduleName: string) {
    this.moduleName = moduleName

    this.router = new AuthRouter(new PrismaClient())
    this.loadRoutes()
  }

  private loadRoutes() {
    this.router
      .login()
      .register()
      .forgotPassword()
      .updatePassword()
      .me()
      .resetPassword()
  }
}
