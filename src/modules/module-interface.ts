import { Router } from 'express'
export interface AppRouter {
  index?: () => AppRouter
  show?: () => AppRouter
  store?: () => AppRouter
  update?: () => AppRouter
  delete?: () => AppRouter

  router: Router
}
export interface Module {
  moduleName: string
  router: AppRouter
  isPublic: boolean
}
