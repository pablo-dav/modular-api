export interface UserRegisterPayload {
  email: string
  name: string
  password: string
  roleId: number
}

export interface User {
  email: string
  name: string
  password: string
  role?: string
  id?: number
}

export interface UserRegisterResponseDTO {
  user: Omit<User, 'password'>
}
export interface UserMeResponseDTO {
  user: Omit<User, 'password' | 'confirmationCode'>
}
export interface UserLoginPayload {
  email: string
  password: string
}
export interface UserLoginResponseDTO {
  token: string
  user: Omit<User, 'password'>
}
export interface UserForgotPasswordPayloadDTO {
  newPassword: string
  newPasswordConfirmation: string
  confirmationCode: string
}

export interface UserResetPasswordPayloadDTO {
  newPassword: string
  email: string
}

