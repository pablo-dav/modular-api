import { PrismaClient, User } from '@prisma/client'

export default class AuthRepository {
  constructor(private readonly client: PrismaClient) {}

  public async findByEmail(email: string): Promise<User | null> {
    const user = await this.client.user.findFirst({
      where: { email },
      // @ts-ignore
      include: {
        role: true,
      },
    })
    return user
  }

  public async findByConfirmationCode(
    confirmationCode: string
  ): Promise<User | null> {
    const user = await this.client.user.findFirst({
      // @ts-ignore
      where: { confirmationCode },
    })
    return user
  }

  public async saveConfirmationCode(
    id: number,
    confirmationCode: string | null
  ): Promise<User> {
    const user = await this.client.user.update({
      where: { id },
      // @ts-ignore
      data: { confirmationCode },
    })

    return user
  }

  public async updatePassword(id: number, password: string): Promise<User> {
    const user = await this.client.user.update({
      where: { id },
      data: { password },
    })

    return user
  }

  public async store(data: any): Promise<User> {
    const user = await this.client.user.create({
      data,
    })

    return user
  }
}
