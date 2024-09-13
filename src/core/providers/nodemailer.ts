'use strict'
import nodemailer from 'nodemailer'
import { Config } from '../config/env'

const env = Config.instance

const transport = nodemailer.createTransport({
  host: env.config.smtpHost,
  port: env.config.smtpPort,
  secure: env.config.smtpSecure,
  auth: {
    user: env.config.smtpUser,
    pass: env.config.smtpPass,
  },
  tls: {
    ciphers: 'SSLv3',
  },
})

export async function sendEmail(
  emailTo: string,
  subject: string,
  html: string
) {
  try {
    const info = await transport.sendMail({
      from: env.config.mailFrom,
      to: emailTo,
      subject,
      html,
      //   attachments: [
      //     {
      //       filename: 'report.pdf',
      //       path: options.pdf,
      //       contentType: 'application/pdf',
      //       encoding: 'base64',
      //     },
      //   ],
    })
    return `Mensagem enviada para: ${info.accepted}`
  } catch (error) {
    console.error(error)
    return `Não foi possível enviar a mensagem`
  }
}
