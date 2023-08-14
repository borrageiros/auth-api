// src/auth/mail.service.ts
import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: 465,
      secure: true, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_EMAIL,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  async sendMail(to: string, subject: string, text: string) {
    const info = await this.transporter.sendMail({
      from: process.env.APP_NAME + " | " + process.env.EMAIL_EMAIL,
      to: to,
      subject: subject,
      text: text,
      // html: '<b>Hello world?</b>', // html body (if needed)
    });
  }
}
