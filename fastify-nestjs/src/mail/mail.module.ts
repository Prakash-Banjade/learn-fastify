import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { Global, Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { join } from 'path';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Global()
@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: async () => {
        const testAccount = await nodemailer.createTestAccount();
        return {
          transport: {
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
              user: 'emilie.bode41@ethereal.email',
              pass: '2FUZWBjpdGZjHBerGB'
            }
          },
          defaults: {
            from: `"No Reply" <${testAccount.user}>`,
          },
          template: {
            dir: join(__dirname, 'templates'),
            adapter: new HandlebarsAdapter(),
            options: {
              strict: true,
            },
          },
        };
      },
    }),
  ],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule { }