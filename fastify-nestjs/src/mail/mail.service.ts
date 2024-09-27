import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { Account } from 'src/auth-system/accounts/entities/account.entity';

@Injectable()
export class MailService {
    constructor(
        private mailerService: MailerService,
        private readonly configService: ConfigService
    ) { }

    async sendEmailVerificationOtp(account: Account, otp: number, verificationToken: string) {
        const result = await this.mailerService.sendMail({
            to: account.email,
            subject: 'Email verification',
            template: './sendEmailVerificationOtp', // `.hbs` extension is appended automatically
            context: { // ✏️ filling curly brackets with content
                name: account.firstName + ' ' + account.lastName,
                otp: otp,
                url: `${this.configService.get('CLIENT_URL')}/verify-email/${verificationToken}`,
            },
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);
        console.log('Preview URL:', previewUrl);

        return { result, previewUrl };

    }

    async sendResetPasswordLink(account: Account, resetToken: string, cms?: string) {
        const CLIENT_URL = cms === "true" ? this.configService.get('CMS_URL') : this.configService.get('CLIENT_URL');

        const result = await this.mailerService.sendMail({
            to: account.email,
            subject: 'Reset your password',
            template: './sendResetPasswordLink', // `.hbs` extension is appended automatically
            context: { // ✏️ filling curly brackets with content
                name: account.firstName + ' ' + account.lastName,
                resetLink: `${CLIENT_URL}/auth/forget-password?resetToken=${resetToken}`,
            },
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);

        return { result, previewUrl };
    }

    async sendNewsletterVerification(email: string, verificationToken: string) {
        const result = await this.mailerService.sendMail({
            to: email,
            subject: 'Verify your email to subscribe to our newsletter',
            template: './sendNewsletterSubscribeLink', // `.hbs` extension is appended automatically
            context: { // ✏️ filling curly brackets with content
                subscribeUrl: `${this.configService.get('CLIENT_URL')}/newsletter/subscribe?verificationToken=${verificationToken}`,
            },
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);

        return { result, previewUrl };
    }

    async subscribeConfirmationNotify(email: string, token: string) {
        const result = await this.mailerService.sendMail({
            to: email,
            subject: 'Successfully subscribed to Car Rental newsletter',
            template: './newsletterSubscribedNotify', // `.hbs` extension is appended automatically
            context: { // ✏️ filling curly brackets with content
                unsubscribeUrl: `${this.configService.get('CLIENT_URL')}/newsletter/unsubscribe?token=${token}`,
            },
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);

        return { result, previewUrl };
    }

    async unSubscribeNotify(email: string) {
        const result = await this.mailerService.sendMail({
            to: email,
            subject: 'Unsubscribed to Car Rental newsletter',
            template: './newsletterUnsubscribeNotify', // `.hbs` extension is appended automatically
            context: { // ✏️ filling curly brackets with content
            },
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);

        return { result, previewUrl };
    }
}