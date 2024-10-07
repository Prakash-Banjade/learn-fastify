import { Injectable, Logger, LoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, Transporter } from 'nodemailer';
import { Account } from 'src/auth-system/accounts/entities/account.entity';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { emailConfig, ITemplatedData, ITemplates } from './mail-service.config';
import { readFileSync } from 'fs';
import Handlebars from 'handlebars';
import { join } from 'path';

@Injectable()
export class MailService {
    private readonly loggerService: LoggerService;
    private readonly transport: Transporter<SMTPTransport.SentMessageInfo>;
    private readonly email: string;
    private readonly domain: string;
    private readonly templates: ITemplates;

    constructor(private readonly configService: ConfigService) {
        this.transport = createTransport(emailConfig);
        this.email = `"Nest Fastify" <${emailConfig.auth.user}>`;
        this.domain = this.configService.get<string>('domain');
        this.loggerService = new Logger(MailService.name);

        this.templates = {
            confirmation: MailService.parseTemplate('email-verification-otp.hbs'),
            resetPassword: MailService.parseTemplate('reset-password.hbs'),
        };
    }

    private static parseTemplate(
        templateName: string,
    ): Handlebars.TemplateDelegate<ITemplatedData> {
        const templateText = readFileSync(
            join(__dirname, 'templates', templateName),
            'utf-8',
        );
        return Handlebars.compile<ITemplatedData>(templateText, { strict: true });
    }

    public sendEmail(
        to: string,
        subject: string,
        html: string,
        log?: string,
    ): void {
        this.transport
            .sendMail({
                from: this.email,
                to,
                subject,
                html,
            })
            .then((data) => {
                console.log(data)
                this.loggerService.log(log ?? 'A new email was sent.')
            })
            .catch((error) => this.loggerService.error(error));
    }

    public sendConfirmationEmail(account: Account, token: string): void {
        const { email, firstName, lastName } = account;
        const subject = 'Confirm your email';
        const html = this.templates.confirmation({
            name: firstName + ' ' + lastName,
            link: `https://${this.domain}/auth/confirm/${token}`,
        });
        this.sendEmail(email, subject, html, 'A new confirmation email was sent.');
    }

    public sendResetPasswordEmail(account: Account, token: string): void {
        const { email, firstName, lastName } = account;
        const subject = 'Reset your password';
        const html = this.templates.resetPassword({
            name: firstName + ' ' + lastName,
            link: `https://${this.domain}/auth/reset-password/${token}`,
        });
        this.sendEmail(
            email,
            subject,
            html,
            'A new reset password email was sent.',
        );
    }
}